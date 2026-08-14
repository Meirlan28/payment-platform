-- Durable control plane for the reference-field expand -> shadow -> verify ->
-- cutover -> contract migration introduced by 002_expand_reference.sql.
--
-- The source is ledger_transactions.reference_transaction_id.  It is part of
-- the immutable, hash-covered ledger header.  The target is a rebuildable
-- projection; historical ledger rows are never updated by this workflow.

CREATE TABLE IF NOT EXISTS reference_migration_control (
    migration_name          STRING PRIMARY KEY,
    active_generation       INT8 NOT NULL DEFAULT 0 CHECK (active_generation >= 0),
    read_generation         INT8 NOT NULL DEFAULT 0 CHECK (read_generation >= 0),
    phase                    STRING NOT NULL CHECK (phase IN (
                                 'EXPANDED', 'SHADOWING', 'VERIFIED',
                                 'CUTOVER', 'CONTRACTED'
                             )),
    state_version            INT8 NOT NULL DEFAULT 0 CHECK (state_version >= 0),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    CHECK (read_generation <= active_generation),
    CHECK ((phase = 'EXPANDED' AND active_generation = 0 AND read_generation = 0)
        OR (phase IN ('SHADOWING', 'VERIFIED')
            AND active_generation > 0 AND read_generation < active_generation)
        OR (phase IN ('CUTOVER', 'CONTRACTED')
            AND active_generation > 0 AND read_generation = active_generation))
);

INSERT INTO reference_migration_control (
    migration_name, active_generation, read_generation, phase, state_version
) VALUES ('ledger-reference-v2', 0, 0, 'EXPANDED', 0)
ON CONFLICT (migration_name) DO NOTHING;

CREATE TABLE IF NOT EXISTS reference_migration_runs (
    migration_name          STRING NOT NULL,
    generation              INT8 NOT NULL CHECK (generation > 0),
    phase                    STRING NOT NULL CHECK (phase IN (
                                 'SHADOWING', 'VERIFIED', 'CUTOVER', 'CONTRACTED'
                             )),
    started_from_version     INT8 NOT NULL CHECK (started_from_version >= 0),
    source_rows              INT8 NULL CHECK (source_rows IS NULL OR source_rows >= 0),
    projected_rows           INT8 NULL CHECK (projected_rows IS NULL OR projected_rows >= 0),
    source_digest            BYTES NULL CHECK (source_digest IS NULL OR length(source_digest) = 32),
    projected_digest         BYTES NULL CHECK (projected_digest IS NULL OR length(projected_digest) = 32),
    started_at               TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    verified_at              TIMESTAMPTZ NULL,
    cutover_at               TIMESTAMPTZ NULL,
    contracted_at            TIMESTAMPTZ NULL,
    PRIMARY KEY (migration_name, generation),
    FOREIGN KEY (migration_name) REFERENCES reference_migration_control (migration_name),
    CHECK ((phase = 'SHADOWING' AND verified_at IS NULL)
        OR (phase = 'VERIFIED' AND verified_at IS NOT NULL)
        OR (phase = 'CUTOVER' AND verified_at IS NOT NULL AND cutover_at IS NOT NULL)
        OR (phase = 'CONTRACTED' AND verified_at IS NOT NULL
            AND cutover_at IS NOT NULL AND contracted_at IS NOT NULL))
);

-- Every book is closed independently at its consensus-committed sequence and
-- hash-chain head.  next_sequence_no is a durable cursor so many restartable
-- workers can backfill bounded batches without timestamps or OFFSET scans.
CREATE TABLE IF NOT EXISTS reference_migration_book_watermarks (
    migration_name          STRING NOT NULL,
    generation              INT8 NOT NULL,
    book_id                 STRING NOT NULL REFERENCES books (book_id),
    watermark_sequence_no   INT8 NOT NULL CHECK (watermark_sequence_no >= 0),
    watermark_entry_hash    BYTES NOT NULL CHECK (length(watermark_entry_hash) = 32),
    next_sequence_no        INT8 NOT NULL DEFAULT 1 CHECK (next_sequence_no > 0),
    referenced_rows_scanned INT8 NOT NULL DEFAULT 0 CHECK (referenced_rows_scanned >= 0),
    completed               BOOL NOT NULL DEFAULT false,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (migration_name, generation, book_id),
    FOREIGN KEY (migration_name, generation)
        REFERENCES reference_migration_runs (migration_name, generation),
    CHECK (next_sequence_no <= watermark_sequence_no + 1),
    CHECK (NOT completed OR next_sequence_no = watermark_sequence_no + 1)
);

CREATE INDEX IF NOT EXISTS reference_migration_pending_idx
    ON reference_migration_book_watermarks (migration_name, generation, completed, book_id);

-- Contract is allowed only after every explicitly registered required reader
-- has durably acknowledged the cutover generation.  This is a deployment
-- barrier, not a clock-based lease, so a 15-minute clock skew cannot retire an
-- old reader accidentally.
CREATE TABLE IF NOT EXISTS reference_migration_consumers (
    migration_name          STRING NOT NULL,
    consumer_id             STRING NOT NULL,
    required                BOOL NOT NULL DEFAULT true,
    acknowledged_generation INT8 NOT NULL DEFAULT 0 CHECK (acknowledged_generation >= 0),
    acknowledged_at         TIMESTAMPTZ NULL,
    PRIMARY KEY (migration_name, consumer_id),
    FOREIGN KEY (migration_name) REFERENCES reference_migration_control (migration_name)
);

CREATE OR REPLACE FUNCTION public.validate_reference_migration_consumer_update()
RETURNS TRIGGER AS $$
DECLARE
    active_generation INT8;
BEGIN
    IF (OLD).migration_name IS DISTINCT FROM (NEW).migration_name
       OR (OLD).consumer_id IS DISTINCT FROM (NEW).consumer_id
       OR (OLD).required IS DISTINCT FROM (NEW).required
       OR (NEW).acknowledged_generation < (OLD).acknowledged_generation THEN
        RAISE EXCEPTION 'migration consumer identity is immutable and acknowledgement is monotonic';
    END IF;
    SELECT c.active_generation INTO active_generation
      FROM public.reference_migration_control AS c
     WHERE c.migration_name = (NEW).migration_name;
    IF active_generation IS NULL OR (NEW).acknowledged_generation > active_generation THEN
        RAISE EXCEPTION 'consumer cannot acknowledge an inactive generation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER reference_migration_consumer_validate_update
BEFORE UPDATE ON reference_migration_consumers
FOR EACH ROW
EXECUTE FUNCTION public.validate_reference_migration_consumer_update();

-- Projection rows are accepted only when they exactly match the immutable
-- source fact.  The guard also prevents an INSERT-only runtime role from
-- fabricating an extra reference that could survive a count-only check.
CREATE OR REPLACE FUNCTION public.validate_ledger_reference_shadow_insert()
RETURNS TRIGGER AS $$
DECLARE
    source_status STRING;
    source_reference STRING;
    source_version INT8;
BEGIN
    SELECT status, reference_transaction_id, schema_version
      INTO source_status, source_reference, source_version
      FROM public.ledger_transactions
     WHERE transaction_id = (NEW).transaction_id;

    IF source_status IS NULL OR source_status <> 'POSTED'
       OR source_reference IS NULL
       OR (NEW).reference_type <> 'LEDGER_TRANSACTION'
       OR (NEW).reference_id IS DISTINCT FROM source_reference
       OR (NEW).source_schema_version IS DISTINCT FROM source_version THEN
        RAISE EXCEPTION 'reference shadow row does not match immutable ledger source';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER ledger_reference_shadow_validate_insert
BEFORE INSERT ON ledger_transaction_references_shadow
FOR EACH ROW
EXECUTE FUNCTION public.validate_ledger_reference_shadow_insert();

CREATE OR REPLACE FUNCTION public.reject_ledger_reference_shadow_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'ledger reference shadow projection is append-only';
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER ledger_reference_shadow_no_update
BEFORE UPDATE ON ledger_transaction_references_shadow
FOR EACH ROW
EXECUTE FUNCTION public.reject_ledger_reference_shadow_mutation();

CREATE TRIGGER ledger_reference_shadow_no_delete
BEFORE DELETE ON ledger_transaction_references_shadow
FOR EACH ROW
EXECUTE FUNCTION public.reject_ledger_reference_shadow_mutation();

-- Once shadowing starts, new reference-bearing journal entries are projected
-- in the same serializable database transaction as the DRAFT -> POSTED commit.
-- A crash cannot expose one side without the other.  Existing rows are filled
-- by the bounded backfill workers at a captured sequence watermark.
CREATE OR REPLACE FUNCTION public.project_ledger_reference_after_post()
RETURNS TRIGGER AS $$
BEGIN
    IF (OLD).status = 'DRAFT' AND (NEW).status = 'POSTED'
       AND (NEW).reference_transaction_id IS NOT NULL
       AND EXISTS (
           SELECT 1 FROM public.reference_migration_control
            WHERE migration_name = 'ledger-reference-v2'
              AND phase IN ('SHADOWING', 'VERIFIED', 'CUTOVER', 'CONTRACTED')
       ) THEN
        INSERT INTO public.ledger_transaction_references_shadow (
            transaction_id, reference_type, reference_id, source_schema_version
        ) VALUES (
            (NEW).transaction_id, 'LEDGER_TRANSACTION',
            (NEW).reference_transaction_id, (NEW).schema_version
        ) ON CONFLICT (transaction_id) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

CREATE TRIGGER ledger_transaction_project_reference
AFTER UPDATE ON ledger_transactions
FOR EACH ROW
WHEN ((OLD).status = 'DRAFT' AND (NEW).status = 'POSTED')
EXECUTE FUNCTION public.project_ledger_reference_after_post();

CREATE ROLE IF NOT EXISTS reference_migration_operator NOLOGIN;

REVOKE ALL ON TABLE reference_migration_control, reference_migration_runs,
    reference_migration_book_watermarks, reference_migration_consumers FROM public;
GRANT ALL ON TABLE reference_migration_control, reference_migration_runs,
    reference_migration_book_watermarks, reference_migration_consumers
    TO ledger_admin;
GRANT SELECT, INSERT, UPDATE ON TABLE reference_migration_control,
    reference_migration_runs, reference_migration_book_watermarks,
    reference_migration_consumers TO reference_migration_operator;
GRANT SELECT ON TABLE books, ledger_transactions,
    ledger_transaction_references_shadow TO reference_migration_operator;
GRANT INSERT ON TABLE ledger_transaction_references_shadow
    TO reference_migration_operator;

REVOKE EXECUTE ON FUNCTION public.validate_ledger_reference_shadow_insert() FROM public;
REVOKE EXECUTE ON FUNCTION public.reject_ledger_reference_shadow_mutation() FROM public;
REVOKE EXECUTE ON FUNCTION public.project_ledger_reference_after_post() FROM public;
REVOKE EXECUTE ON FUNCTION public.validate_reference_migration_consumer_update() FROM public;
