-- Expand phase of an expand -> shadow -> verify -> cutover -> contract change.
-- Existing financial facts are not rewritten. New writers populate the nullable
-- reference columns and the shadow projection; readers remain compatible with
-- rows written under schema_version=1.

ALTER TABLE payment_operations
    ADD COLUMN IF NOT EXISTS reference_type STRING NULL;
ALTER TABLE payment_operations
    ADD COLUMN IF NOT EXISTS reference_id STRING NULL;

CREATE TABLE IF NOT EXISTS ledger_transaction_references_shadow (
    transaction_id           STRING PRIMARY KEY REFERENCES ledger_transactions (transaction_id),
    reference_type           STRING NOT NULL,
    reference_id             STRING NOT NULL,
    source_schema_version    INT8 NOT NULL CHECK (source_schema_version > 0),
    projected_at             TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (reference_type, reference_id, transaction_id)
);

REVOKE ALL ON TABLE ledger_transaction_references_shadow FROM public;
GRANT ALL ON TABLE ledger_transaction_references_shadow TO ledger_admin;
GRANT SELECT, INSERT ON TABLE ledger_transaction_references_shadow TO ledger_writer;
GRANT SELECT ON TABLE ledger_transaction_references_shadow TO ledger_reader, ledger_auditor;

-- Contract is intentionally deferred until shadow-vs-source verification at a
-- closed ledger watermark succeeds.  In particular, no UPDATE of historical
-- ledger_transactions is part of this migration.
