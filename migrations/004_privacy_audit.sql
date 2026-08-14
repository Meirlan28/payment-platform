CREATE SCHEMA IF NOT EXISTS pii;
CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE IF NOT EXISTS pii.identity_mappings (
    identity_id STRING PRIMARY KEY,
    jurisdiction STRING NOT NULL,
    vault_key_name STRING NOT NULL UNIQUE,
    ciphertext STRING NOT NULL,
    state STRING NOT NULL CHECK (state IN ('ACTIVE', 'DELETION_PENDING')),
    deletion_request_id STRING NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT deletion_request_required CHECK (
        state != 'DELETION_PENDING' OR deletion_request_id IS NOT NULL
    )
);

CREATE INDEX IF NOT EXISTS identity_mappings_jurisdiction_idx
    ON pii.identity_mappings (jurisdiction, identity_id);

CREATE TABLE IF NOT EXISTS pii.deletion_receipts (
    request_id STRING PRIMARY KEY,
    jurisdiction STRING NOT NULL,
    result STRING NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit.merkle_checkpoints (
    book_id STRING NOT NULL,
    first_sequence INT8 NOT NULL,
    last_sequence INT8 NOT NULL,
    leaf_count INT8 NOT NULL CHECK (leaf_count > 0),
    merkle_root BYTES NOT NULL,
    last_entry_hash BYTES NOT NULL CHECK (length(last_entry_hash) = 32),
    previous_checkpoint_root BYTES NULL,
    signature BYTES NOT NULL,
    signing_key_id STRING NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (book_id, last_sequence),
    CONSTRAINT valid_checkpoint_range CHECK (first_sequence > 0 AND last_sequence >= first_sequence)
);

CREATE OR REPLACE FUNCTION audit.reject_checkpoint_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit checkpoints are append-only';
END
$$ LANGUAGE PLpgSQL;

DROP TRIGGER IF EXISTS audit_checkpoints_immutable ON audit.merkle_checkpoints;
CREATE TRIGGER audit_checkpoints_immutable
BEFORE UPDATE OR DELETE ON audit.merkle_checkpoints
FOR EACH ROW EXECUTE FUNCTION audit.reject_checkpoint_mutation();

CREATE TRIGGER deletion_receipts_immutable
BEFORE UPDATE OR DELETE ON pii.deletion_receipts
FOR EACH ROW EXECUTE FUNCTION audit.reject_checkpoint_mutation();

CREATE ROLE IF NOT EXISTS pii_writer NOLOGIN;
CREATE ROLE IF NOT EXISTS pii_reader NOLOGIN;
CREATE ROLE IF NOT EXISTS audit_writer NOLOGIN;
CREATE ROLE IF NOT EXISTS audit_reader NOLOGIN;

REVOKE ALL ON TABLE pii.identity_mappings, pii.deletion_receipts,
    audit.merkle_checkpoints FROM public;
GRANT USAGE ON SCHEMA pii TO pii_writer, pii_reader;
GRANT USAGE ON SCHEMA audit TO audit_writer, audit_reader;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE pii.identity_mappings TO pii_writer;
GRANT SELECT, INSERT ON TABLE pii.deletion_receipts TO pii_writer;
GRANT SELECT ON TABLE pii.identity_mappings, pii.deletion_receipts TO pii_reader;
GRANT SELECT, INSERT ON TABLE audit.merkle_checkpoints TO audit_writer;
GRANT SELECT ON TABLE audit.merkle_checkpoints TO audit_reader;
