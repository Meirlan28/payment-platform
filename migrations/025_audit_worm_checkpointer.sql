-- Production audit-checkpointer state. Checkpoints, canonical manifests,
-- per-sink cursors/receipts, and P0 conflict evidence are append-only. The
-- worker has read-only ledger access and can only append to this schema.

CREATE TABLE IF NOT EXISTS audit.checkpoint_manifests (
    book_id STRING NOT NULL,
    last_sequence INT8 NOT NULL,
    manifest_format STRING NOT NULL,
    object_key STRING NOT NULL,
    manifest_bytes BYTES NOT NULL,
    content_sha256 BYTES NOT NULL CHECK (length(content_sha256) = 32),
    retention_until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (book_id, last_sequence),
    CONSTRAINT checkpoint_manifest_checkpoint_fk
        FOREIGN KEY (book_id, last_sequence)
        REFERENCES audit.merkle_checkpoints (book_id, last_sequence),
    CONSTRAINT checkpoint_manifest_digest_matches
        CHECK (content_sha256 = decode(sha256(manifest_bytes), 'hex')),
    CONSTRAINT checkpoint_manifest_format_v1
        CHECK (manifest_format = 'payment-platform/audit-manifest/v1'),
    CONSTRAINT checkpoint_manifest_key_bound
        CHECK (length(object_key) BETWEEN 1 AND 2048)
);

CREATE TABLE IF NOT EXISTS audit.worm_export_receipts (
    sink_id STRING NOT NULL CHECK (length(sink_id) BETWEEN 1 AND 128),
    book_id STRING NOT NULL,
    last_sequence INT8 NOT NULL,
    object_key STRING NOT NULL,
    content_sha256 BYTES NOT NULL CHECK (length(content_sha256) = 32),
    checksum_algorithm STRING NOT NULL CHECK (checksum_algorithm = 'SHA256'),
    bucket STRING NOT NULL CHECK (length(bucket) BETWEEN 1 AND 255),
    endpoint_authority STRING NOT NULL CHECK (length(endpoint_authority) BETWEEN 1 AND 512),
    provider_identity STRING NOT NULL CHECK (length(provider_identity) BETWEEN 1 AND 1024),
    object_version_id STRING NOT NULL CHECK (length(object_version_id) BETWEEN 1 AND 1024),
    etag STRING NOT NULL CHECK (length(etag) BETWEEN 1 AND 512),
    object_lock_mode STRING NOT NULL CHECK (object_lock_mode = 'COMPLIANCE'),
    retention_until TIMESTAMPTZ NOT NULL,
    exported_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (sink_id, book_id, last_sequence),
    CONSTRAINT worm_receipt_manifest_fk
        FOREIGN KEY (book_id, last_sequence)
        REFERENCES audit.checkpoint_manifests (book_id, last_sequence)
);

-- Conflicting bytes at a deterministic object key are a P0. A deterministic
-- incident_id makes recording retry-safe while preserving an immutable event.
CREATE TABLE IF NOT EXISTS audit.worm_export_incidents (
    incident_id BYTES PRIMARY KEY CHECK (length(incident_id) = 32),
    incident_kind STRING NOT NULL CHECK (incident_kind = 'OBJECT_CONFLICT'),
    sink_id STRING NOT NULL CHECK (length(sink_id) BETWEEN 1 AND 128),
    book_id STRING NOT NULL,
    last_sequence INT8 NOT NULL,
    object_key STRING NOT NULL,
    expected_sha256 BYTES NOT NULL CHECK (length(expected_sha256) = 32),
    observed_sha256 BYTES NULL CHECK (observed_sha256 IS NULL OR length(observed_sha256) = 32),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT worm_incident_manifest_fk
        FOREIGN KEY (book_id, last_sequence)
        REFERENCES audit.checkpoint_manifests (book_id, last_sequence)
);

CREATE OR REPLACE FUNCTION audit.enforce_checkpoint_manifest_insert()
RETURNS TRIGGER AS $$
DECLARE
    checkpoint_created_at TIMESTAMPTZ;
BEGIN
    SELECT created_at INTO checkpoint_created_at
      FROM audit.merkle_checkpoints
     WHERE book_id=(NEW).book_id AND last_sequence=(NEW).last_sequence;
    IF checkpoint_created_at IS NULL THEN
        RAISE EXCEPTION 'checkpoint manifest has no checkpoint';
    END IF;
    IF (NEW).retention_until < checkpoint_created_at + INTERVAL '10 years' THEN
        RAISE EXCEPTION 'checkpoint manifest retention is less than ten years';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE OR REPLACE FUNCTION audit.enforce_worm_receipt_insert()
RETURNS TRIGGER AS $$
DECLARE
    target_first_sequence INT8;
    target_object_key STRING;
    target_digest BYTES;
    target_retention TIMESTAMPTZ;
BEGIN
    SELECT checkpoint.first_sequence, manifest.object_key,
           manifest.content_sha256, manifest.retention_until
      INTO target_first_sequence, target_object_key,
           target_digest, target_retention
      FROM audit.checkpoint_manifests AS manifest
      JOIN audit.merkle_checkpoints AS checkpoint
        ON checkpoint.book_id=manifest.book_id
       AND checkpoint.last_sequence=manifest.last_sequence
     WHERE manifest.book_id=(NEW).book_id
       AND manifest.last_sequence=(NEW).last_sequence;
    IF target_first_sequence IS NULL
       OR (NEW).object_key IS DISTINCT FROM target_object_key
       OR (NEW).content_sha256 IS DISTINCT FROM target_digest
       OR (NEW).retention_until < target_retention THEN
        RAISE EXCEPTION 'WORM receipt does not match its canonical manifest';
    END IF;
    IF target_first_sequence > 1 AND NOT EXISTS (
        SELECT 1
          FROM audit.worm_export_receipts AS prior
         WHERE prior.sink_id=(NEW).sink_id
           AND prior.book_id=(NEW).book_id
           AND prior.last_sequence=target_first_sequence-1
    ) THEN
        RAISE EXCEPTION 'WORM receipt would create a per-sink export cursor gap';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

DROP TRIGGER IF EXISTS checkpoint_manifests_validate_insert
    ON audit.checkpoint_manifests;
CREATE TRIGGER checkpoint_manifests_validate_insert
BEFORE INSERT ON audit.checkpoint_manifests
FOR EACH ROW EXECUTE FUNCTION audit.enforce_checkpoint_manifest_insert();

DROP TRIGGER IF EXISTS checkpoint_manifests_immutable
    ON audit.checkpoint_manifests;
CREATE TRIGGER checkpoint_manifests_immutable
BEFORE UPDATE OR DELETE ON audit.checkpoint_manifests
FOR EACH ROW EXECUTE FUNCTION audit.reject_checkpoint_mutation();

DROP TRIGGER IF EXISTS worm_export_receipts_validate_insert
    ON audit.worm_export_receipts;
CREATE TRIGGER worm_export_receipts_validate_insert
BEFORE INSERT ON audit.worm_export_receipts
FOR EACH ROW EXECUTE FUNCTION audit.enforce_worm_receipt_insert();

DROP TRIGGER IF EXISTS worm_export_receipts_immutable
    ON audit.worm_export_receipts;
CREATE TRIGGER worm_export_receipts_immutable
BEFORE UPDATE OR DELETE ON audit.worm_export_receipts
FOR EACH ROW EXECUTE FUNCTION audit.reject_checkpoint_mutation();

DROP TRIGGER IF EXISTS worm_export_incidents_immutable
    ON audit.worm_export_incidents;
CREATE TRIGGER worm_export_incidents_immutable
BEFORE UPDATE OR DELETE ON audit.worm_export_incidents
FOR EACH ROW EXECUTE FUNCTION audit.reject_checkpoint_mutation();

CREATE ROLE IF NOT EXISTS audit_checkpointer_runtime NOLOGIN;

REVOKE ALL ON TABLE audit.checkpoint_manifests,
    audit.worm_export_receipts, audit.worm_export_incidents FROM public;
REVOKE EXECUTE ON FUNCTION audit.enforce_checkpoint_manifest_insert() FROM public;
REVOKE EXECUTE ON FUNCTION audit.enforce_worm_receipt_insert() FROM public;

GRANT USAGE ON SCHEMA public, audit TO audit_checkpointer_runtime,
    audit_reader, ledger_auditor, ledger_admin;
GRANT SELECT ON TABLE books, ledger_transactions, ledger_lines
    TO audit_checkpointer_runtime;
GRANT SELECT, INSERT ON TABLE audit.merkle_checkpoints,
    audit.checkpoint_manifests, audit.worm_export_receipts,
    audit.worm_export_incidents TO audit_checkpointer_runtime;

GRANT SELECT ON TABLE audit.checkpoint_manifests,
    audit.worm_export_receipts, audit.worm_export_incidents
    TO audit_reader, ledger_auditor;

GRANT ALL ON TABLE audit.checkpoint_manifests,
    audit.worm_export_receipts, audit.worm_export_incidents TO ledger_admin;
