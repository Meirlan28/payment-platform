-- Cross-authority escrow transfer hardening.  Destination consumption is a
-- local SERIALIZABLE commit followed by a destination-key signature over the
-- committed row's durable watermark.  Source settlement trusts that signed
-- receipt; it never joins a destination-local table.

CREATE TABLE IF NOT EXISTS escrow_verification_keys (
    key_id          STRING PRIMARY KEY,
    purpose         STRING NOT NULL CHECK (purpose IN
                        ('ESCROW_TRANSFER_CERTIFICATE_V2', 'ESCROW_CONSUMPTION_RECEIPT_V1')),
    legal_entity_id STRING NOT NULL,
    region          STRING NOT NULL,
    key_epoch       INT8 NOT NULL CHECK (key_epoch > 0),
    public_key      BYTES NOT NULL CHECK (length(public_key) = 32),
    state           STRING NOT NULL DEFAULT 'ACTIVE'
                    CHECK (state IN ('ACTIVE', 'VERIFY_ONLY', 'REVOKED')),
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    state_changed_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (purpose, legal_entity_id, region, key_epoch)
);

ALTER TABLE escrow_transfers
    ADD COLUMN IF NOT EXISTS source_legal_entity_id STRING NULL;
ALTER TABLE escrow_transfers
    ADD COLUMN IF NOT EXISTS destination_legal_entity_id STRING NULL;
ALTER TABLE escrow_transfers
    ADD COLUMN IF NOT EXISTS source_key_epoch INT8 NULL;
ALTER TABLE escrow_transfers
    ADD COLUMN IF NOT EXISTS consumption_receipt_payload BYTES NULL;
ALTER TABLE escrow_transfers
    ADD COLUMN IF NOT EXISTS consumption_receipt_sig BYTES NULL;
ALTER TABLE escrow_transfers
    ADD COLUMN IF NOT EXISTS consumption_receipt_hash BYTES NULL;
ALTER TABLE escrow_transfers
    ADD COLUMN IF NOT EXISTS destination_watermark INT8 NULL;
ALTER TABLE escrow_transfers
    ADD COLUMN IF NOT EXISTS receipt_key_id STRING NULL;
ALTER TABLE escrow_transfers
    ADD COLUMN IF NOT EXISTS receipt_key_epoch INT8 NULL;
ALTER TABLE escrow_transfers
    ALTER COLUMN certificate_sig DROP NOT NULL;

ALTER TABLE escrow_consumed_certificates
    ADD COLUMN IF NOT EXISTS source_legal_entity_id STRING NULL;
ALTER TABLE escrow_consumed_certificates
    ADD COLUMN IF NOT EXISTS source_key_epoch INT8 NULL;
ALTER TABLE escrow_consumed_certificates
    ADD COLUMN IF NOT EXISTS source_epoch INT8 NULL;
ALTER TABLE escrow_consumed_certificates
    ADD COLUMN IF NOT EXISTS destination_legal_entity_id STRING NULL;
ALTER TABLE escrow_consumed_certificates
    ADD COLUMN IF NOT EXISTS destination_key_id STRING NULL;
ALTER TABLE escrow_consumed_certificates
    ADD COLUMN IF NOT EXISTS destination_key_epoch INT8 NULL;
ALTER TABLE escrow_consumed_certificates
    ADD COLUMN IF NOT EXISTS destination_watermark INT8 NULL;
ALTER TABLE escrow_consumed_certificates
    ADD COLUMN IF NOT EXISTS receipt_payload BYTES NULL;
ALTER TABLE escrow_consumed_certificates
    ADD COLUMN IF NOT EXISTS receipt_sig BYTES NULL;
ALTER TABLE escrow_consumed_certificates
    ADD COLUMN IF NOT EXISTS receipt_signed_at TIMESTAMPTZ NULL;

-- The independent issuance tuple catches a compromised/restarted producer
-- that reuses one source sequence under a different TransferID.
CREATE UNIQUE INDEX IF NOT EXISTS escrow_consumed_source_issuance_uq
    ON escrow_consumed_certificates
       (source_legal_entity_id, source_region, source_key_epoch,
        account_id, asset_id, source_epoch)
    WHERE source_legal_entity_id IS NOT NULL
      AND source_key_epoch IS NOT NULL
      AND source_epoch IS NOT NULL;

CREATE TABLE IF NOT EXISTS escrow_consumption_watermarks (
    destination_legal_entity_id STRING NOT NULL,
    destination_region          STRING NOT NULL,
    next_watermark              INT8 NOT NULL DEFAULT 0
                                CHECK (next_watermark >= 0),
    PRIMARY KEY (destination_legal_entity_id, destination_region)
);

-- Lock rows make TransferID and the source issuance tuple independent
-- serialization points.  They are permanent, so a replay after arbitrary
-- retention periods cannot race a forgotten tombstone.
CREATE TABLE IF NOT EXISTS escrow_consumption_transfer_locks (
    transfer_id STRING PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE IF NOT EXISTS escrow_consumption_issuance_locks (
    source_legal_entity_id STRING NOT NULL,
    source_region          STRING NOT NULL,
    source_key_epoch       INT8 NOT NULL CHECK (source_key_epoch > 0),
    account_id             STRING NOT NULL,
    asset_id               STRING NOT NULL,
    source_epoch           INT8 NOT NULL CHECK (source_epoch > 0),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (source_legal_entity_id, source_region, source_key_epoch,
                 account_id, asset_id, source_epoch)
);

CREATE OR REPLACE FUNCTION enforce_escrow_verification_key_transition()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'escrow verification keys cannot be deleted';
    END IF;
    IF (OLD).key_id IS DISTINCT FROM (NEW).key_id
       OR (OLD).purpose IS DISTINCT FROM (NEW).purpose
       OR (OLD).legal_entity_id IS DISTINCT FROM (NEW).legal_entity_id
       OR (OLD).region IS DISTINCT FROM (NEW).region
       OR (OLD).key_epoch IS DISTINCT FROM (NEW).key_epoch
       OR (OLD).public_key IS DISTINCT FROM (NEW).public_key
       OR (OLD).registered_at IS DISTINCT FROM (NEW).registered_at THEN
        RAISE EXCEPTION 'escrow key identity is immutable';
    END IF;
    IF (OLD).state = 'REVOKED' OR
       ((OLD).state = 'VERIFY_ONLY' AND (NEW).state <> 'REVOKED') OR
       ((OLD).state = 'ACTIVE' AND (NEW).state NOT IN ('VERIFY_ONLY', 'REVOKED')) OR
       (OLD).state = (NEW).state THEN
        RAISE EXCEPTION 'invalid escrow key state transition';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER escrow_verification_key_update_guard
BEFORE UPDATE ON escrow_verification_keys
FOR EACH ROW EXECUTE FUNCTION enforce_escrow_verification_key_transition();
CREATE TRIGGER escrow_verification_key_delete_guard
BEFORE DELETE ON escrow_verification_keys
FOR EACH ROW EXECUTE FUNCTION enforce_escrow_verification_key_transition();

CREATE OR REPLACE FUNCTION enforce_escrow_consumed_certificate_immutability()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'consumed escrow certificates cannot be deleted';
    END IF;
    IF (OLD).transfer_id IS DISTINCT FROM (NEW).transfer_id
       OR (OLD).account_id IS DISTINCT FROM (NEW).account_id
       OR (OLD).asset_id IS DISTINCT FROM (NEW).asset_id
       OR (OLD).source_region IS DISTINCT FROM (NEW).source_region
       OR (OLD).destination_region IS DISTINCT FROM (NEW).destination_region
       OR (OLD).amount IS DISTINCT FROM (NEW).amount
       OR (OLD).payload_hash IS DISTINCT FROM (NEW).payload_hash
       OR (OLD).source_legal_entity_id IS DISTINCT FROM (NEW).source_legal_entity_id
       OR (OLD).source_key_epoch IS DISTINCT FROM (NEW).source_key_epoch
       OR (OLD).source_epoch IS DISTINCT FROM (NEW).source_epoch
       OR (OLD).destination_legal_entity_id IS DISTINCT FROM (NEW).destination_legal_entity_id
       OR (OLD).destination_key_id IS DISTINCT FROM (NEW).destination_key_id
       OR (OLD).destination_key_epoch IS DISTINCT FROM (NEW).destination_key_epoch
       OR (OLD).destination_watermark IS DISTINCT FROM (NEW).destination_watermark
       OR (OLD).receipt_payload IS DISTINCT FROM (NEW).receipt_payload
       OR (OLD).consumed_at IS DISTINCT FROM (NEW).consumed_at THEN
        RAISE EXCEPTION 'consumed escrow certificate identity is immutable';
    END IF;
    IF (OLD).receipt_sig IS NULL AND (NEW).receipt_sig IS NOT NULL
       AND (OLD).receipt_signed_at IS NULL AND (NEW).receipt_signed_at IS NOT NULL THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'consumed escrow receipt is append-only after signature attachment';
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER escrow_consumed_certificate_update_guard
BEFORE UPDATE ON escrow_consumed_certificates
FOR EACH ROW EXECUTE FUNCTION enforce_escrow_consumed_certificate_immutability();
CREATE TRIGGER escrow_consumed_certificate_delete_guard
BEFORE DELETE ON escrow_consumed_certificates
FOR EACH ROW EXECUTE FUNCTION enforce_escrow_consumed_certificate_immutability();

CREATE OR REPLACE FUNCTION enforce_escrow_transfer_transition_v2()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'escrow transfers cannot be deleted';
    END IF;
    IF (OLD).transfer_id IS DISTINCT FROM (NEW).transfer_id
       OR (OLD).account_id IS DISTINCT FROM (NEW).account_id
       OR (OLD).asset_id IS DISTINCT FROM (NEW).asset_id
       OR (OLD).source_region IS DISTINCT FROM (NEW).source_region
       OR (OLD).destination_region IS DISTINCT FROM (NEW).destination_region
       OR (OLD).amount IS DISTINCT FROM (NEW).amount
       OR (OLD).source_epoch IS DISTINCT FROM (NEW).source_epoch
       OR (OLD).key_id IS DISTINCT FROM (NEW).key_id
       OR (OLD).certificate_payload IS DISTINCT FROM (NEW).certificate_payload
       OR (OLD).source_legal_entity_id IS DISTINCT FROM (NEW).source_legal_entity_id
       OR (OLD).destination_legal_entity_id IS DISTINCT FROM (NEW).destination_legal_entity_id
       OR (OLD).source_key_epoch IS DISTINCT FROM (NEW).source_key_epoch
       OR (OLD).created_at IS DISTINCT FROM (NEW).created_at THEN
        RAISE EXCEPTION 'escrow transfer issuance identity is immutable';
    END IF;

    IF (OLD).certificate_sig IS NULL AND (NEW).certificate_sig IS NOT NULL
       AND (OLD).status = (NEW).status
       AND (OLD).consumption_receipt_payload IS NOT DISTINCT FROM (NEW).consumption_receipt_payload
       AND (OLD).consumption_receipt_sig IS NOT DISTINCT FROM (NEW).consumption_receipt_sig THEN
        RETURN NEW;
    END IF;

    IF (OLD).certificate_sig IS NOT NULL
       AND (OLD).certificate_sig IS NOT DISTINCT FROM (NEW).certificate_sig
       AND (OLD).status = 'IN_TRANSIT' AND (NEW).status = 'ACKNOWLEDGED'
       AND (OLD).acknowledged_at IS NULL AND (NEW).acknowledged_at IS NOT NULL
       AND (NEW).consumption_receipt_payload IS NOT NULL
       AND (NEW).consumption_receipt_sig IS NOT NULL
       AND (NEW).consumption_receipt_hash IS NOT NULL
       AND (NEW).destination_watermark IS NOT NULL
       AND (NEW).receipt_key_id IS NOT NULL
       AND (NEW).receipt_key_epoch IS NOT NULL THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid escrow transfer state transition';
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER escrow_transfer_update_guard_v2
BEFORE UPDATE ON escrow_transfers
FOR EACH ROW EXECUTE FUNCTION enforce_escrow_transfer_transition_v2();
CREATE TRIGGER escrow_transfer_delete_guard_v2
BEFORE DELETE ON escrow_transfers
FOR EACH ROW EXECUTE FUNCTION enforce_escrow_transfer_transition_v2();

CREATE OR REPLACE FUNCTION reject_escrow_consumption_lock_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'escrow consumption lock history is immutable';
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER escrow_consumption_transfer_lock_no_update
BEFORE UPDATE OR DELETE ON escrow_consumption_transfer_locks
FOR EACH ROW EXECUTE FUNCTION reject_escrow_consumption_lock_mutation();
CREATE TRIGGER escrow_consumption_issuance_lock_no_update
BEFORE UPDATE OR DELETE ON escrow_consumption_issuance_locks
FOR EACH ROW EXECUTE FUNCTION reject_escrow_consumption_lock_mutation();

REVOKE ALL ON TABLE escrow_verification_keys,
    escrow_consumption_watermarks, escrow_consumption_transfer_locks,
    escrow_consumption_issuance_locks FROM public;
GRANT ALL ON TABLE escrow_verification_keys,
    escrow_consumption_watermarks, escrow_consumption_transfer_locks,
    escrow_consumption_issuance_locks TO ledger_admin;
GRANT SELECT ON TABLE escrow_verification_keys TO ledger_writer, ledger_reader,
    ledger_auditor, reconciliation_runtime;
GRANT SELECT, INSERT, UPDATE ON TABLE escrow_consumption_watermarks TO ledger_writer;
GRANT SELECT, INSERT ON TABLE escrow_consumption_transfer_locks,
    escrow_consumption_issuance_locks TO ledger_writer;
GRANT SELECT ON TABLE escrow_consumption_watermarks,
    escrow_consumption_transfer_locks, escrow_consumption_issuance_locks
    TO ledger_reader, ledger_auditor, reconciliation_runtime;
