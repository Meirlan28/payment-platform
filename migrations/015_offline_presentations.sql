-- EXPAND ONLY: non-transferable offline presentations and domain-closure
-- evidence. Every new column is nullable and the v1 receipt/proof guards from
-- migration 009 remain in force. Therefore a drained-or-undrained v1 writer
-- can run after this migration, while the v2 writer can already dual-write
-- the complete evidence. The separately gated offline contract migration must
-- not be applied until the rollout queries in docs/operations.md are empty.
-- Correctness uses signed logical epochs, upload fences, and monotonic secure-
-- element counters. TIMESTAMPTZ columns are audit metadata only.

CREATE TABLE IF NOT EXISTS offline_acceptance_domains (
    acceptance_domain       STRING PRIMARY KEY CHECK (length(acceptance_domain) > 0),
    -- Compatibility pointer for the initial key. Append-only rotation history
    -- is introduced separately; this column is never updated.
    closure_key_id          STRING NOT NULL UNIQUE CHECK (length(closure_key_id) > 0),
    first_settlement_epoch  INT8 NOT NULL CHECK (first_settlement_epoch > 0),
    last_settlement_epoch   INT8 NULL,
    configured_at           TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    CHECK (last_settlement_epoch IS NULL
           OR last_settlement_epoch >= first_settlement_epoch)
);

CREATE OR REPLACE FUNCTION reject_offline_acceptance_domain_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'offline acceptance-domain coverage is immutable';
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER offline_acceptance_domain_no_update
BEFORE UPDATE ON offline_acceptance_domains
FOR EACH ROW EXECUTE FUNCTION reject_offline_acceptance_domain_mutation();
CREATE TRIGGER offline_acceptance_domain_no_delete
BEFORE DELETE ON offline_acceptance_domains
FOR EACH ROW EXECUTE FUNCTION reject_offline_acceptance_domain_mutation();

-- Historical v1 rows intentionally stay NULL. The v2 application dual-writes
-- all fields before the later contract migration makes omissions fail closed.
ALTER TABLE offline_redemption_receipts
    ADD COLUMN IF NOT EXISTS presentation_payload_hash BYTES NULL;
ALTER TABLE offline_redemption_receipts
    ADD COLUMN IF NOT EXISTS presentation_hash BYTES NULL;
ALTER TABLE offline_redemption_receipts
    ADD COLUMN IF NOT EXISTS merchant_account_id STRING NULL;
ALTER TABLE offline_redemption_receipts
    ADD COLUMN IF NOT EXISTS acceptance_domain STRING NULL;
ALTER TABLE offline_redemption_receipts
    ADD COLUMN IF NOT EXISTS challenge_hash BYTES NULL;
ALTER TABLE offline_redemption_receipts
    ADD COLUMN IF NOT EXISTS merchant_challenge BYTES NULL;
ALTER TABLE offline_redemption_receipts
    ADD COLUMN IF NOT EXISTS settlement_epoch INT8 NULL;
ALTER TABLE offline_redemption_receipts
    ADD COLUMN IF NOT EXISTS upload_fence INT8 NULL;
ALTER TABLE offline_redemption_receipts
    ADD COLUMN IF NOT EXISTS presentation_counter INT8 NULL;
ALTER TABLE offline_redemption_receipts
    ADD COLUMN IF NOT EXISTS device_identity_hash BYTES NULL;
ALTER TABLE offline_redemption_receipts
    ADD COLUMN IF NOT EXISTS device_key_id STRING NULL;
ALTER TABLE offline_redemption_receipts
    ADD COLUMN IF NOT EXISTS presentation_payload BYTES NULL;
ALTER TABLE offline_redemption_receipts
    ADD COLUMN IF NOT EXISTS presentation_signature BYTES NULL;

ALTER TABLE offline_redemption_receipts
    ADD CONSTRAINT offline_receipt_acceptance_domain_fk
    FOREIGN KEY (acceptance_domain)
    REFERENCES offline_acceptance_domains (acceptance_domain);

CREATE UNIQUE INDEX IF NOT EXISTS offline_receipt_presentation_hash_uq
    ON offline_redemption_receipts (presentation_hash)
    WHERE presentation_hash IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS offline_receipt_challenge_uq
    ON offline_redemption_receipts
       (acceptance_domain, merchant_account_id, challenge_hash)
    WHERE challenge_hash IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS offline_receipt_device_counter_uq
    ON offline_redemption_receipts (device_identity_hash, presentation_counter)
    WHERE device_identity_hash IS NOT NULL AND presentation_counter IS NOT NULL;

-- Domain closure facts are reusable, immutable signed watermarks bound to one
-- exact issuance namespace. The v2 writer records these rows and links them to
-- a terminal proof; enforcement is deliberately deferred to the contract.
CREATE TABLE IF NOT EXISTS offline_domain_closure_evidence (
    evidence_hash            BYTES PRIMARY KEY CHECK (length(evidence_hash) = 32),
    acceptance_domain        STRING NOT NULL
                             REFERENCES offline_acceptance_domains (acceptance_domain),
    account_id               STRING NOT NULL,
    asset_id                 STRING NOT NULL,
    origin_region            STRING NOT NULL,
    device_identity_hash     BYTES NOT NULL CHECK (length(device_identity_hash) = 32),
    closed_settlement_epoch  INT8 NOT NULL CHECK (closed_settlement_epoch > 0),
    closed_upload_fence      INT8 NOT NULL CHECK (closed_upload_fence >= 0),
    key_id                   STRING NOT NULL,
    payload_hash             BYTES NOT NULL CHECK (length(payload_hash) = 32),
    canonical_payload        BYTES NOT NULL,
    signature                BYTES NOT NULL,
    recorded_at              TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (account_id, asset_id, origin_region, device_identity_hash)
        REFERENCES offline_device_counters
            (account_id, asset_id, origin_region, device_identity_hash),
    UNIQUE (acceptance_domain, account_id, asset_id, origin_region,
            device_identity_hash, closed_settlement_epoch,
            closed_upload_fence, key_id, payload_hash)
);

CREATE TABLE IF NOT EXISTS offline_termination_closure_links (
    allowance_id       STRING NOT NULL REFERENCES offline_allowances (allowance_id),
    acceptance_domain  STRING NOT NULL
                       REFERENCES offline_acceptance_domains (acceptance_domain),
    evidence_hash      BYTES NOT NULL
                       REFERENCES offline_domain_closure_evidence (evidence_hash),
    linked_at          TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (allowance_id, acceptance_domain),
    UNIQUE (allowance_id, evidence_hash)
);

ALTER TABLE offline_non_redemption_proofs
    ADD COLUMN IF NOT EXISTS closure_set_hash BYTES NULL;

CREATE OR REPLACE FUNCTION reject_offline_presentation_history_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'offline presentation/closure history is immutable';
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER offline_domain_closure_no_update
BEFORE UPDATE ON offline_domain_closure_evidence
FOR EACH ROW EXECUTE FUNCTION reject_offline_presentation_history_mutation();
CREATE TRIGGER offline_domain_closure_no_delete
BEFORE DELETE ON offline_domain_closure_evidence
FOR EACH ROW EXECUTE FUNCTION reject_offline_presentation_history_mutation();
CREATE TRIGGER offline_termination_closure_link_no_update
BEFORE UPDATE ON offline_termination_closure_links
FOR EACH ROW EXECUTE FUNCTION reject_offline_presentation_history_mutation();
CREATE TRIGGER offline_termination_closure_link_no_delete
BEFORE DELETE ON offline_termination_closure_links
FOR EACH ROW EXECUTE FUNCTION reject_offline_presentation_history_mutation();

REVOKE ALL ON TABLE offline_acceptance_domains,
    offline_domain_closure_evidence, offline_termination_closure_links FROM public;
GRANT ALL ON TABLE offline_acceptance_domains,
    offline_domain_closure_evidence, offline_termination_closure_links TO ledger_admin;

-- Compatibility grants are intentionally broad during expand. Migration 024
-- revokes raw mutation after every writer uses the narrow procedures.
GRANT SELECT ON TABLE offline_acceptance_domains TO ledger_writer;
GRANT SELECT, INSERT ON TABLE offline_domain_closure_evidence,
    offline_termination_closure_links TO ledger_writer;
GRANT SELECT ON TABLE offline_acceptance_domains,
    offline_domain_closure_evidence, offline_termination_closure_links
    TO ledger_reader, ledger_auditor, reconciliation_runtime;

REVOKE EXECUTE ON FUNCTION reject_offline_acceptance_domain_mutation() FROM public;
REVOKE EXECUTE ON FUNCTION reject_offline_presentation_history_mutation() FROM public;
