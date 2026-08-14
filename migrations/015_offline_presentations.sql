-- Non-transferable offline presentations and fail-closed authority return.
-- Correctness uses only signed logical epochs, upload fences and monotonic
-- secure-element counters. TIMESTAMPTZ columns below are audit metadata.

CREATE TABLE IF NOT EXISTS offline_acceptance_domains (
    acceptance_domain       STRING PRIMARY KEY CHECK (length(acceptance_domain) > 0),
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

-- New receipts carry the device-signed presentation. Columns remain nullable
-- only so an online migration never rewrites historical v1 rows. The replaced
-- insert guard below requires every field for all post-migration receipts;
-- legacy rows remain visibly unverifiable and cannot be mistaken for v2.
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

CREATE OR REPLACE FUNCTION enforce_offline_redemption_ledger_effect()
RETURNS TRIGGER AS $$
DECLARE
    matching_effects INT8 := 0;
    allowance_amount DECIMAL;
    allowance_account STRING;
    allowance_asset STRING;
    allowance_payload_hash BYTES;
    allowance_device_hash BYTES;
    allowance_epoch INT8;
    allowance_fence INT8;
    matching_debit DECIMAL;
    matching_merchant_credit DECIMAL;
    configured_domains INT8 := 0;
BEGIN
    IF (NEW).presentation_payload_hash IS NULL
       OR length((NEW).presentation_payload_hash) <> 32
       OR (NEW).presentation_hash IS NULL
       OR length((NEW).presentation_hash) <> 32
       OR (NEW).merchant_account_id IS NULL
       OR length((NEW).merchant_account_id) = 0
       OR (NEW).acceptance_domain IS NULL
       OR length((NEW).acceptance_domain) = 0
       OR (NEW).challenge_hash IS NULL OR length((NEW).challenge_hash) <> 32
       OR (NEW).settlement_epoch IS NULL OR (NEW).settlement_epoch <= 0
       OR (NEW).upload_fence IS NULL OR (NEW).upload_fence <= 0
       OR (NEW).presentation_counter IS NULL OR (NEW).presentation_counter <= 0
       OR (NEW).device_identity_hash IS NULL
       OR length((NEW).device_identity_hash) <> 32
       OR (NEW).device_key_id IS NULL OR length((NEW).device_key_id) = 0
       OR (NEW).presentation_payload IS NULL
       OR length((NEW).presentation_payload) = 0
       OR (NEW).presentation_signature IS NULL
       OR length((NEW).presentation_signature) = 0 THEN
        RAISE EXCEPTION 'offline redemption requires complete secure-element presentation';
    END IF;

    SELECT count(*) INTO matching_effects
      FROM ledger_transactions
     WHERE transaction_id = (NEW).ledger_transaction_id
       AND effect_id = (NEW).effect_id
       AND request_hash = (NEW).posting_request_hash
       AND status = 'POSTED';
    IF matching_effects <> 1 THEN
        RAISE EXCEPTION 'offline redemption requires matching POSTED ledger effect';
    END IF;

    SELECT amount, account_id, asset_id, payload_hash, device_identity_hash,
           issuer_epoch, device_counter
      INTO allowance_amount, allowance_account, allowance_asset,
           allowance_payload_hash, allowance_device_hash,
           allowance_epoch, allowance_fence
      FROM offline_allowances WHERE allowance_id = (NEW).allowance_id;
    IF (NEW).payload_hash IS DISTINCT FROM allowance_payload_hash
       OR (NEW).device_identity_hash IS DISTINCT FROM allowance_device_hash
       OR (NEW).settlement_epoch <> allowance_epoch
       OR (NEW).upload_fence <> allowance_fence
       OR (NEW).merchant_account_id = allowance_account THEN
        RAISE EXCEPTION 'offline presentation does not bind the issued allowance';
    END IF;

    SELECT count(*) INTO configured_domains
      FROM offline_acceptance_domains
     WHERE acceptance_domain = (NEW).acceptance_domain
       AND first_settlement_epoch <= allowance_epoch
       AND (last_settlement_epoch IS NULL
            OR last_settlement_epoch >= allowance_epoch);
    IF configured_domains <> 1 THEN
        RAISE EXCEPTION 'offline presentation acceptance domain is not configured';
    END IF;

    SELECT coalesce(sum(amount_atoms), 0) INTO matching_debit
      FROM ledger_lines
     WHERE transaction_id = (NEW).ledger_transaction_id
       AND account_id = allowance_account
       AND asset_id = allowance_asset
       AND side = 'DEBIT';
    SELECT coalesce(sum(amount_atoms), 0) INTO matching_merchant_credit
      FROM ledger_lines
     WHERE transaction_id = (NEW).ledger_transaction_id
       AND account_id = (NEW).merchant_account_id
       AND asset_id = allowance_asset
       AND side = 'CREDIT';
    IF matching_debit <> allowance_amount
       OR matching_merchant_credit <> allowance_amount THEN
        RAISE EXCEPTION 'offline redemption debit/merchant credit does not match allowance';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

-- Domain closure facts are reusable, immutable signed watermarks. A domain is
-- contractually allowed to sign only after every presentation at or below its
-- watermark is durably uploaded or durably rejected.
CREATE TABLE IF NOT EXISTS offline_domain_closure_evidence (
    evidence_hash            BYTES PRIMARY KEY CHECK (length(evidence_hash) = 32),
    acceptance_domain        STRING NOT NULL
                             REFERENCES offline_acceptance_domains (acceptance_domain),
    closed_settlement_epoch  INT8 NOT NULL CHECK (closed_settlement_epoch > 0),
    closed_upload_fence      INT8 NOT NULL CHECK (closed_upload_fence >= 0),
    key_id                   STRING NOT NULL,
    payload_hash             BYTES NOT NULL CHECK (length(payload_hash) = 32),
    canonical_payload        BYTES NOT NULL,
    signature                BYTES NOT NULL,
    recorded_at              TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (acceptance_domain, closed_settlement_epoch,
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

CREATE OR REPLACE FUNCTION enforce_offline_complete_domain_closure()
RETURNS TRIGGER AS $$
DECLARE
    allowance_epoch INT8;
    allowance_fence INT8;
    required_domains INT8 := 0;
    valid_links INT8 := 0;
    all_links INT8 := 0;
BEGIN
    IF (NEW).closure_set_hash IS NULL
       OR length((NEW).closure_set_hash) <> 32 THEN
        RAISE EXCEPTION 'offline termination requires closure-set hash';
    END IF;
    SELECT issuer_epoch, device_counter
      INTO allowance_epoch, allowance_fence
      FROM offline_allowances WHERE allowance_id=(NEW).allowance_id;

    SELECT count(*) INTO required_domains
      FROM offline_acceptance_domains
     WHERE first_settlement_epoch <= allowance_epoch
       AND (last_settlement_epoch IS NULL
            OR last_settlement_epoch >= allowance_epoch);
    SELECT count(*) INTO all_links
      FROM offline_termination_closure_links
     WHERE allowance_id=(NEW).allowance_id;
    SELECT count(*) INTO valid_links
      FROM offline_termination_closure_links AS link
      JOIN offline_acceptance_domains AS domain
        ON domain.acceptance_domain=link.acceptance_domain
      JOIN offline_domain_closure_evidence AS evidence
        ON evidence.evidence_hash=link.evidence_hash
       AND evidence.acceptance_domain=link.acceptance_domain
       AND evidence.key_id=domain.closure_key_id
     WHERE link.allowance_id=(NEW).allowance_id
       AND domain.first_settlement_epoch <= allowance_epoch
       AND (domain.last_settlement_epoch IS NULL
            OR domain.last_settlement_epoch >= allowance_epoch)
       AND (evidence.closed_settlement_epoch > allowance_epoch
            OR (evidence.closed_settlement_epoch = allowance_epoch
                AND evidence.closed_upload_fence >= allowance_fence));
    IF required_domains = 0 OR all_links <> required_domains
       OR valid_links <> required_domains THEN
        RAISE EXCEPTION 'offline termination lacks complete signed domain closure';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER offline_proof_requires_complete_domain_closure
BEFORE INSERT ON offline_non_redemption_proofs
FOR EACH ROW EXECUTE FUNCTION enforce_offline_complete_domain_closure();

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
GRANT SELECT ON TABLE offline_acceptance_domains TO ledger_writer;
GRANT SELECT, INSERT ON TABLE offline_domain_closure_evidence,
    offline_termination_closure_links TO ledger_writer;
GRANT SELECT ON TABLE offline_acceptance_domains,
    offline_domain_closure_evidence, offline_termination_closure_links
    TO ledger_reader, ledger_auditor, reconciliation_runtime;

REVOKE EXECUTE ON FUNCTION reject_offline_acceptance_domain_mutation() FROM public;
REVOKE EXECUTE ON FUNCTION enforce_offline_redemption_ledger_effect() FROM public;
REVOKE EXECUTE ON FUNCTION enforce_offline_complete_domain_closure() FROM public;
REVOKE EXECUTE ON FUNCTION reject_offline_presentation_history_mutation() FROM public;
