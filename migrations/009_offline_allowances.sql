-- Single-use offline spending allowances. Correctness depends on durable
-- counters, issuer epochs, signatures, and SERIALIZABLE row transitions; wall
-- clocks below are audit metadata only.

CREATE TABLE IF NOT EXISTS offline_device_counters (
    account_id           STRING NOT NULL,
    asset_id             STRING NOT NULL,
    origin_region        STRING NOT NULL,
    device_identity_hash BYTES NOT NULL CHECK (length(device_identity_hash) = 32),
    issuer_epoch         INT8 NOT NULL CHECK (issuer_epoch > 0),
    last_counter         INT8 NOT NULL DEFAULT 0 CHECK (last_counter >= 0),
    fence_version        INT8 NOT NULL DEFAULT 0 CHECK (fence_version >= 0),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (account_id, asset_id, origin_region, device_identity_hash),
    FOREIGN KEY (account_id, asset_id, origin_region)
        REFERENCES escrow_regional_rights (account_id, asset_id, region)
);

-- This is the materialized offline-issued term in the authority conservation
-- equation. It avoids scanning individual instruments on the authorization
-- path; reconciliation independently folds the immutable allowance facts.
CREATE TABLE IF NOT EXISTS escrow_offline_issued (
    account_id    STRING NOT NULL,
    asset_id      STRING NOT NULL,
    origin_region STRING NOT NULL,
    amount        DECIMAL(38,0) NOT NULL DEFAULT 0 CHECK (amount >= 0),
    version       INT8 NOT NULL DEFAULT 0 CHECK (version >= 0),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (account_id, asset_id, origin_region),
    FOREIGN KEY (account_id, asset_id, origin_region)
        REFERENCES escrow_regional_rights (account_id, asset_id, region)
);

CREATE TABLE IF NOT EXISTS offline_allowances (
    allowance_id         STRING PRIMARY KEY,
    account_id           STRING NOT NULL,
    asset_id             STRING NOT NULL,
    origin_region        STRING NOT NULL,
    device_identity_hash BYTES NOT NULL CHECK (length(device_identity_hash) = 32),
    device_counter       INT8 NOT NULL CHECK (device_counter > 0),
    amount               DECIMAL(38,0) NOT NULL CHECK (amount > 0),
    issuer_epoch         INT8 NOT NULL CHECK (issuer_epoch > 0),
    key_id               STRING NOT NULL,
    canonical_payload    BYTES NOT NULL,
    payload_hash         BYTES NOT NULL CHECK (length(payload_hash) = 32),
    signature            BYTES NULL,
    state                STRING NOT NULL DEFAULT 'PREPARED'
                         CHECK (state IN ('PREPARED', 'ISSUED', 'REDEEMED', 'REVOKED', 'EXPIRED')),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    issued_at            TIMESTAMPTZ NULL,
    redeemed_at          TIMESTAMPTZ NULL,
    terminal_at          TIMESTAMPTZ NULL,
    FOREIGN KEY (account_id, asset_id, origin_region, device_identity_hash)
        REFERENCES offline_device_counters
            (account_id, asset_id, origin_region, device_identity_hash),
    UNIQUE (account_id, asset_id, origin_region, device_identity_hash,
            issuer_epoch, device_counter),
    CHECK (
        (state = 'PREPARED' AND signature IS NULL AND issued_at IS NULL
                            AND redeemed_at IS NULL AND terminal_at IS NULL)
        OR
        (state = 'ISSUED' AND signature IS NOT NULL AND issued_at IS NOT NULL
                          AND redeemed_at IS NULL AND terminal_at IS NULL)
        OR
        (state = 'REDEEMED' AND signature IS NOT NULL AND issued_at IS NOT NULL
                            AND redeemed_at IS NOT NULL AND terminal_at IS NULL)
        OR
        (state IN ('REVOKED', 'EXPIRED') AND signature IS NOT NULL
                          AND issued_at IS NOT NULL AND redeemed_at IS NULL
                          AND terminal_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS offline_allowances_outstanding_idx
    ON offline_allowances (account_id, asset_id, origin_region, allowance_id)
    WHERE state = 'ISSUED';

CREATE OR REPLACE FUNCTION enforce_offline_device_counter_transition()
RETURNS TRIGGER AS $$
BEGIN
    IF (OLD).account_id IS DISTINCT FROM (NEW).account_id
       OR (OLD).asset_id IS DISTINCT FROM (NEW).asset_id
       OR (OLD).origin_region IS DISTINCT FROM (NEW).origin_region
       OR (OLD).device_identity_hash IS DISTINCT FROM (NEW).device_identity_hash
       OR (NEW).fence_version < (OLD).fence_version THEN
        RAISE EXCEPTION 'offline device identity/fence is immutable or monotonic';
    END IF;

    IF (NEW).issuer_epoch = (OLD).issuer_epoch THEN
        IF (NEW).last_counter < (OLD).last_counter THEN
            RAISE EXCEPTION 'offline device counter cannot move backwards';
        END IF;
        RETURN NEW;
    END IF;
    IF (NEW).issuer_epoch = (OLD).issuer_epoch + 1
       AND (NEW).last_counter = 0
       AND (NEW).fence_version > (OLD).fence_version THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'offline issuer epoch must advance exactly once under a new fence';
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER offline_device_counter_transition_guard
BEFORE UPDATE ON offline_device_counters
FOR EACH ROW
EXECUTE FUNCTION enforce_offline_device_counter_transition();

-- Permanent exactly-once economic-effect receipt. There is intentionally no
-- retention timestamp or deletion path: a six-month-late duplicate must still
-- be recognized after operational event retention has elapsed.
CREATE TABLE IF NOT EXISTS offline_redemption_receipts (
    allowance_id         STRING PRIMARY KEY REFERENCES offline_allowances (allowance_id),
    payload_hash         BYTES NOT NULL CHECK (length(payload_hash) = 32),
    effect_hash          BYTES NOT NULL CHECK (length(effect_hash) = 32),
    effect_id            STRING NOT NULL,
    ledger_transaction_id STRING NOT NULL UNIQUE
                          REFERENCES ledger_transactions (transaction_id),
    posting_request_hash BYTES NOT NULL CHECK (length(posting_request_hash) = 32),
    redeemed_at          TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (effect_id)
);

-- A receipt may only be inserted after ledger.PostInTx has finalized the
-- matching effect in the same SQL transaction. This database-level guard
-- makes a standalone/phantom authority consumption impossible even if an
-- application caller misorders the operations.
CREATE OR REPLACE FUNCTION enforce_offline_redemption_ledger_effect()
RETURNS TRIGGER AS $$
DECLARE
    matching_effects INT8 := 0;
    allowance_amount DECIMAL;
    allowance_account STRING;
    allowance_asset STRING;
    matching_debit DECIMAL;
BEGIN
    SELECT count(*) INTO matching_effects
      FROM ledger_transactions
     WHERE transaction_id = (NEW).ledger_transaction_id
       AND effect_id = (NEW).effect_id
       AND request_hash = (NEW).posting_request_hash
       AND status = 'POSTED';
    IF matching_effects <> 1 THEN
        RAISE EXCEPTION 'offline redemption requires matching POSTED ledger effect';
    END IF;
    SELECT amount, account_id, asset_id
      INTO allowance_amount, allowance_account, allowance_asset
      FROM offline_allowances WHERE allowance_id = (NEW).allowance_id;
    SELECT coalesce(sum(amount_atoms), 0) INTO matching_debit
      FROM ledger_lines
     WHERE transaction_id = (NEW).ledger_transaction_id
       AND account_id = allowance_account
       AND asset_id = allowance_asset
       AND side = 'DEBIT';
    IF matching_debit <> allowance_amount THEN
        RAISE EXCEPTION 'offline redemption ledger debit does not match allowance';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER offline_receipt_requires_posted_ledger_effect
BEFORE INSERT ON offline_redemption_receipts
FOR EACH ROW
EXECUTE FUNCTION enforce_offline_redemption_ledger_effect();

-- A revocation/expiry proof is created under the same row lock that proves no
-- redemption receipt exists. fence_version is a monotonically increasing
-- consensus token, not a timestamp.
CREATE TABLE IF NOT EXISTS offline_non_redemption_proofs (
    allowance_id        STRING PRIMARY KEY REFERENCES offline_allowances (allowance_id),
    terminal_kind       STRING NOT NULL CHECK (terminal_kind IN ('REVOKED', 'EXPIRED')),
    payload_hash        BYTES NOT NULL CHECK (length(payload_hash) = 32),
    issuer_epoch        INT8 NOT NULL CHECK (issuer_epoch > 0),
    device_counter      INT8 NOT NULL CHECK (device_counter > 0),
    fence_version       INT8 NOT NULL CHECK (fence_version > 0),
    policy_evidence_hash BYTES NOT NULL CHECK (length(policy_evidence_hash) = 32),
    proof_hash          BYTES NOT NULL CHECK (length(proof_hash) = 32),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp()
);

CREATE OR REPLACE FUNCTION enforce_offline_allowance_transition()
RETURNS TRIGGER AS $$
BEGIN
    IF (OLD).allowance_id IS DISTINCT FROM (NEW).allowance_id
       OR (OLD).account_id IS DISTINCT FROM (NEW).account_id
       OR (OLD).asset_id IS DISTINCT FROM (NEW).asset_id
       OR (OLD).origin_region IS DISTINCT FROM (NEW).origin_region
       OR (OLD).device_identity_hash IS DISTINCT FROM (NEW).device_identity_hash
       OR (OLD).device_counter IS DISTINCT FROM (NEW).device_counter
       OR (OLD).amount IS DISTINCT FROM (NEW).amount
       OR (OLD).issuer_epoch IS DISTINCT FROM (NEW).issuer_epoch
       OR (OLD).key_id IS DISTINCT FROM (NEW).key_id
       OR (OLD).canonical_payload IS DISTINCT FROM (NEW).canonical_payload
       OR (OLD).payload_hash IS DISTINCT FROM (NEW).payload_hash
       OR (OLD).created_at IS DISTINCT FROM (NEW).created_at THEN
        RAISE EXCEPTION 'offline allowance immutable payload was changed';
    END IF;

    IF (OLD).state = 'PREPARED' AND (NEW).state = 'ISSUED' THEN
        IF (OLD).signature IS NOT NULL OR (NEW).signature IS NULL
           OR (NEW).issued_at IS NULL THEN
            RAISE EXCEPTION 'invalid offline allowance issuance';
        END IF;
        RETURN NEW;
    END IF;
    IF (OLD).state = 'ISSUED' AND (NEW).state = 'REDEEMED' THEN
        IF (OLD).signature IS DISTINCT FROM (NEW).signature
           OR (OLD).issued_at IS DISTINCT FROM (NEW).issued_at
           OR (NEW).redeemed_at IS NULL THEN
            RAISE EXCEPTION 'invalid offline allowance redemption';
        END IF;
        RETURN NEW;
    END IF;
    IF (OLD).state = 'ISSUED' AND (NEW).state IN ('REVOKED', 'EXPIRED') THEN
        IF (OLD).signature IS DISTINCT FROM (NEW).signature
           OR (OLD).issued_at IS DISTINCT FROM (NEW).issued_at
           OR (NEW).terminal_at IS NULL THEN
            RAISE EXCEPTION 'invalid offline allowance terminal transition';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid offline allowance state transition';
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER offline_allowance_transition_guard
BEFORE UPDATE ON offline_allowances
FOR EACH ROW
EXECUTE FUNCTION enforce_offline_allowance_transition();

CREATE OR REPLACE FUNCTION reject_offline_history_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'offline allowance proof/receipt history is immutable';
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER offline_receipt_no_update
BEFORE UPDATE ON offline_redemption_receipts
FOR EACH ROW EXECUTE FUNCTION reject_offline_history_mutation();
CREATE TRIGGER offline_receipt_no_delete
BEFORE DELETE ON offline_redemption_receipts
FOR EACH ROW EXECUTE FUNCTION reject_offline_history_mutation();
CREATE TRIGGER offline_proof_no_update
BEFORE UPDATE ON offline_non_redemption_proofs
FOR EACH ROW EXECUTE FUNCTION reject_offline_history_mutation();
CREATE TRIGGER offline_proof_no_delete
BEFORE DELETE ON offline_non_redemption_proofs
FOR EACH ROW EXECUTE FUNCTION reject_offline_history_mutation();
CREATE TRIGGER offline_allowance_no_delete
BEFORE DELETE ON offline_allowances
FOR EACH ROW EXECUTE FUNCTION reject_offline_history_mutation();

-- Reconciliation view. A healthy row satisfies both the global authority
-- equation and the fold of ISSUED allowance facts into the materialized bucket.
CREATE OR REPLACE VIEW escrow_authority_conservation AS
SELECT authority.account_id,
       authority.asset_id,
       authority.total_authority,
       authority.unallocated,
       coalesce(regional.amount, 0)::DECIMAL(38,0) AS regional,
       coalesce(transit.amount, 0)::DECIMAL(38,0) AS in_transit,
       coalesce(offline.amount, 0)::DECIMAL(38,0) AS offline_issued,
       coalesce(folded.amount, 0)::DECIMAL(38,0) AS folded_offline_issued,
       (authority.unallocated + coalesce(regional.amount, 0)
          + coalesce(transit.amount, 0) + coalesce(offline.amount, 0)
          = authority.total_authority
        AND coalesce(offline.amount, 0) = coalesce(folded.amount, 0)) AS conserved
  FROM escrow_authorities AS authority
  LEFT JOIN (
      SELECT account_id, asset_id, sum(available) AS amount
        FROM escrow_regional_rights GROUP BY account_id, asset_id
  ) AS regional USING (account_id, asset_id)
  LEFT JOIN (
      SELECT account_id, asset_id, sum(amount) AS amount
        FROM escrow_transfers WHERE status = 'IN_TRANSIT'
       GROUP BY account_id, asset_id
  ) AS transit USING (account_id, asset_id)
  LEFT JOIN (
      SELECT account_id, asset_id, sum(amount) AS amount
        FROM escrow_offline_issued GROUP BY account_id, asset_id
  ) AS offline USING (account_id, asset_id)
  LEFT JOIN (
      SELECT account_id, asset_id, sum(amount) AS amount
        FROM offline_allowances WHERE state = 'ISSUED'
       GROUP BY account_id, asset_id
  ) AS folded USING (account_id, asset_id);

REVOKE ALL ON TABLE offline_device_counters, escrow_offline_issued,
    offline_allowances, offline_redemption_receipts,
    offline_non_redemption_proofs FROM public;
REVOKE ALL ON escrow_authority_conservation FROM public;

GRANT ALL ON TABLE offline_device_counters, escrow_offline_issued,
    offline_allowances, offline_redemption_receipts,
    offline_non_redemption_proofs TO ledger_admin;
GRANT SELECT ON escrow_authority_conservation TO ledger_admin;

GRANT SELECT, INSERT, UPDATE ON TABLE offline_device_counters,
    escrow_offline_issued, offline_allowances TO ledger_writer;
GRANT SELECT, INSERT ON TABLE offline_redemption_receipts,
    offline_non_redemption_proofs TO ledger_writer;

GRANT SELECT ON TABLE offline_device_counters, escrow_offline_issued,
    offline_allowances, offline_redemption_receipts,
    offline_non_redemption_proofs TO ledger_reader, ledger_auditor;
GRANT SELECT ON escrow_authority_conservation
    TO ledger_writer, ledger_reader, ledger_auditor;
