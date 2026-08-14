-- Permanent exactly-once receipts for every local escrow authority mutation.
-- The receipt and authority update are committed by the same SERIALIZABLE
-- transaction. Wall-clock timestamps are evidence only and never identify or
-- order an economic effect.

CREATE TABLE IF NOT EXISTS escrow_effect_receipts (
    effect_id     STRING PRIMARY KEY CHECK (length(effect_id) BETWEEN 1 AND 512),
    effect_kind   STRING NOT NULL CHECK (effect_kind IN ('ALLOCATE', 'SPEND', 'RETURN')),
    account_id    STRING NOT NULL,
    asset_id      STRING NOT NULL,
    region        STRING NOT NULL,
    amount        DECIMAL(38,0) NOT NULL CHECK (amount > 0),
    request_hash  BYTES NOT NULL CHECK (length(request_hash) = 32),
    committed_at  TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (account_id, asset_id)
        REFERENCES escrow_authorities (account_id, asset_id)
);

CREATE INDEX IF NOT EXISTS escrow_effect_receipts_authority_idx
    ON escrow_effect_receipts (account_id, asset_id, committed_at);

CREATE OR REPLACE FUNCTION reject_escrow_effect_receipt_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'escrow effect receipts are append-only';
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER escrow_effect_receipt_no_update
BEFORE UPDATE ON escrow_effect_receipts
FOR EACH ROW
EXECUTE FUNCTION reject_escrow_effect_receipt_mutation();

CREATE TRIGGER escrow_effect_receipt_no_delete
BEFORE DELETE ON escrow_effect_receipts
FOR EACH ROW
EXECUTE FUNCTION reject_escrow_effect_receipt_mutation();

REVOKE ALL ON TABLE escrow_effect_receipts FROM public;
GRANT ALL ON TABLE escrow_effect_receipts TO ledger_admin;
GRANT SELECT, INSERT ON TABLE escrow_effect_receipts TO ledger_writer;
GRANT SELECT ON TABLE escrow_effect_receipts TO ledger_reader, ledger_auditor,
    reconciliation_runtime;

-- Provider outcomes are first-terminal-wins. A late or concurrent lookup may
-- add evidence elsewhere, but it must never rewrite a committed economic
-- answer from SUCCEEDED to FAILED (or vice versa).
CREATE OR REPLACE FUNCTION enforce_external_attempt_transition()
RETURNS TRIGGER AS $$
BEGIN
    IF (OLD).operation_id IS DISTINCT FROM (NEW).operation_id
       OR (OLD).rail IS DISTINCT FROM (NEW).rail
       OR (OLD).provider_reference IS DISTINCT FROM (NEW).provider_reference
       OR (OLD).request_hash IS DISTINCT FROM (NEW).request_hash
       OR (OLD).request_payload IS DISTINCT FROM (NEW).request_payload
       OR (OLD).created_at IS DISTINCT FROM (NEW).created_at THEN
        RAISE EXCEPTION 'external attempt request identity is immutable';
    END IF;

    IF (OLD).status IN ('SUCCEEDED', 'FAILED') THEN
        RAISE EXCEPTION 'external attempt terminal outcome is immutable';
    END IF;

    IF (NEW).status NOT IN ('IN_FLIGHT', 'UNKNOWN', 'SUCCEEDED', 'FAILED') THEN
        RAISE EXCEPTION 'invalid external attempt state';
    END IF;

    IF (NEW).attempts = (OLD).attempts + 1 THEN
        IF (OLD).status <> 'UNKNOWN' OR (NEW).status <> 'IN_FLIGHT'
           OR (OLD).attempt_token = (NEW).attempt_token THEN
            RAISE EXCEPTION 'only a fenced same-reference retry may advance attempts';
        END IF;
    ELSIF (NEW).attempts = (OLD).attempts THEN
        IF (OLD).attempt_token <> (NEW).attempt_token
           OR (NEW).status = 'IN_FLIGHT' THEN
            RAISE EXCEPTION 'attempt token/state changed without advancing attempt';
        END IF;
    ELSE
        RAISE EXCEPTION 'external attempt counter must stay or advance by one';
    END IF;

    IF (NEW).status IN ('SUCCEEDED', 'FAILED') AND (NEW).resolved_at IS NULL THEN
        RAISE EXCEPTION 'terminal external attempt requires resolved_at';
    END IF;
    IF (NEW).status IN ('IN_FLIGHT', 'UNKNOWN') AND (NEW).resolved_at IS NOT NULL THEN
        RAISE EXCEPTION 'non-terminal external attempt cannot have resolved_at';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER external_attempt_transition_guard
BEFORE UPDATE ON external_attempts
FOR EACH ROW
EXECUTE FUNCTION enforce_external_attempt_transition();
