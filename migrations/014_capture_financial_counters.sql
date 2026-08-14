-- Per-capture lifecycle authority. Aggregate counters on payment_operations are
-- projections of these rows; refund and chargeback cannot borrow unused
-- principal from a different capture. expected_cashback_atoms is the immutable
-- calculated result accepted with this capture, not the authorization-time
-- maximum stored on payment_operations.cashback_rule_atoms.

ALTER TABLE payment_operations
    ADD COLUMN IF NOT EXISTS cashback_reversed_atoms DECIMAL(38,0)
        NOT NULL DEFAULT 0 CHECK (cashback_reversed_atoms >= 0);

CREATE TABLE IF NOT EXISTS payment_capture_financials (
    capture_transaction_id STRING PRIMARY KEY
        REFERENCES ledger_transactions (transaction_id),
    payment_id STRING NOT NULL REFERENCES payment_operations (payment_id),
    capture_effect_id STRING NOT NULL,
    captured_atoms DECIMAL(38,0) NOT NULL CHECK (captured_atoms > 0),
    expected_cashback_atoms DECIMAL(38,0) NOT NULL
        CHECK (expected_cashback_atoms >= 0),
    refunded_atoms DECIMAL(38,0) NOT NULL DEFAULT 0 CHECK (refunded_atoms >= 0),
    charged_back_atoms DECIMAL(38,0) NOT NULL DEFAULT 0
        CHECK (charged_back_atoms >= 0),
    cashback_reversed_atoms DECIMAL(38,0) NOT NULL DEFAULT 0
        CHECK (cashback_reversed_atoms >= 0),
    version INT8 NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (payment_id, capture_transaction_id),
    UNIQUE (payment_id, capture_effect_id),
    FOREIGN KEY (payment_id, capture_effect_id)
        REFERENCES payment_effects (payment_id, payment_effect_id),
    CHECK (refunded_atoms + charged_back_atoms <= captured_atoms)
);

CREATE INDEX IF NOT EXISTS payment_capture_financials_payment_idx
    ON payment_capture_financials (payment_id, capture_transaction_id);

-- Legacy rows predate storage of the calculated result. For the supported
-- duplicate-cashback incident the earliest cashback linked to a capture is the
-- original calculated grant and later rows are duplicates. Any historical
-- per-capture over-return makes this INSERT fail its CHECK constraint and must
-- be investigated rather than hidden by an aggregate backfill.
INSERT INTO payment_capture_financials (
    capture_transaction_id, payment_id, capture_effect_id, captured_atoms,
    expected_cashback_atoms, refunded_atoms, charged_back_atoms,
    cashback_reversed_atoms
)
SELECT capture.ledger_transaction_id, capture.payment_id,
       capture.payment_effect_id, capture.amount_atoms,
       coalesce((
           SELECT cashback.amount_atoms
           FROM payment_effects AS cashback
           JOIN ledger_transactions AS cashback_tx
             ON cashback_tx.transaction_id=cashback.ledger_transaction_id
           WHERE cashback.payment_id=capture.payment_id
             AND cashback.effect_kind='CASHBACK'
             AND cashback.original_transaction_id=capture.ledger_transaction_id
           ORDER BY cashback_tx.sequence_no, cashback.payment_effect_id
           LIMIT 1
       ), 0),
       coalesce((
           SELECT sum(refund.amount_atoms) FROM payment_effects AS refund
           WHERE refund.payment_id=capture.payment_id
             AND refund.effect_kind='REFUND'
             AND refund.original_transaction_id=capture.ledger_transaction_id
       ), 0),
       coalesce((
           SELECT sum(chargeback.amount_atoms) FROM payment_effects AS chargeback
           WHERE chargeback.payment_id=capture.payment_id
             AND chargeback.effect_kind='CHARGEBACK'
             AND chargeback.original_transaction_id=capture.ledger_transaction_id
       ), 0),
       coalesce((
           SELECT sum(reversal.amount_atoms)
           FROM payment_effects AS cashback
           JOIN payment_effects AS reversal
             ON reversal.payment_id=cashback.payment_id
            AND reversal.effect_kind='REVERSAL'
            AND reversal.original_transaction_id=cashback.ledger_transaction_id
           WHERE cashback.payment_id=capture.payment_id
             AND cashback.effect_kind='CASHBACK'
             AND cashback.original_transaction_id=capture.ledger_transaction_id
       ), 0)
FROM payment_effects AS capture
WHERE capture.effect_kind='CAPTURE'
ON CONFLICT (capture_transaction_id) DO NOTHING;

-- Preserve already-posted repair evidence while keeping the new aggregate
-- counter monotonic. Domain version advances because this is a real projection
-- change; rows without a historical reversal are untouched.
UPDATE payment_operations AS payment
SET cashback_reversed_atoms=folded.reversed,
    version=payment.version+1,
    updated_at=transaction_timestamp()
FROM (
    SELECT payment_id, sum(cashback_reversed_atoms) AS reversed
    FROM payment_capture_financials
    GROUP BY payment_id
) AS folded
WHERE payment.payment_id=folded.payment_id
  AND folded.reversed > payment.cashback_reversed_atoms;

CREATE OR REPLACE FUNCTION public.validate_payment_capture_financial_update()
RETURNS TRIGGER AS $$
BEGIN
    IF (OLD).capture_transaction_id IS DISTINCT FROM (NEW).capture_transaction_id
       OR (OLD).payment_id IS DISTINCT FROM (NEW).payment_id
       OR (OLD).capture_effect_id IS DISTINCT FROM (NEW).capture_effect_id
       OR (OLD).captured_atoms IS DISTINCT FROM (NEW).captured_atoms
       OR (OLD).expected_cashback_atoms IS DISTINCT FROM (NEW).expected_cashback_atoms
       OR (OLD).created_at IS DISTINCT FROM (NEW).created_at
       OR (NEW).refunded_atoms < (OLD).refunded_atoms
       OR (NEW).charged_back_atoms < (OLD).charged_back_atoms
       OR (NEW).cashback_reversed_atoms < (OLD).cashback_reversed_atoms
       OR (NEW).version <> (OLD).version + 1
       OR ((NEW).refunded_atoms = (OLD).refunded_atoms
           AND (NEW).charged_back_atoms = (OLD).charged_back_atoms
           AND (NEW).cashback_reversed_atoms = (OLD).cashback_reversed_atoms) THEN
        RAISE EXCEPTION 'capture identity is immutable and counters are monotonic';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER payment_capture_financial_validate_update
BEFORE UPDATE ON payment_capture_financials
FOR EACH ROW
EXECUTE FUNCTION public.validate_payment_capture_financial_update();

CREATE OR REPLACE FUNCTION public.reject_payment_capture_financial_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'capture financial authority is append-only';
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER payment_capture_financial_no_delete
BEFORE DELETE ON payment_capture_financials
FOR EACH ROW
EXECUTE FUNCTION public.reject_payment_capture_financial_delete();

-- Extend the aggregate guard with the separate gross reversal counter. Gross
-- cashback_atoms never decreases; net cashback is derived from immutable
-- effects or cashback_atoms-cashback_reversed_atoms only where both counters
-- were advanced by the same posting protocol.
CREATE OR REPLACE FUNCTION payment_state_transition_allowed(old_state STRING, new_state STRING)
RETURNS BOOL
LANGUAGE SQL
IMMUTABLE
AS $$
    SELECT old_state = new_state OR CASE old_state
      WHEN 'CREATED' THEN new_state IN ('AUTHORIZED', 'HELD', 'FAILED', 'UNKNOWN')
      WHEN 'AUTHORIZED' THEN new_state IN ('HELD', 'CAPTURED', 'REVERSED', 'FAILED', 'UNKNOWN')
      WHEN 'HELD' THEN new_state IN ('PARTIALLY_CAPTURED', 'CAPTURED', 'REVERSED', 'UNKNOWN')
      WHEN 'PARTIALLY_CAPTURED' THEN new_state IN ('CAPTURED', 'REVERSED', 'UNKNOWN')
      WHEN 'CAPTURED' THEN new_state IN ('SETTLED', 'PARTIALLY_REFUNDED', 'REFUNDED',
                                          'DISPUTED', 'CHARGED_BACK', 'UNKNOWN')
      WHEN 'SETTLED' THEN new_state IN ('PARTIALLY_REFUNDED', 'REFUNDED',
                                        'DISPUTED', 'CHARGED_BACK')
      WHEN 'PARTIALLY_REFUNDED' THEN new_state IN ('REFUNDED', 'DISPUTED', 'CHARGED_BACK')
      WHEN 'DISPUTED' THEN new_state IN ('CHARGED_BACK', 'SETTLED',
                                         'PARTIALLY_REFUNDED', 'REFUNDED')
      WHEN 'UNKNOWN' THEN new_state IN ('AUTHORIZED', 'HELD', 'CAPTURED',
                                        'SETTLED', 'FAILED', 'REVERSED')
      ELSE false
    END
$$;

CREATE OR REPLACE FUNCTION public.validate_payment_update()
RETURNS TRIGGER AS $$
BEGIN
    IF NOT payment_state_transition_allowed((OLD).state, (NEW).state) THEN
        RAISE EXCEPTION 'invalid payment state transition: % to %', (OLD).state, (NEW).state;
    END IF;
    IF (OLD).payment_id IS DISTINCT FROM (NEW).payment_id
       OR (OLD).idempotency_scope IS DISTINCT FROM (NEW).idempotency_scope
       OR (OLD).idempotency_key IS DISTINCT FROM (NEW).idempotency_key
       OR (OLD).asset_id IS DISTINCT FROM (NEW).asset_id
       OR (OLD).customer_available_account_id IS DISTINCT FROM (NEW).customer_available_account_id
       OR (OLD).customer_held_account_id IS DISTINCT FROM (NEW).customer_held_account_id
       OR (OLD).merchant_account_id IS DISTINCT FROM (NEW).merchant_account_id
       OR (OLD).authority_region IS DISTINCT FROM (NEW).authority_region
       OR (OLD).authorized_atoms IS DISTINCT FROM (NEW).authorized_atoms
       OR (NEW).captured_atoms < (OLD).captured_atoms
       OR (NEW).released_atoms < (OLD).released_atoms
       OR (NEW).refunded_atoms < (OLD).refunded_atoms
       OR (NEW).charged_back_atoms < (OLD).charged_back_atoms
       OR (NEW).fee_atoms < (OLD).fee_atoms
       OR (NEW).tax_atoms < (OLD).tax_atoms
       OR (NEW).cashback_atoms < (OLD).cashback_atoms
       OR (NEW).cashback_reversed_atoms < (OLD).cashback_reversed_atoms
       OR (OLD).cashback_rule_atoms IS DISTINCT FROM (NEW).cashback_rule_atoms
       OR (NEW).version <> (OLD).version + 1 THEN
        RAISE EXCEPTION 'payment identity/counters are immutable or monotonic';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

ALTER TABLE cashback_repair_manifests
    ADD COLUMN IF NOT EXISTS capture_transaction_id STRING NULL;

UPDATE cashback_repair_manifests AS manifest
SET capture_transaction_id=cashback.original_transaction_id
FROM payment_effects AS cashback
WHERE manifest.capture_transaction_id IS NULL
  AND cashback.payment_id=manifest.original_payment_id
  AND cashback.effect_kind='CASHBACK'
  AND cashback.ledger_transaction_id=manifest.original_transaction_id;

ALTER TABLE cashback_repair_manifests
    ALTER COLUMN capture_transaction_id SET NOT NULL;
ALTER TABLE cashback_repair_manifests
    ADD CONSTRAINT cashback_repair_capture_fk
    FOREIGN KEY (capture_transaction_id)
    REFERENCES payment_capture_financials (capture_transaction_id);

CREATE OR REPLACE FUNCTION public.enforce_cashback_manifest_update()
RETURNS TRIGGER AS $$
BEGIN
    IF (OLD).repair_id IS DISTINCT FROM (NEW).repair_id
       OR (OLD).original_payment_id IS DISTINCT FROM (NEW).original_payment_id
       OR (OLD).original_transaction_id IS DISTINCT FROM (NEW).original_transaction_id
       OR (OLD).capture_transaction_id IS DISTINCT FROM (NEW).capture_transaction_id
       OR (OLD).posting_rule_version IS DISTINCT FROM (NEW).posting_rule_version
       OR (OLD).asset_id IS DISTINCT FROM (NEW).asset_id
       OR (OLD).expected_atoms IS DISTINCT FROM (NEW).expected_atoms
       OR (OLD).actual_atoms IS DISTINCT FROM (NEW).actual_atoms
       OR (OLD).excess_atoms IS DISTINCT FROM (NEW).excess_atoms
       OR (OLD).correction_effect_id IS DISTINCT FROM (NEW).correction_effect_id
       OR (OLD).correction_transaction_id IS DISTINCT FROM (NEW).correction_transaction_id
       OR (OLD).created_at IS DISTINCT FROM (NEW).created_at
       OR (OLD).status <> 'PLANNED'
       OR (NEW).status NOT IN ('POSTED', 'WAIVED') THEN
        RAISE EXCEPTION 'cashback repair manifest facts are immutable and terminal';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

REVOKE ALL ON TABLE payment_capture_financials FROM public;
GRANT ALL ON TABLE payment_capture_financials TO ledger_admin;
GRANT SELECT, INSERT, UPDATE ON TABLE payment_capture_financials TO ledger_writer;
GRANT SELECT, UPDATE ON TABLE payment_capture_financials TO cashback_repair_runtime;
GRANT SELECT ON TABLE payment_capture_financials
    TO ledger_reader, ledger_auditor, reconciliation_runtime;

REVOKE EXECUTE ON FUNCTION public.validate_payment_capture_financial_update() FROM public;
REVOKE EXECUTE ON FUNCTION public.reject_payment_capture_financial_delete() FROM public;
REVOKE EXECUTE ON FUNCTION public.validate_payment_update() FROM public;
REVOKE EXECUTE ON FUNCTION public.enforce_cashback_manifest_update() FROM public;
