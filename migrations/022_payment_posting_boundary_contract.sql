-- Contract phase for 021. Apply only after every payment_api identity has
-- payment_journal_runtime, the procedure-aware binary is fully rolled out,
-- all old writers are drained, and ledger_writer membership has been revoked
-- from the payment_api LOGIN identity. The replacement boundary is installed
-- and exercised before any privilege below is removed.

-- Close the entire old-writer window, not only the rows visible when the
-- expand migration first ran.
SELECT public.backfill_missing_payment_capture_financials();

INSERT INTO payment_effect_request_receipts (payment_effect_id, request_hash)
SELECT effect.payment_effect_id, journal.request_hash
  FROM payment_effects AS effect
  JOIN ledger_transactions AS journal
    ON journal.transaction_id=effect.ledger_transaction_id
ON CONFLICT (payment_effect_id) DO NOTHING;

CREATE OR REPLACE FUNCTION public.assert_payment_posting_contract()
RETURNS BOOL AS $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM public.payment_effects AS effect
          JOIN public.ledger_transactions AS journal
            ON journal.transaction_id=effect.ledger_transaction_id
          LEFT JOIN public.payment_effect_request_receipts AS receipt
            ON receipt.payment_effect_id=effect.payment_effect_id
         WHERE receipt.payment_effect_id IS NULL
            OR receipt.request_hash IS DISTINCT FROM journal.request_hash
    ) THEN
        RAISE EXCEPTION 'payment effect canonical request hashes are incomplete';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM public.payment_effects AS capture
          LEFT JOIN public.payment_capture_financials AS financial
            ON financial.payment_id=capture.payment_id
           AND financial.capture_effect_id=capture.payment_effect_id
           AND financial.capture_transaction_id=capture.ledger_transaction_id
           AND financial.captured_atoms=capture.amount_atoms
         WHERE capture.effect_kind='CAPTURE'
           AND (financial.capture_transaction_id IS NULL OR NOT EXISTS (
               SELECT 1 FROM public.ledger_transactions AS journal
                WHERE journal.transaction_id=capture.ledger_transaction_id
                  AND journal.effect_id=capture.payment_effect_id
                  AND journal.transaction_kind='CAPTURE'
                  AND journal.status='POSTED'))
    ) OR EXISTS (
        SELECT 1
          FROM public.payment_capture_financials AS financial
          LEFT JOIN public.payment_effects AS capture
            ON capture.payment_id=financial.payment_id
           AND capture.payment_effect_id=financial.capture_effect_id
           AND capture.ledger_transaction_id=financial.capture_transaction_id
           AND capture.amount_atoms=financial.captured_atoms
           AND capture.effect_kind='CAPTURE'
         WHERE capture.payment_effect_id IS NULL OR NOT EXISTS (
               SELECT 1 FROM public.ledger_transactions AS journal
                WHERE journal.transaction_id=financial.capture_transaction_id
                  AND journal.effect_id=financial.capture_effect_id
                  AND journal.transaction_kind='CAPTURE'
                  AND journal.status='POSTED')
    ) THEN
        RAISE EXCEPTION 'CAPTURE/payment_capture_financials 1:1 contract is not satisfied';
    END IF;
    RETURN true;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

REVOKE ALL ON FUNCTION public.assert_payment_posting_contract() FROM public;
GRANT EXECUTE ON FUNCTION public.assert_payment_posting_contract()
    TO ledger_admin;

SELECT public.assert_payment_posting_contract();

-- The assertion is a committed step before these statements. If the
-- statement-by-statement migrator crashes, either legacy privileges still
-- exist or the fully installed replacement already exists; there is no state
-- where both paths are absent.
REVOKE INSERT ON TABLE payment_effects FROM payment_runtime;
REVOKE INSERT ON TABLE payment_capture_financials FROM payment_runtime;
REVOKE EXECUTE ON FUNCTION public.apply_payment_escrow_effect(
    STRING, STRING, STRING, STRING, STRING, DECIMAL, BYTES)
    FROM cashback_repair_runtime;

-- Keep exact read/update projection rights; all immutable inserts now cross
-- record_payment_effect and CAPTURE+financial authority is one DB call.
GRANT SELECT ON TABLE payment_effects TO payment_runtime;
GRANT SELECT, UPDATE ON TABLE payment_operations, holds,
    payment_capture_financials TO payment_runtime;
GRANT EXECUTE ON FUNCTION public.record_payment_effect(
    STRING, STRING, STRING, DECIMAL, STRING, STRING, DECIMAL, BYTES)
    TO payment_runtime;
GRANT EXECUTE ON FUNCTION public.apply_cashback_repair_escrow_spend(
    STRING, STRING, STRING, STRING, STRING, DECIMAL, BYTES)
    TO cashback_repair_runtime;
