-- Expand phase for the payment-specific posting boundary. Production applies
-- this migration first, deploys the procedure-aware binary, and drains every
-- legacy payment writer. Migration 022 repeats the catch-up and removes the
-- generic journal/effect capabilities. Existing grants deliberately remain
-- during this phase so an old pod is never broken mid-rollout.

CREATE ROLE IF NOT EXISTS payment_journal_runtime NOLOGIN;
GRANT USAGE ON SCHEMA public TO payment_journal_runtime;

-- The runtime may construct immutable DRAFT rows, but it cannot turn them into
-- balance authority with the generic finalizer. A DRAFT is not included in any
-- balance/reconciliation fold and can be quarantined if template validation
-- fails.
GRANT SELECT ON TABLE assets, books, accounts, account_balances,
    ledger_transactions, ledger_lines, payment_operations, holds,
    payment_capture_financials, payment_effects,
    payment_account_capabilities, payment_account_capability_revocations
    TO payment_journal_runtime;
GRANT INSERT ON TABLE ledger_transactions, ledger_lines
    TO payment_journal_runtime;

CREATE TABLE IF NOT EXISTS payment_effect_request_receipts (
    payment_effect_id STRING PRIMARY KEY
        REFERENCES payment_effects (payment_effect_id),
    request_hash BYTES NOT NULL CHECK (length(request_hash)=32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp()
);

CREATE TRIGGER payment_effect_request_receipt_no_update
BEFORE UPDATE ON payment_effect_request_receipts
FOR EACH ROW EXECUTE FUNCTION public.reject_row_mutation();

CREATE TRIGGER payment_effect_request_receipt_no_delete
BEFORE DELETE ON payment_effect_request_receipts
FOR EACH ROW EXECUTE FUNCTION public.reject_row_mutation();

REVOKE ALL ON TABLE payment_effect_request_receipts FROM public;
GRANT ALL ON TABLE payment_effect_request_receipts TO ledger_admin;
GRANT SELECT ON TABLE payment_effect_request_receipts
    TO ledger_reader, ledger_auditor, reconciliation_runtime;

ALTER TABLE ledger_transactions
    ADD COLUMN IF NOT EXISTS payment_template_verified BOOL NOT NULL DEFAULT false;

CREATE OR REPLACE FUNCTION public.reject_inserted_payment_template_marker()
RETURNS TRIGGER AS $$
BEGIN
    IF (NEW).payment_template_verified THEN
        RAISE EXCEPTION 'payment template marker is finalizer-owned';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER ledger_transaction_reject_inserted_payment_template_marker
BEFORE INSERT ON ledger_transactions
FOR EACH ROW
EXECUTE FUNCTION public.reject_inserted_payment_template_marker();

REVOKE ALL ON FUNCTION public.reject_inserted_payment_template_marker()
    FROM public;

-- Cockroach authenticates the workload, not the end-user. The immutable
-- payment intent therefore binds the authenticated API scope to all three
-- account capabilities before any journal can be finalized. Root is the
-- migration/test TCB and is deliberately outside the workload policy.
CREATE OR REPLACE FUNCTION public.validate_payment_intent_insert()
RETURNS TRIGGER AS $$
BEGIN
    IF session_user<>'root' AND (
       NOT EXISTS (
           SELECT 1 FROM public.accounts AS account
            WHERE account.account_id=(NEW).customer_available_account_id
              AND account.book_id=(
                  SELECT capability.book_id
                    FROM public.payment_account_capabilities AS capability
                   WHERE (NEW).idempotency_scope=
                         'principal/'||capability.principal_id||'/hold'
                     AND capability.account_id=(NEW).customer_available_account_id
                     AND capability.permission='AUTHORIZE_PAYER_AVAILABLE'
                     AND NOT EXISTS (
                         SELECT 1 FROM public.payment_account_capability_revocations AS revocation
                          WHERE revocation.capability_id=capability.capability_id)
                   LIMIT 1)
              AND account.asset_id=(NEW).asset_id)
       OR NOT EXISTS (
           SELECT 1 FROM public.payment_account_capabilities AS available
           JOIN public.payment_account_capabilities AS held
             ON held.principal_id=available.principal_id
            AND held.book_id=available.book_id
           JOIN public.payment_account_capabilities AS merchant
             ON merchant.principal_id=available.principal_id
            AND merchant.book_id=available.book_id
          WHERE (NEW).idempotency_scope='principal/'||available.principal_id||'/hold'
            AND available.account_id=(NEW).customer_available_account_id
            AND available.permission='AUTHORIZE_PAYER_AVAILABLE'
            AND held.account_id=(NEW).customer_held_account_id
            AND held.permission='AUTHORIZE_PAYER_HELD'
            AND merchant.account_id=(NEW).merchant_account_id
            AND merchant.permission='AUTHORIZE_MERCHANT'
            AND NOT EXISTS (SELECT 1 FROM public.payment_account_capability_revocations AS r
                             WHERE r.capability_id=available.capability_id)
            AND NOT EXISTS (SELECT 1 FROM public.payment_account_capability_revocations AS r
                             WHERE r.capability_id=held.capability_id)
            AND NOT EXISTS (SELECT 1 FROM public.payment_account_capability_revocations AS r
                             WHERE r.capability_id=merchant.capability_id))
    ) THEN
        RAISE EXCEPTION 'payment intent is not bound to exact account capabilities';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER payment_operation_validate_intent_insert
BEFORE INSERT ON payment_operations
FOR EACH ROW EXECUTE FUNCTION public.validate_payment_intent_insert();

REVOKE ALL ON FUNCTION public.validate_payment_intent_insert() FROM public;

-- The journal request hash is the already-canonical API command hash. It is
-- copied into the immutable payment fact so retries compare the whole effect,
-- not only a user-selected effect ID.
INSERT INTO payment_effect_request_receipts (payment_effect_id, request_hash)
SELECT effect.payment_effect_id, journal.request_hash
  FROM payment_effects AS effect
  JOIN ledger_transactions AS journal
    ON journal.transaction_id=effect.ledger_transaction_id
ON CONFLICT (payment_effect_id) DO NOTHING;

CREATE OR REPLACE FUNCTION public.finalize_payment_ledger_transaction(
    target_transaction_id STRING
)
RETURNS STRING AS $$
DECLARE
    target_kind STRING;
    target_book_id STRING;
    target_payment_id STRING;
    target_reference_id STRING;
    target_asset_id STRING;
    target_available_account_id STRING;
    target_held_account_id STRING;
    target_merchant_account_id STRING;
    target_scope STRING;
    line_count INT8;
    matching_count INT8;
BEGIN
    target_kind := NULL;
    SELECT transaction.transaction_kind, transaction.book_id,
           transaction.reference_transaction_id,
           transaction.metadata->>'payment_id'
      INTO target_kind, target_book_id, target_reference_id, target_payment_id
      FROM public.ledger_transactions AS transaction
     WHERE transaction.transaction_id=target_transaction_id
       AND transaction.status='DRAFT';
    IF target_kind IS NULL OR target_payment_id IS NULL
       OR pg_catalog.length(target_payment_id)=0
       OR target_kind NOT IN ('HOLD','CAPTURE','CASHBACK','RELEASE','REVERSAL',
                              'REFUND','CHARGEBACK') THEN
        RAISE EXCEPTION 'invalid payment journal draft';
    END IF;

    SELECT pg_catalog.count(*), pg_catalog.min(line.asset_id)
      INTO line_count, target_asset_id
      FROM public.ledger_lines AS line
     WHERE line.transaction_id=target_transaction_id;
    IF line_count < 2 OR EXISTS (
        SELECT 1 FROM public.ledger_lines AS line
         JOIN public.accounts AS account ON account.account_id=line.account_id
         WHERE line.transaction_id=target_transaction_id
           AND (line.asset_id IS DISTINCT FROM target_asset_id
                OR account.asset_id IS DISTINCT FROM target_asset_id
                OR account.book_id IS DISTINCT FROM target_book_id)
    ) THEN
        RAISE EXCEPTION 'payment journal crosses an asset or book boundary';
    END IF;

    SELECT payment.asset_id, payment.customer_available_account_id,
           payment.customer_held_account_id, payment.merchant_account_id,
           payment.idempotency_scope
      INTO target_asset_id, target_available_account_id,
           target_held_account_id, target_merchant_account_id, target_scope
      FROM public.payment_operations AS payment
     WHERE payment.payment_id=target_payment_id;
    IF target_asset_id IS NULL THEN
        RAISE EXCEPTION 'payment journal has no payment authority';
    END IF;

    IF target_kind='HOLD' THEN
        IF target_reference_id IS NOT NULL OR line_count<>2
           OR (SELECT pg_catalog.count(*) FROM public.ledger_lines AS line
                WHERE line.transaction_id=target_transaction_id
                  AND line.side='DEBIT'
                  AND line.account_id=target_available_account_id
                  AND line.asset_id=target_asset_id
                  AND line.amount_atoms=(SELECT payment.authorized_atoms
                                           FROM public.payment_operations AS payment
                                          WHERE payment.payment_id=target_payment_id))<>1
           OR (SELECT pg_catalog.count(*) FROM public.ledger_lines AS line
                WHERE line.transaction_id=target_transaction_id
                  AND line.side='CREDIT'
                  AND line.account_id=target_held_account_id
                  AND line.asset_id=target_asset_id
                  AND line.amount_atoms=(SELECT payment.authorized_atoms
                                           FROM public.payment_operations AS payment
                                          WHERE payment.payment_id=target_payment_id))<>1 THEN
            RAISE EXCEPTION 'invalid HOLD journal template';
        END IF;
        UPDATE public.ledger_transactions
           SET payment_template_verified=true
         WHERE transaction_id=target_transaction_id AND status='DRAFT';
        RETURN public.finalize_ledger_transaction(target_transaction_id);
    END IF;

    IF target_kind='CAPTURE' THEN
        IF target_reference_id IS DISTINCT FROM (
               SELECT hold.authorization_transaction_id FROM public.holds AS hold
                WHERE hold.payment_id=target_payment_id)
           OR (SELECT pg_catalog.count(*) FROM public.ledger_lines AS line
                WHERE line.transaction_id=target_transaction_id
                  AND line.side='DEBIT' AND line.account_id=target_held_account_id
                  AND line.asset_id=target_asset_id)<>1
           OR (SELECT pg_catalog.count(*) FROM public.ledger_lines AS line
                WHERE line.transaction_id=target_transaction_id
                  AND line.side='DEBIT')<>1
           OR EXISTS (
               SELECT 1 FROM public.ledger_lines AS line
                WHERE line.transaction_id=target_transaction_id
                  AND line.side='CREDIT'
                  AND line.account_id<>target_merchant_account_id
                  AND (NOT EXISTS (
                           SELECT 1 FROM public.accounts AS account
                            WHERE account.account_id=line.account_id
                              AND account.account_type IN ('FEE_REVENUE','TAX_PAYABLE'))
                       OR (session_user<>'root' AND NOT EXISTS (
                           SELECT 1
                             FROM public.accounts AS account
                             JOIN public.payment_account_capabilities AS capability
                               ON capability.account_id=account.account_id
                            WHERE target_scope='principal/'||capability.principal_id||'/hold'
                              AND capability.book_id=target_book_id
                              AND capability.account_id=line.account_id
                              AND capability.permission=CASE account.account_type
                                    WHEN 'FEE_REVENUE' THEN 'CAPTURE_FEE'
                                    WHEN 'TAX_PAYABLE' THEN 'CAPTURE_TAX'
                                    ELSE '__INVALID__' END
                              AND NOT EXISTS (
                                  SELECT 1
                                    FROM public.payment_account_capability_revocations AS revocation
                                   WHERE revocation.capability_id=capability.capability_id))))) THEN
            RAISE EXCEPTION 'invalid CAPTURE journal template';
        END IF;
    ELSIF target_kind='CASHBACK' THEN
        IF line_count<>2 OR NOT EXISTS (
               SELECT 1 FROM public.payment_capture_financials AS capture
                WHERE capture.payment_id=target_payment_id
                  AND capture.capture_transaction_id=target_reference_id)
           OR (SELECT pg_catalog.count(*) FROM public.ledger_lines AS line
                WHERE line.transaction_id=target_transaction_id
                  AND line.side='CREDIT' AND line.account_id=target_available_account_id
                  AND line.asset_id=target_asset_id)<>1
           OR (SELECT pg_catalog.count(*) FROM public.ledger_lines AS line
                WHERE line.transaction_id=target_transaction_id
                  AND line.side='DEBIT'
                  AND (EXISTS (
                      SELECT 1 FROM public.accounts AS account
                       WHERE account.account_id=line.account_id
                         AND account.account_type='CASHBACK_EXPENSE')
                       AND (session_user='root' OR EXISTS (
                      SELECT 1
                        FROM public.payment_account_capabilities AS capability
                       WHERE target_scope='principal/'||capability.principal_id||'/hold'
                         AND capability.book_id=target_book_id
                         AND capability.account_id=line.account_id
                         AND capability.permission='CAPTURE_CASHBACK_EXPENSE'
                         AND NOT EXISTS (
                             SELECT 1
                               FROM public.payment_account_capability_revocations AS revocation
                              WHERE revocation.capability_id=capability.capability_id)))))<>1 THEN
            RAISE EXCEPTION 'invalid CASHBACK journal template';
        END IF;
    ELSIF target_kind IN ('RELEASE','REVERSAL') THEN
        IF line_count<>2
           OR target_reference_id IS DISTINCT FROM (
               SELECT hold.authorization_transaction_id FROM public.holds AS hold
                WHERE hold.payment_id=target_payment_id)
           OR (SELECT pg_catalog.count(*) FROM public.ledger_lines AS line
                WHERE line.transaction_id=target_transaction_id AND line.side='DEBIT'
                  AND line.account_id=target_held_account_id
                  AND line.asset_id=target_asset_id)<>1
           OR (SELECT pg_catalog.count(*) FROM public.ledger_lines AS line
                WHERE line.transaction_id=target_transaction_id AND line.side='CREDIT'
                  AND line.account_id=target_available_account_id
                  AND line.asset_id=target_asset_id)<>1 THEN
            RAISE EXCEPTION 'invalid hold RETURN journal template';
        END IF;
    ELSIF target_kind IN ('REFUND','CHARGEBACK') THEN
        IF line_count<>2 OR NOT EXISTS (
               SELECT 1 FROM public.payment_capture_financials AS capture
                WHERE capture.payment_id=target_payment_id
                  AND capture.capture_transaction_id=target_reference_id)
           OR (SELECT pg_catalog.count(*) FROM public.ledger_lines AS line
                WHERE line.transaction_id=target_transaction_id AND line.side='CREDIT'
                  AND line.account_id=target_available_account_id
                  AND line.asset_id=target_asset_id)<>1 THEN
            RAISE EXCEPTION 'invalid capture RETURN journal template';
        END IF;
        matching_count := 0;
        SELECT pg_catalog.count(*) INTO matching_count
          FROM public.ledger_lines AS line
         WHERE line.transaction_id=target_transaction_id AND line.side='DEBIT'
           AND (line.account_id=target_merchant_account_id OR EXISTS (
               SELECT 1 FROM public.payment_account_capabilities AS capability
                WHERE target_scope='principal/'||capability.principal_id||'/hold'
                  AND capability.book_id=target_book_id
                  AND capability.account_id=line.account_id
                  AND capability.permission=CASE target_kind
                        WHEN 'REFUND' THEN 'REFUND_MERCHANT_DEBIT'
                        ELSE 'CHARGEBACK_MERCHANT_RESERVE' END
                  AND NOT EXISTS (
                      SELECT 1 FROM public.payment_account_capability_revocations AS revocation
                       WHERE revocation.capability_id=capability.capability_id)));
        IF matching_count<>1 THEN
            RAISE EXCEPTION 'capture RETURN debit account is not authorized';
        END IF;
    END IF;

    UPDATE public.ledger_transactions
       SET payment_template_verified=true
     WHERE transaction_id=target_transaction_id AND status='DRAFT';
    RETURN public.finalize_ledger_transaction(target_transaction_id);
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

REVOKE ALL ON FUNCTION public.finalize_payment_ledger_transaction(STRING)
    FROM public;

-- This is the only final-state payment-effect writer. It compares the exact
-- canonical API hash with the journal, validates the causal/lifecycle fold,
-- and creates CAPTURE plus its immutable financial authority in one call.
CREATE OR REPLACE FUNCTION public.record_payment_effect(
    target_effect_id STRING,
    target_payment_id STRING,
    target_effect_kind STRING,
    target_amount DECIMAL,
    target_ledger_transaction_id STRING,
    target_original_transaction_id STRING,
    target_expected_cashback DECIMAL,
    supplied_request_hash BYTES
)
RETURNS BOOL AS $$
DECLARE
    stored_kind STRING;
    stored_payment_id STRING;
    stored_amount DECIMAL;
    stored_transaction_id STRING;
    stored_original_id STRING;
    stored_request_hash BYTES;
    stored_expected_cashback DECIMAL;
    linked_count INT8;
    finalized_transaction_id STRING;
BEGIN
    IF target_effect_id IS NULL OR pg_catalog.length(target_effect_id) NOT BETWEEN 1 AND 512
       OR target_payment_id IS NULL OR pg_catalog.length(target_payment_id)=0
       OR target_effect_kind NOT IN ('HOLD','CAPTURE','RELEASE','REVERSAL',
                                     'REFUND','CHARGEBACK','FEE','TAX','CASHBACK')
       OR target_amount IS NULL OR target_amount<=0
       OR target_amount<>pg_catalog.trunc(target_amount)
       OR supplied_request_hash IS NULL
       OR pg_catalog.length(supplied_request_hash)<>32
       OR (target_effect_kind='CAPTURE' AND
           (target_expected_cashback IS NULL OR target_expected_cashback<0
            OR target_expected_cashback<>pg_catalog.trunc(target_expected_cashback)))
       OR (target_effect_kind<>'CAPTURE' AND target_expected_cashback IS NOT NULL) THEN
        RAISE EXCEPTION 'invalid payment effect request';
    END IF;

    stored_kind := NULL;
    SELECT effect.payment_id, effect.effect_kind, effect.amount_atoms,
           effect.ledger_transaction_id, effect.original_transaction_id,
           receipt.request_hash,
           capture.expected_cashback_atoms
      INTO stored_payment_id, stored_kind, stored_amount,
           stored_transaction_id, stored_original_id, stored_request_hash,
           stored_expected_cashback
      FROM public.payment_effects AS effect
      LEFT JOIN public.payment_effect_request_receipts AS receipt
        ON receipt.payment_effect_id=effect.payment_effect_id
      LEFT JOIN public.payment_capture_financials AS capture
        ON capture.payment_id=effect.payment_id
       AND capture.capture_effect_id=effect.payment_effect_id
     WHERE effect.payment_effect_id=target_effect_id;
    IF stored_kind IS NOT NULL THEN
        IF stored_payment_id IS DISTINCT FROM target_payment_id
           OR stored_kind IS DISTINCT FROM target_effect_kind
           OR stored_amount IS DISTINCT FROM target_amount
           OR stored_transaction_id IS DISTINCT FROM target_ledger_transaction_id
           OR stored_original_id IS DISTINCT FROM target_original_transaction_id
           OR stored_request_hash IS DISTINCT FROM supplied_request_hash
           OR stored_expected_cashback IS DISTINCT FROM target_expected_cashback THEN
            RAISE EXCEPTION 'payment effect conflict';
        END IF;
        RETURN false;
    END IF;

    -- Primary payment facts own their journal transition. Secondary FEE/TAX
    -- facts share the already-finalized CAPTURE journal. No workload receives
    -- direct EXECUTE on the template finalizer, so POSTED+effect is atomic.
    IF target_effect_kind NOT IN ('FEE','TAX') THEN
        SELECT public.finalize_payment_ledger_transaction(
                   target_ledger_transaction_id)
          INTO finalized_transaction_id;
        IF finalized_transaction_id IS DISTINCT FROM target_ledger_transaction_id THEN
            RAISE EXCEPTION 'payment journal template did not finalize one draft';
        END IF;
    END IF;

    SELECT pg_catalog.count(*) INTO linked_count
      FROM public.ledger_transactions AS journal
     WHERE journal.transaction_id=target_ledger_transaction_id
       AND journal.status='POSTED'
       AND journal.payment_template_verified
       AND journal.request_hash=supplied_request_hash
       AND journal.metadata->>'payment_id'=target_payment_id
       AND ((target_effect_kind IN ('FEE','TAX')
             AND journal.transaction_kind='CAPTURE'
             AND journal.transaction_id=target_original_transaction_id
             AND EXISTS (
                 SELECT 1 FROM public.payment_effects AS capture
                  WHERE capture.payment_id=target_payment_id
                    AND capture.effect_kind='CAPTURE'
                    AND capture.payment_effect_id=journal.effect_id
                    AND capture.ledger_transaction_id=journal.transaction_id))
         OR (target_effect_kind NOT IN ('FEE','TAX')
             AND journal.transaction_kind=target_effect_kind
             AND journal.effect_id=target_effect_id
             AND journal.reference_transaction_id
                 IS NOT DISTINCT FROM target_original_transaction_id));
    IF linked_count<>1 THEN
        RAISE EXCEPTION 'payment effect is not linked to one exact posted journal';
    END IF;

    IF target_effect_kind='HOLD' THEN
        SELECT pg_catalog.count(*) INTO linked_count
          FROM public.payment_operations AS payment
          JOIN public.holds AS hold ON hold.payment_id=payment.payment_id
         WHERE payment.payment_id=target_payment_id
           AND payment.authorized_atoms=target_amount
           AND payment.captured_atoms=0 AND payment.released_atoms=0
           AND hold.authorization_transaction_id=target_ledger_transaction_id
           AND hold.authorization_atoms=target_amount
           AND (SELECT pg_catalog.count(*) FROM public.ledger_lines AS line
                 WHERE line.transaction_id=target_ledger_transaction_id
                   AND line.account_id=payment.customer_available_account_id
                   AND line.asset_id=payment.asset_id AND line.side='DEBIT'
                   AND line.amount_atoms=target_amount)=1;
    ELSIF target_effect_kind='CAPTURE' THEN
        SELECT pg_catalog.count(*) INTO linked_count
          FROM public.payment_operations AS payment
          JOIN public.holds AS hold ON hold.payment_id=payment.payment_id
         WHERE payment.payment_id=target_payment_id
           AND hold.authorization_transaction_id=target_original_transaction_id
           AND payment.captured_atoms=(
               SELECT coalesce(pg_catalog.sum(effect.amount_atoms),0)+target_amount
                 FROM public.payment_effects AS effect
                WHERE effect.payment_id=target_payment_id
                  AND effect.effect_kind='CAPTURE')
           AND hold.captured_atoms=payment.captured_atoms
           AND payment.cashback_atoms=(
               SELECT coalesce(pg_catalog.sum(capture.expected_cashback_atoms),0)
                      +target_expected_cashback
                 FROM public.payment_capture_financials AS capture
                WHERE capture.payment_id=target_payment_id)
           AND (SELECT pg_catalog.count(*) FROM public.ledger_lines AS line
                 WHERE line.transaction_id=target_ledger_transaction_id
                   AND line.account_id=payment.customer_held_account_id
                   AND line.asset_id=payment.asset_id AND line.side='DEBIT'
                   AND line.amount_atoms=target_amount)=1
           AND (SELECT coalesce(pg_catalog.sum(line.amount_atoms),0)
                  FROM public.ledger_lines AS line
                 WHERE line.transaction_id=target_ledger_transaction_id
                   AND line.account_id=payment.merchant_account_id
                   AND line.asset_id=payment.asset_id AND line.side='CREDIT')
               = target_amount
                 -(payment.fee_atoms-(SELECT coalesce(pg_catalog.sum(effect.amount_atoms),0)
                                        FROM public.payment_effects AS effect
                                       WHERE effect.payment_id=target_payment_id
                                         AND effect.effect_kind='FEE'))
                 -(payment.tax_atoms-(SELECT coalesce(pg_catalog.sum(effect.amount_atoms),0)
                                        FROM public.payment_effects AS effect
                                       WHERE effect.payment_id=target_payment_id
                                         AND effect.effect_kind='TAX'))
           AND (SELECT coalesce(pg_catalog.sum(line.amount_atoms),0)
                  FROM public.ledger_lines AS line
                  JOIN public.accounts AS account ON account.account_id=line.account_id
                 WHERE line.transaction_id=target_ledger_transaction_id
                   AND line.asset_id=payment.asset_id AND line.side='CREDIT'
                   AND account.account_type='FEE_REVENUE')
               = payment.fee_atoms-(SELECT coalesce(pg_catalog.sum(effect.amount_atoms),0)
                                      FROM public.payment_effects AS effect
                                     WHERE effect.payment_id=target_payment_id
                                       AND effect.effect_kind='FEE')
           AND (SELECT coalesce(pg_catalog.sum(line.amount_atoms),0)
                  FROM public.ledger_lines AS line
                  JOIN public.accounts AS account ON account.account_id=line.account_id
                 WHERE line.transaction_id=target_ledger_transaction_id
                   AND line.asset_id=payment.asset_id AND line.side='CREDIT'
                   AND account.account_type='TAX_PAYABLE')
               = payment.tax_atoms-(SELECT coalesce(pg_catalog.sum(effect.amount_atoms),0)
                                      FROM public.payment_effects AS effect
                                     WHERE effect.payment_id=target_payment_id
                                       AND effect.effect_kind='TAX');
    ELSIF target_effect_kind IN ('FEE','TAX') THEN
        SELECT pg_catalog.count(*) INTO linked_count
          FROM public.payment_operations AS payment
         WHERE payment.payment_id=target_payment_id
           AND CASE target_effect_kind
                 WHEN 'FEE' THEN payment.fee_atoms
                 ELSE payment.tax_atoms END=(
               SELECT coalesce(pg_catalog.sum(effect.amount_atoms),0)+target_amount
                 FROM public.payment_effects AS effect
                WHERE effect.payment_id=target_payment_id
                  AND effect.effect_kind=target_effect_kind)
           AND (SELECT coalesce(pg_catalog.sum(line.amount_atoms),0)
                  FROM public.ledger_lines AS line
                  JOIN public.accounts AS account ON account.account_id=line.account_id
                 WHERE line.transaction_id=target_ledger_transaction_id
                   AND line.side='CREDIT' AND line.asset_id=payment.asset_id
                   AND account.account_type=CASE target_effect_kind
                         WHEN 'FEE' THEN 'FEE_REVENUE'
                         ELSE 'TAX_PAYABLE' END)=target_amount;
    ELSIF target_effect_kind='CASHBACK' THEN
        SELECT pg_catalog.count(*) INTO linked_count
          FROM public.payment_operations AS payment
          JOIN public.payment_capture_financials AS capture
            ON capture.payment_id=payment.payment_id
           AND capture.capture_transaction_id=target_original_transaction_id
         WHERE payment.payment_id=target_payment_id
           AND capture.expected_cashback_atoms=target_amount
           AND payment.cashback_atoms=(
               SELECT coalesce(pg_catalog.sum(financial.expected_cashback_atoms),0)
                 FROM public.payment_capture_financials AS financial
                WHERE financial.payment_id=target_payment_id)
           AND NOT EXISTS (
               SELECT 1 FROM public.payment_effects AS effect
                WHERE effect.payment_id=target_payment_id
                  AND effect.effect_kind='CASHBACK'
                  AND effect.original_transaction_id=target_original_transaction_id)
           AND (SELECT coalesce(pg_catalog.sum(line.amount_atoms),0)
                  FROM public.ledger_lines AS line
                 WHERE line.transaction_id=target_ledger_transaction_id
                   AND line.account_id=payment.customer_available_account_id
                   AND line.asset_id=payment.asset_id
                   AND line.side='CREDIT')=target_amount
           AND (SELECT coalesce(pg_catalog.sum(line.amount_atoms),0)
                  FROM public.ledger_lines AS line
                 WHERE line.transaction_id=target_ledger_transaction_id
                   AND line.asset_id=payment.asset_id
                   AND line.side='DEBIT')=target_amount;
    ELSIF target_effect_kind IN ('RELEASE','REVERSAL') THEN
        SELECT pg_catalog.count(*) INTO linked_count
          FROM public.payment_operations AS payment
          JOIN public.holds AS hold ON hold.payment_id=payment.payment_id
         WHERE payment.payment_id=target_payment_id
           AND hold.authorization_transaction_id=target_original_transaction_id
           AND payment.released_atoms=(
               SELECT coalesce(pg_catalog.sum(effect.amount_atoms),0)+target_amount
                 FROM public.payment_effects AS effect
                WHERE effect.payment_id=target_payment_id
                  AND (effect.effect_kind='RELEASE'
                       OR (effect.effect_kind='REVERSAL'
                           AND effect.original_transaction_id=hold.authorization_transaction_id)))
           AND hold.released_atoms=payment.released_atoms
           AND (SELECT coalesce(pg_catalog.sum(line.amount_atoms),0)
                  FROM public.ledger_lines AS line
                 WHERE line.transaction_id=target_ledger_transaction_id
                   AND line.account_id=payment.customer_held_account_id
                   AND line.asset_id=payment.asset_id
                   AND line.side='DEBIT')=target_amount
           AND (SELECT coalesce(pg_catalog.sum(line.amount_atoms),0)
                  FROM public.ledger_lines AS line
                 WHERE line.transaction_id=target_ledger_transaction_id
                   AND line.account_id=payment.customer_available_account_id
                   AND line.asset_id=payment.asset_id
                   AND line.side='CREDIT')=target_amount;
    ELSIF target_effect_kind IN ('REFUND','CHARGEBACK') THEN
        SELECT pg_catalog.count(*) INTO linked_count
          FROM public.payment_operations AS payment
          JOIN public.payment_capture_financials AS capture
            ON capture.payment_id=payment.payment_id
           AND capture.capture_transaction_id=target_original_transaction_id
         WHERE payment.payment_id=target_payment_id
           AND CASE target_effect_kind
                 WHEN 'REFUND' THEN capture.refunded_atoms
                 ELSE capture.charged_back_atoms END=(
               SELECT coalesce(pg_catalog.sum(effect.amount_atoms),0)+target_amount
                 FROM public.payment_effects AS effect
                WHERE effect.payment_id=target_payment_id
                  AND effect.effect_kind=target_effect_kind
                  AND effect.original_transaction_id=target_original_transaction_id)
           AND payment.refunded_atoms=(
               SELECT coalesce(pg_catalog.sum(financial.refunded_atoms),0)
                 FROM public.payment_capture_financials AS financial
                WHERE financial.payment_id=target_payment_id)
           AND payment.charged_back_atoms=(
               SELECT coalesce(pg_catalog.sum(financial.charged_back_atoms),0)
                 FROM public.payment_capture_financials AS financial
                WHERE financial.payment_id=target_payment_id)
           AND (SELECT coalesce(pg_catalog.sum(line.amount_atoms),0)
                  FROM public.ledger_lines AS line
                 WHERE line.transaction_id=target_ledger_transaction_id
                   AND line.account_id=payment.customer_available_account_id
                   AND line.asset_id=payment.asset_id
                   AND line.side='CREDIT')=target_amount
           AND (SELECT coalesce(pg_catalog.sum(line.amount_atoms),0)
                  FROM public.ledger_lines AS line
                 WHERE line.transaction_id=target_ledger_transaction_id
                   AND line.asset_id=payment.asset_id
                   AND line.side='DEBIT')=target_amount;
    END IF;
    IF linked_count<>1 THEN
        RAISE EXCEPTION 'payment effect does not match the exact lifecycle projection';
    END IF;

    INSERT INTO public.payment_effects (
        payment_effect_id, payment_id, effect_kind, amount_atoms,
        ledger_transaction_id, original_transaction_id
    ) VALUES (target_effect_id, target_payment_id, target_effect_kind,
              target_amount, target_ledger_transaction_id,
              target_original_transaction_id);

    INSERT INTO public.payment_effect_request_receipts (
        payment_effect_id, request_hash
    ) VALUES (target_effect_id, supplied_request_hash);

    IF target_effect_kind='CAPTURE' THEN
        INSERT INTO public.payment_capture_financials (
            capture_transaction_id, payment_id, capture_effect_id,
            captured_atoms, expected_cashback_atoms
        ) VALUES (target_ledger_transaction_id, target_payment_id,
                  target_effect_id, target_amount, target_expected_cashback);
    END IF;
    RETURN true;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

REVOKE ALL ON FUNCTION public.record_payment_effect(
    STRING, STRING, STRING, DECIMAL, STRING, STRING, DECIMAL, BYTES)
    FROM public;
GRANT EXECUTE ON FUNCTION public.record_payment_effect(
    STRING, STRING, STRING, DECIMAL, STRING, STRING, DECIMAL, BYTES)
    TO payment_runtime;

-- Cashback repair is a value-reducing correction, never a RETURN capability.
-- Bind SPEND to the reviewed immutable manifest and exact posted reversal so a
-- compromised repair credential cannot reuse the generic escrow transition to
-- mint total/regional authority.
CREATE OR REPLACE FUNCTION public.apply_cashback_repair_escrow_spend(
    target_repair_id STRING,
    target_effect_id STRING,
    target_account_id STRING,
    target_asset_id STRING,
    target_region STRING,
    target_amount DECIMAL,
    supplied_request_hash BYTES
)
RETURNS BOOL AS $$
DECLARE
    linked_count INT8;
    applied BOOL;
BEGIN
    SELECT pg_catalog.count(*) INTO linked_count
      FROM public.cashback_repair_manifests AS manifest
      JOIN public.payment_operations AS payment
        ON payment.payment_id=manifest.original_payment_id
      JOIN public.payment_effects AS effect
        ON effect.payment_id=manifest.original_payment_id
       AND effect.payment_effect_id=manifest.correction_effect_id
       AND effect.effect_kind='REVERSAL'
       AND effect.amount_atoms=manifest.excess_atoms
       AND effect.original_transaction_id=manifest.original_transaction_id
      JOIN public.ledger_transactions AS journal
        ON journal.transaction_id=manifest.correction_transaction_id
       AND journal.transaction_id=effect.ledger_transaction_id
       AND journal.effect_id=effect.payment_effect_id
       AND journal.transaction_kind='CASHBACK_REVERSAL'
       AND journal.status='POSTED'
     WHERE manifest.repair_id=target_repair_id
       AND manifest.status='PLANNED'
       AND manifest.correction_effect_id=target_effect_id
       AND manifest.asset_id=target_asset_id
       AND manifest.excess_atoms=target_amount
       AND payment.customer_available_account_id=target_account_id
       AND payment.asset_id=target_asset_id
       AND payment.authority_region=target_region;
    IF linked_count<>1 THEN
        RAISE EXCEPTION 'cashback repair escrow spend is not manifest-bound';
    END IF;

    SELECT public.apply_payment_escrow_effect(
               target_effect_id, 'SPEND', target_account_id, target_asset_id,
               target_region, target_amount, supplied_request_hash)
      INTO applied;
    RETURN applied;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

REVOKE ALL ON FUNCTION public.apply_cashback_repair_escrow_spend(
    STRING, STRING, STRING, STRING, STRING, DECIMAL, BYTES) FROM public;
GRANT EXECUTE ON FUNCTION public.apply_cashback_repair_escrow_spend(
    STRING, STRING, STRING, STRING, STRING, DECIMAL, BYTES)
    TO cashback_repair_runtime;

-- A strict catch-up is safe during expand but not sufficient as the contract:
-- an old pod may commit another CAPTURE immediately afterwards. Ambiguous
-- cashback history aborts rather than choosing an arbitrary "first" grant.
CREATE OR REPLACE FUNCTION public.backfill_missing_payment_capture_financials()
RETURNS BOOL AS $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM public.payment_effects AS capture
          LEFT JOIN public.payment_capture_financials AS financial
            ON financial.payment_id=capture.payment_id
           AND financial.capture_effect_id=capture.payment_effect_id
         WHERE capture.effect_kind='CAPTURE'
           AND financial.capture_transaction_id IS NULL
           AND (SELECT pg_catalog.count(*)
                  FROM public.payment_effects AS cashback
                  JOIN public.ledger_transactions AS journal
                    ON journal.transaction_id=cashback.ledger_transaction_id
                   AND journal.effect_id=cashback.payment_effect_id
                   AND journal.status='POSTED'
                 WHERE cashback.payment_id=capture.payment_id
                   AND cashback.effect_kind='CASHBACK'
                   AND cashback.original_transaction_id=capture.ledger_transaction_id)>1
    ) THEN
        RAISE EXCEPTION 'ambiguous cashback facts for missing capture financial';
    END IF;

    INSERT INTO public.payment_capture_financials (
        capture_transaction_id, payment_id, capture_effect_id, captured_atoms,
        expected_cashback_atoms, refunded_atoms, charged_back_atoms,
        cashback_reversed_atoms
    )
    SELECT capture.ledger_transaction_id, capture.payment_id,
           capture.payment_effect_id, capture.amount_atoms,
           coalesce((SELECT pg_catalog.sum(cashback.amount_atoms)
                       FROM public.payment_effects AS cashback
                       JOIN public.ledger_transactions AS journal
                         ON journal.transaction_id=cashback.ledger_transaction_id
                        AND journal.effect_id=cashback.payment_effect_id
                        AND journal.status='POSTED'
                      WHERE cashback.payment_id=capture.payment_id
                        AND cashback.effect_kind='CASHBACK'
                        AND cashback.original_transaction_id=capture.ledger_transaction_id),0),
           coalesce((SELECT pg_catalog.sum(refund.amount_atoms)
                       FROM public.payment_effects AS refund
                       JOIN public.ledger_transactions AS journal
                         ON journal.transaction_id=refund.ledger_transaction_id
                        AND journal.effect_id=refund.payment_effect_id
                        AND journal.status='POSTED'
                      WHERE refund.payment_id=capture.payment_id
                        AND refund.effect_kind='REFUND'
                        AND refund.original_transaction_id=capture.ledger_transaction_id),0),
           coalesce((SELECT pg_catalog.sum(chargeback.amount_atoms)
                       FROM public.payment_effects AS chargeback
                       JOIN public.ledger_transactions AS journal
                         ON journal.transaction_id=chargeback.ledger_transaction_id
                        AND journal.effect_id=chargeback.payment_effect_id
                        AND journal.status='POSTED'
                      WHERE chargeback.payment_id=capture.payment_id
                        AND chargeback.effect_kind='CHARGEBACK'
                        AND chargeback.original_transaction_id=capture.ledger_transaction_id),0),
           coalesce((SELECT pg_catalog.sum(reversal.amount_atoms)
                       FROM public.payment_effects AS cashback
                       JOIN public.payment_effects AS reversal
                         ON reversal.payment_id=cashback.payment_id
                        AND reversal.effect_kind='REVERSAL'
                        AND reversal.original_transaction_id=cashback.ledger_transaction_id
                      WHERE cashback.payment_id=capture.payment_id
                        AND cashback.effect_kind='CASHBACK'
                        AND cashback.original_transaction_id=capture.ledger_transaction_id),0)
      FROM public.payment_effects AS capture
      JOIN public.ledger_transactions AS journal
        ON journal.transaction_id=capture.ledger_transaction_id
       AND journal.effect_id=capture.payment_effect_id
       AND journal.transaction_kind='CAPTURE'
       AND journal.status='POSTED'
     WHERE capture.effect_kind='CAPTURE'
       AND NOT EXISTS (
           SELECT 1 FROM public.payment_capture_financials AS financial
            WHERE financial.payment_id=capture.payment_id
              AND financial.capture_effect_id=capture.payment_effect_id);
    RETURN true;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

REVOKE ALL ON FUNCTION public.backfill_missing_payment_capture_financials()
    FROM public;
GRANT EXECUTE ON FUNCTION public.backfill_missing_payment_capture_financials()
    TO ledger_admin;

SELECT public.backfill_missing_payment_capture_financials();
