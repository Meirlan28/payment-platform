-- Expand phase for splitting the historical ledger_writer capability into
-- workload-specific roles. Existing grants deliberately remain valid so the
-- old binary can run while new identities and the procedure-aware writer are
-- rolled out. Migration 020 is the separately gated privilege contract.

CREATE ROLE IF NOT EXISTS payment_runtime NOLOGIN;
CREATE ROLE IF NOT EXISTS payment_escrow_runtime NOLOGIN;
CREATE ROLE IF NOT EXISTS idempotency_runtime NOLOGIN;
CREATE ROLE IF NOT EXISTS outbox_enqueue_runtime NOLOGIN;
CREATE ROLE IF NOT EXISTS fx_runtime NOLOGIN;
CREATE ROLE IF NOT EXISTS escrow_transfer_runtime NOLOGIN;
CREATE ROLE IF NOT EXISTS offline_runtime NOLOGIN;
CREATE ROLE IF NOT EXISTS offline_configuration_runtime NOLOGIN;
CREATE ROLE IF NOT EXISTS transport_inbox_runtime NOLOGIN;
CREATE ROLE IF NOT EXISTS saga_runtime NOLOGIN;
CREATE ROLE IF NOT EXISTS rail_runtime NOLOGIN;

GRANT USAGE ON SCHEMA public TO payment_runtime, payment_escrow_runtime,
    idempotency_runtime, outbox_enqueue_runtime, fx_runtime,
    escrow_transfer_runtime, offline_runtime, offline_configuration_runtime,
    transport_inbox_runtime, saga_runtime, rail_runtime;

-- The payment credential may not write escrow tables directly. This function
-- accepts only a SPEND/RETURN already tied to a posted payment effect and an
-- exact debit/credit of the payment's available account. Because the caller
-- invokes it inside the same SERIALIZABLE transaction, the receipt, journal,
-- payment fact, and authority delta either commit together or all roll back.
CREATE OR REPLACE FUNCTION public.apply_payment_escrow_effect(
    target_effect_id STRING,
    target_effect_kind STRING,
    target_account_id STRING,
    target_asset_id STRING,
    target_region STRING,
    target_amount DECIMAL,
    supplied_request_hash BYTES
)
RETURNS BOOL AS $$
DECLARE
    amount_text STRING;
    hash_input BYTES;
    calculated_request_hash BYTES;
    linked_effects INT8;
    inserted_effect_id STRING;
    changed_account_id STRING;
    stored_effect_kind STRING;
    stored_account_id STRING;
    stored_asset_id STRING;
    stored_region STRING;
    stored_amount DECIMAL;
    stored_request_hash BYTES;
BEGIN
    -- CockroachDB does not implement CREATE FUNCTION ... SET search_path or
    -- procedural SET LOCAL. Every relation/helper is therefore explicitly
    -- qualified; no lookup below depends on the caller's search_path.

    IF target_effect_kind NOT IN ('SPEND', 'RETURN')
       OR target_effect_id IS NULL OR pg_catalog.length(target_effect_id) NOT BETWEEN 1 AND 512
       OR target_account_id IS NULL OR pg_catalog.length(target_account_id) = 0
       OR target_asset_id IS NULL OR pg_catalog.length(target_asset_id) = 0
       OR target_region IS NULL OR pg_catalog.length(target_region) = 0
       OR target_amount IS NULL OR target_amount <= 0
       OR target_amount <> pg_catalog.trunc(target_amount)
       OR supplied_request_hash IS NULL OR pg_catalog.length(supplied_request_hash) <> 32 THEN
        RAISE EXCEPTION 'invalid payment escrow effect request';
    END IF;

    amount_text := target_amount::STRING;
    hash_input :=
        pg_catalog.decode('7061796d656e742d706c6174666f726d2f657363726f772d6566666563742f763100', 'hex')
        || public.ledger_hash_int64(pg_catalog.length(pg_catalog.convert_to(target_effect_kind, 'UTF8'))::INT8)
        || pg_catalog.convert_to(target_effect_kind, 'UTF8')
        || public.ledger_hash_int64(pg_catalog.length(pg_catalog.convert_to(target_effect_id, 'UTF8'))::INT8)
        || pg_catalog.convert_to(target_effect_id, 'UTF8')
        || public.ledger_hash_int64(pg_catalog.length(pg_catalog.convert_to(target_account_id, 'UTF8'))::INT8)
        || pg_catalog.convert_to(target_account_id, 'UTF8')
        || public.ledger_hash_int64(pg_catalog.length(pg_catalog.convert_to(target_asset_id, 'UTF8'))::INT8)
        || pg_catalog.convert_to(target_asset_id, 'UTF8')
        || public.ledger_hash_int64(pg_catalog.length(pg_catalog.convert_to(target_region, 'UTF8'))::INT8)
        || pg_catalog.convert_to(target_region, 'UTF8')
        || public.ledger_hash_int64(pg_catalog.length(pg_catalog.convert_to(amount_text, 'UTF8'))::INT8)
        || pg_catalog.convert_to(amount_text, 'UTF8');
    calculated_request_hash := pg_catalog.decode(pg_catalog.sha256(hash_input), 'hex');
    IF calculated_request_hash IS DISTINCT FROM supplied_request_hash THEN
        RAISE EXCEPTION 'payment escrow request hash verification failed';
    END IF;

    -- Resolve a committed retry/conflict before re-evaluating linkage. This
    -- preserves exact effect-ID substitution semantics even when the attacker
    -- changes an account/amount that cannot match the original payment fact.
    stored_effect_kind := NULL;
    SELECT effect_kind, account_id, asset_id, region, amount, request_hash
      INTO stored_effect_kind, stored_account_id, stored_asset_id,
           stored_region, stored_amount, stored_request_hash
      FROM public.escrow_effect_receipts
     WHERE effect_id=target_effect_id;
    IF stored_effect_kind IS NOT NULL THEN
        IF stored_effect_kind IS DISTINCT FROM target_effect_kind
           OR stored_account_id IS DISTINCT FROM target_account_id
           OR stored_asset_id IS DISTINCT FROM target_asset_id
           OR stored_region IS DISTINCT FROM target_region
           OR stored_amount IS DISTINCT FROM target_amount
           OR stored_request_hash IS DISTINCT FROM calculated_request_hash THEN
            RAISE EXCEPTION 'escrow effect conflict';
        END IF;
        RETURN false;
    END IF;

    SELECT pg_catalog.count(*) INTO linked_effects
      FROM public.payment_effects AS effect
      JOIN public.payment_operations AS payment
        ON payment.payment_id=effect.payment_id
      JOIN public.ledger_transactions AS transaction
        ON transaction.transaction_id=effect.ledger_transaction_id
       AND transaction.effect_id=effect.payment_effect_id
       AND transaction.status='POSTED'
     WHERE effect.payment_effect_id=target_effect_id
       AND effect.amount_atoms=target_amount
       AND payment.customer_available_account_id=target_account_id
       AND payment.asset_id=target_asset_id
       AND payment.authority_region=target_region
       AND (
           (target_effect_kind='SPEND'
            AND effect.effect_kind IN ('HOLD', 'REVERSAL')
            AND (SELECT coalesce(pg_catalog.sum(line.amount_atoms), 0)
                   FROM public.ledger_lines AS line
                  WHERE line.transaction_id=transaction.transaction_id
                    AND line.account_id=target_account_id
                    AND line.asset_id=target_asset_id
                    AND line.side='DEBIT')=target_amount
            AND NOT EXISTS (
                SELECT 1 FROM public.ledger_lines AS line
                 WHERE line.transaction_id=transaction.transaction_id
                   AND line.account_id=target_account_id
                   AND line.asset_id=target_asset_id
                   AND line.side='CREDIT'))
        OR (target_effect_kind='RETURN'
            AND effect.effect_kind IN ('CASHBACK', 'RELEASE', 'REVERSAL',
                                       'REFUND', 'CHARGEBACK')
            AND (SELECT coalesce(pg_catalog.sum(line.amount_atoms), 0)
                   FROM public.ledger_lines AS line
                  WHERE line.transaction_id=transaction.transaction_id
                    AND line.account_id=target_account_id
                    AND line.asset_id=target_asset_id
                    AND line.side='CREDIT')=target_amount
            AND NOT EXISTS (
                SELECT 1 FROM public.ledger_lines AS line
                 WHERE line.transaction_id=transaction.transaction_id
                   AND line.account_id=target_account_id
                   AND line.asset_id=target_asset_id
                   AND line.side='DEBIT'))
       );
    IF linked_effects <> 1 THEN
        RAISE EXCEPTION 'payment escrow effect is not linked to one exact posted payment effect';
    END IF;

    INSERT INTO public.escrow_effect_receipts
        (effect_id, effect_kind, account_id, asset_id, region, amount, request_hash)
    VALUES (target_effect_id, target_effect_kind, target_account_id,
            target_asset_id, target_region, target_amount,
            calculated_request_hash)
    ON CONFLICT (effect_id) DO NOTHING
    RETURNING effect_id INTO inserted_effect_id;

    IF inserted_effect_id IS NULL THEN
        SELECT effect_kind, account_id, asset_id, region, amount, request_hash
          INTO stored_effect_kind, stored_account_id, stored_asset_id,
               stored_region, stored_amount, stored_request_hash
          FROM public.escrow_effect_receipts
         WHERE effect_id=target_effect_id;
        IF stored_effect_kind IS DISTINCT FROM target_effect_kind
           OR stored_account_id IS DISTINCT FROM target_account_id
           OR stored_asset_id IS DISTINCT FROM target_asset_id
           OR stored_region IS DISTINCT FROM target_region
           OR stored_amount IS DISTINCT FROM target_amount
           OR stored_request_hash IS DISTINCT FROM calculated_request_hash THEN
            RAISE EXCEPTION 'escrow effect conflict';
        END IF;
        RETURN false;
    END IF;

    changed_account_id := NULL;
    IF target_effect_kind = 'SPEND' THEN
        UPDATE public.escrow_regional_rights
           SET available=available-target_amount,
               version=version+1,
               updated_at=pg_catalog.transaction_timestamp()
         WHERE account_id=target_account_id
           AND asset_id=target_asset_id
           AND region=target_region
           AND available >= target_amount
        RETURNING account_id INTO changed_account_id;
        IF changed_account_id IS NULL THEN
            RAISE EXCEPTION 'escrow insufficient rights';
        END IF;

        changed_account_id := NULL;
        UPDATE public.escrow_authorities
           SET total_authority=total_authority-target_amount,
               version=version+1
         WHERE account_id=target_account_id
           AND asset_id=target_asset_id
           AND total_authority >= target_amount
        RETURNING account_id INTO changed_account_id;
        IF changed_account_id IS NULL THEN
            RAISE EXCEPTION 'escrow authority inconsistent';
        END IF;
    ELSE
        UPDATE public.escrow_regional_rights
           SET available=available+target_amount,
               version=version+1,
               updated_at=pg_catalog.transaction_timestamp()
         WHERE account_id=target_account_id
           AND asset_id=target_asset_id
           AND region=target_region
        RETURNING account_id INTO changed_account_id;
        IF changed_account_id IS NULL THEN
            RAISE EXCEPTION 'escrow regional authority is missing';
        END IF;

        changed_account_id := NULL;
        UPDATE public.escrow_authorities
           SET total_authority=total_authority+target_amount,
               version=version+1
         WHERE account_id=target_account_id
           AND asset_id=target_asset_id
        RETURNING account_id INTO changed_account_id;
        IF changed_account_id IS NULL THEN
            RAISE EXCEPTION 'escrow authority is missing';
        END IF;
    END IF;
    RETURN true;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

REVOKE ALL ON FUNCTION public.apply_payment_escrow_effect(
    STRING, STRING, STRING, STRING, STRING, DECIMAL, BYTES) FROM public;
GRANT EXECUTE ON FUNCTION public.apply_payment_escrow_effect(
    STRING, STRING, STRING, STRING, STRING, DECIMAL, BYTES)
    TO payment_escrow_runtime, cashback_repair_runtime;

-- Payment lifecycle capability. It cannot publish/claim outbox rows, allocate
-- IDs, evaluate authorization, post a journal entry, or mutate escrow unless
-- the corresponding independent capability is composed onto the LOGIN user.
GRANT SELECT, INSERT, UPDATE ON TABLE payment_operations, holds,
    payment_capture_financials TO payment_runtime;
GRANT SELECT, INSERT ON TABLE payment_effects TO payment_runtime;

GRANT SELECT, INSERT, UPDATE ON TABLE idempotency_records
    TO idempotency_runtime;
GRANT INSERT ON TABLE outbox_messages TO outbox_enqueue_runtime;

GRANT SELECT, INSERT ON TABLE fx_quotes, fx_quote_consumptions TO fx_runtime;

-- The authority-transfer workload owns allocation, signed hand-off, and
-- destination consumption. It has no ledger/payment/offline/workflow rights.
GRANT SELECT, INSERT, UPDATE ON TABLE escrow_authorities,
    escrow_regional_rights, escrow_transfers, escrow_consumed_certificates
    TO escrow_transfer_runtime;
GRANT SELECT, INSERT ON TABLE escrow_effect_receipts,
    escrow_consumption_transfer_locks, escrow_consumption_issuance_locks
    TO escrow_transfer_runtime;
GRANT SELECT, INSERT, UPDATE ON TABLE escrow_consumption_watermarks
    TO escrow_transfer_runtime;
GRANT SELECT ON TABLE escrow_verification_keys TO escrow_transfer_runtime;
GRANT SELECT ON escrow_authority_conservation TO escrow_transfer_runtime;

-- Offline issuance/redemption is isolated from online payment and transfer
-- certificate state. Acceptance-domain configuration remains a distinct
-- control-plane capability, not a runtime mutation permission.
GRANT SELECT, UPDATE ON TABLE escrow_authorities, escrow_regional_rights
    TO offline_runtime;
GRANT SELECT, INSERT, UPDATE ON TABLE offline_device_counters,
    escrow_offline_issued, offline_allowances TO offline_runtime;
GRANT SELECT, INSERT ON TABLE offline_redemption_receipts,
    offline_non_redemption_proofs, offline_domain_closure_evidence,
    offline_termination_closure_links TO offline_runtime;
GRANT SELECT ON TABLE offline_acceptance_domains TO offline_runtime;
GRANT SELECT ON escrow_authority_conservation TO offline_runtime;
GRANT SELECT, INSERT ON TABLE offline_acceptance_domains
    TO offline_configuration_runtime;

GRANT SELECT, INSERT, UPDATE ON TABLE transport_inbox_messages
    TO transport_inbox_runtime;
GRANT SELECT, INSERT, UPDATE ON TABLE saga_instances, saga_steps
    TO saga_runtime;
GRANT SELECT, INSERT, UPDATE ON TABLE external_attempts TO rail_runtime;

-- Repair is a reviewed financial workload. It can write only the correction
-- projection/effect it owns; journal posting and payment-bound escrow spend
-- remain separately composed capabilities on its LOGIN identity.
GRANT INSERT ON TABLE payment_effects TO cashback_repair_runtime;
GRANT UPDATE ON TABLE payment_operations, payment_capture_financials
    TO cashback_repair_runtime;
