-- CONTRACT: apply only after every offline writer uses migration 023's narrow
-- procedures and the exact rollout gates in docs/operations.md are green.
-- Enforcement functions/triggers are installed before raw runtime authority
-- is revoked. A crash at any statement boundary is therefore fail-closed and
-- never opens a drop-trigger/create-trigger gap.

CREATE OR REPLACE FUNCTION public.assert_offline_authority_contract_ready()
RETURNS BOOL AS $$
DECLARE
    partial_receipts INT8;
    invalid_v2_receipts INT8;
    invalid_closure_evidence INT8;
    missing_key_history INT8;
    overlapping_windows INT8;
BEGIN
    -- Fully legacy rows (all v2 fields NULL) remain immutable audit facts.
    -- Partially dual-written rows are neither v1 nor v2 and block cutover.
    SELECT pg_catalog.count(*) INTO partial_receipts
      FROM public.offline_redemption_receipts
     WHERE (presentation_payload_hash IS NOT NULL
            OR presentation_hash IS NOT NULL
            OR merchant_account_id IS NOT NULL
            OR acceptance_domain IS NOT NULL
            OR challenge_hash IS NOT NULL
            OR merchant_challenge IS NOT NULL
            OR settlement_epoch IS NOT NULL
            OR upload_fence IS NOT NULL
            OR presentation_counter IS NOT NULL
            OR device_identity_hash IS NOT NULL
            OR device_key_id IS NOT NULL
            OR presentation_payload IS NOT NULL
            OR presentation_signature IS NOT NULL)
       AND (presentation_payload_hash IS NULL
            OR presentation_hash IS NULL
            OR merchant_account_id IS NULL
            OR acceptance_domain IS NULL
            OR challenge_hash IS NULL
            OR merchant_challenge IS NULL
            OR settlement_epoch IS NULL
            OR upload_fence IS NULL
            OR presentation_counter IS NULL
            OR device_identity_hash IS NULL
            OR device_key_id IS NULL
            OR presentation_payload IS NULL
            OR presentation_signature IS NULL);
    SELECT pg_catalog.count(*) INTO invalid_v2_receipts
      FROM public.offline_redemption_receipts AS receipt
      JOIN public.offline_allowances AS allowance USING (allowance_id)
     WHERE receipt.presentation_payload_hash IS NOT NULL
       AND (
         pg_catalog.length(receipt.presentation_payload_hash) <> 32
         OR pg_catalog.length(receipt.presentation_hash) <> 32
         OR pg_catalog.length(receipt.challenge_hash) <> 32
         OR pg_catalog.length(receipt.merchant_challenge) <> 32
         OR pg_catalog.length(receipt.device_identity_hash) <> 32
         OR pg_catalog.length(receipt.presentation_signature) = 0
         OR pg_catalog.length(receipt.device_key_id) = 0
         OR receipt.settlement_epoch <= 0 OR receipt.upload_fence <= 0
         OR receipt.presentation_counter <= 0
         OR receipt.payload_hash IS DISTINCT FROM allowance.payload_hash
         OR receipt.device_identity_hash IS DISTINCT FROM allowance.device_identity_hash
         OR receipt.settlement_epoch IS DISTINCT FROM allowance.issuer_epoch
         OR receipt.upload_fence IS DISTINCT FROM allowance.device_counter
         OR receipt.challenge_hash IS DISTINCT FROM pg_catalog.decode(
                pg_catalog.sha256(receipt.merchant_challenge), 'hex')
         OR receipt.presentation_payload IS DISTINCT FROM (
              pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d70726573656e746174696f6e2f763100', 'hex')
              || pg_catalog.decode('0001', 'hex')
              || allowance.payload_hash
              || public.ledger_hash_length_prefixed(
                     pg_catalog.convert_to(receipt.merchant_account_id, 'UTF8'))
              || public.ledger_hash_length_prefixed(
                     pg_catalog.convert_to(receipt.acceptance_domain, 'UTF8'))
              || receipt.merchant_challenge
              || public.ledger_hash_int64(receipt.settlement_epoch)
              || public.ledger_hash_int64(receipt.upload_fence)
              || public.ledger_hash_int64(receipt.presentation_counter)
              || public.ledger_hash_length_prefixed(
                     pg_catalog.convert_to(receipt.device_key_id, 'UTF8')))
         OR receipt.presentation_payload_hash IS DISTINCT FROM
              pg_catalog.decode(pg_catalog.sha256(receipt.presentation_payload), 'hex')
         OR receipt.presentation_hash IS DISTINCT FROM pg_catalog.decode(pg_catalog.sha256(
              pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d70726573656e746174696f6e2d656e76656c6f70652f763100', 'hex')
              || public.ledger_hash_length_prefixed(receipt.presentation_payload)
              || public.ledger_hash_length_prefixed(receipt.presentation_signature)), 'hex')
         OR receipt.effect_hash IS DISTINCT FROM pg_catalog.decode(pg_catalog.sha256(
              pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d726564656d7074696f6e2d6566666563742f763100', 'hex')
              || public.ledger_hash_length_prefixed(
                     pg_catalog.convert_to(receipt.effect_id, 'UTF8'))
              || public.ledger_hash_length_prefixed(
                     pg_catalog.convert_to(receipt.ledger_transaction_id, 'UTF8'))
              || receipt.posting_request_hash), 'hex')
         OR (SELECT pg_catalog.count(*)
               FROM public.ledger_transactions AS transaction
              WHERE transaction.transaction_id=receipt.ledger_transaction_id
                AND transaction.effect_id=receipt.effect_id
                AND transaction.request_hash=receipt.posting_request_hash
                AND transaction.status='POSTED'
                AND transaction.transaction_kind='OFFLINE_REDEMPTION') <> 1
         OR (SELECT coalesce(pg_catalog.sum(line.amount_atoms), 0)
               FROM public.ledger_lines AS line
              WHERE line.transaction_id=receipt.ledger_transaction_id
                AND line.account_id=allowance.account_id
                AND line.asset_id=allowance.asset_id
                AND line.side='DEBIT') <> allowance.amount
         OR (SELECT coalesce(pg_catalog.sum(line.amount_atoms), 0)
               FROM public.ledger_lines AS line
              WHERE line.transaction_id=receipt.ledger_transaction_id
                AND line.account_id=allowance.account_id
                AND line.asset_id=allowance.asset_id
                AND line.side='CREDIT') <> 0
         OR (SELECT coalesce(pg_catalog.sum(line.amount_atoms), 0)
               FROM public.ledger_lines AS line
              WHERE line.transaction_id=receipt.ledger_transaction_id
                AND line.account_id=receipt.merchant_account_id
                AND line.asset_id=allowance.asset_id
                AND line.side='CREDIT') <> allowance.amount
         OR (SELECT coalesce(pg_catalog.sum(line.amount_atoms), 0)
               FROM public.ledger_lines AS line
              WHERE line.transaction_id=receipt.ledger_transaction_id
                AND line.account_id=receipt.merchant_account_id
                AND line.asset_id=allowance.asset_id
                AND line.side='DEBIT') <> 0
         OR NOT EXISTS (
              SELECT 1
                FROM public.offline_acceptance_domains AS domain
               WHERE domain.acceptance_domain=receipt.acceptance_domain
                 AND domain.first_settlement_epoch <= allowance.issuer_epoch
                 AND (domain.last_settlement_epoch IS NULL
                      OR domain.last_settlement_epoch >= allowance.issuer_epoch))
       );
    SELECT pg_catalog.count(*) INTO invalid_closure_evidence
     FROM public.offline_domain_closure_evidence AS evidence
     WHERE pg_catalog.length(evidence.signature)=0
        OR evidence.canonical_payload IS DISTINCT FROM (
              pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d616363657074616e63652d646f6d61696e2d636c6f737572652f763100', 'hex')
              || pg_catalog.decode('0001', 'hex')
              || public.ledger_hash_length_prefixed(
                     pg_catalog.convert_to(evidence.acceptance_domain, 'UTF8'))
              || public.ledger_hash_length_prefixed(
                     pg_catalog.convert_to(evidence.account_id, 'UTF8'))
              || public.ledger_hash_length_prefixed(
                     pg_catalog.convert_to(evidence.asset_id, 'UTF8'))
              || public.ledger_hash_length_prefixed(
                     pg_catalog.convert_to(evidence.origin_region, 'UTF8'))
              || evidence.device_identity_hash
              || public.ledger_hash_int64(evidence.closed_settlement_epoch)
              || public.ledger_hash_int64(evidence.closed_upload_fence)
              || public.ledger_hash_length_prefixed(
                     pg_catalog.convert_to(evidence.key_id, 'UTF8')))
        OR evidence.payload_hash IS DISTINCT FROM
             pg_catalog.decode(pg_catalog.sha256(evidence.canonical_payload), 'hex')
        OR evidence.evidence_hash IS DISTINCT FROM pg_catalog.decode(pg_catalog.sha256(
             pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d636c6f737572652d65766964656e63652f763100', 'hex')
             || public.ledger_hash_length_prefixed(evidence.canonical_payload)
             || public.ledger_hash_length_prefixed(evidence.signature)), 'hex')
        OR NOT EXISTS (
             SELECT 1
               FROM public.offline_acceptance_domain_key_activations AS activation
               LEFT JOIN public.offline_acceptance_domain_key_terminations AS termination
                 ON termination.acceptance_domain=activation.acceptance_domain
                AND termination.key_id=activation.key_id
              WHERE activation.acceptance_domain=evidence.acceptance_domain
                AND activation.key_id=evidence.key_id
                AND activation.activated_epoch <= evidence.closed_settlement_epoch
                AND (termination.terminated_epoch IS NULL
                     OR termination.terminated_epoch > evidence.closed_settlement_epoch)
        );
    SELECT pg_catalog.count(*) INTO missing_key_history
      FROM public.offline_acceptance_domains AS domain
     WHERE NOT EXISTS (
         SELECT 1
           FROM public.offline_acceptance_domain_key_activations AS activation
          WHERE activation.acceptance_domain=domain.acceptance_domain
            AND activation.key_id=domain.closure_key_id
            AND activation.activated_epoch=domain.first_settlement_epoch
     );
    SELECT pg_catalog.count(*) INTO overlapping_windows
      FROM public.offline_acceptance_domain_key_activations AS left_key
      JOIN public.offline_acceptance_domain_key_activations AS right_key
        ON right_key.acceptance_domain=left_key.acceptance_domain
       AND right_key.activated_epoch > left_key.activated_epoch
      LEFT JOIN public.offline_acceptance_domain_key_terminations AS left_end
        ON left_end.acceptance_domain=left_key.acceptance_domain
       AND left_end.key_id=left_key.key_id
     WHERE left_end.terminated_epoch IS NULL
        OR left_end.terminated_epoch > right_key.activated_epoch;
    IF partial_receipts <> 0 OR invalid_v2_receipts <> 0
       OR invalid_closure_evidence <> 0 OR missing_key_history <> 0
       OR overlapping_windows <> 0 THEN
        RAISE EXCEPTION 'offline contract gate failed: partial_receipts=%, invalid_v2_receipts=%, invalid_closures=%, missing_key_history=%, overlapping_windows=%',
            partial_receipts, invalid_v2_receipts, invalid_closure_evidence,
            missing_key_history, overlapping_windows;
    END IF;
    RETURN true;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

SELECT public.assert_offline_authority_contract_ready();

-- Replace the migration-009 function in place. The already-present trigger
-- never disappears, so no receipt can enter between old and new enforcement.
CREATE OR REPLACE FUNCTION public.enforce_offline_redemption_ledger_effect()
RETURNS TRIGGER AS $$
DECLARE
    allowance_amount DECIMAL;
    allowance_account STRING;
    allowance_asset STRING;
    allowance_payload_hash BYTES;
    allowance_device_hash BYTES;
    allowance_epoch INT8;
    allowance_fence INT8;
    matching_effects INT8;
    matching_debit DECIMAL;
    matching_credit DECIMAL;
    matching_source_credit DECIMAL;
    matching_merchant_debit DECIMAL;
    matching_domain INT8;
    canonical_presentation BYTES;
    calculated_effect_hash BYTES;
    calculated_payload_hash BYTES;
    calculated_envelope_hash BYTES;
BEGIN
    IF (NEW).presentation_payload_hash IS NULL
       OR pg_catalog.length((NEW).presentation_payload_hash) <> 32
       OR (NEW).presentation_hash IS NULL
       OR pg_catalog.length((NEW).presentation_hash) <> 32
       OR (NEW).merchant_account_id IS NULL
       OR pg_catalog.length((NEW).merchant_account_id) = 0
       OR (NEW).acceptance_domain IS NULL
       OR pg_catalog.length((NEW).acceptance_domain) = 0
       OR (NEW).challenge_hash IS NULL
       OR pg_catalog.length((NEW).challenge_hash) <> 32
       OR (NEW).merchant_challenge IS NULL
       OR pg_catalog.length((NEW).merchant_challenge) <> 32
       OR (NEW).settlement_epoch IS NULL OR (NEW).settlement_epoch <= 0
       OR (NEW).upload_fence IS NULL OR (NEW).upload_fence <= 0
       OR (NEW).presentation_counter IS NULL OR (NEW).presentation_counter <= 0
       OR (NEW).device_identity_hash IS NULL
       OR pg_catalog.length((NEW).device_identity_hash) <> 32
       OR (NEW).device_key_id IS NULL OR pg_catalog.length((NEW).device_key_id) = 0
       OR (NEW).presentation_payload IS NULL
       OR pg_catalog.length((NEW).presentation_payload) = 0
       OR (NEW).presentation_signature IS NULL
       OR pg_catalog.length((NEW).presentation_signature) = 0 THEN
        RAISE EXCEPTION 'offline redemption requires complete secure-element presentation';
    END IF;

    SELECT amount, account_id, asset_id, payload_hash, device_identity_hash,
           issuer_epoch, device_counter
      INTO allowance_amount, allowance_account, allowance_asset,
           allowance_payload_hash, allowance_device_hash,
           allowance_epoch, allowance_fence
      FROM public.offline_allowances
     WHERE allowance_id=(NEW).allowance_id;
    IF allowance_amount IS NULL
       OR (NEW).payload_hash IS DISTINCT FROM allowance_payload_hash
       OR (NEW).device_identity_hash IS DISTINCT FROM allowance_device_hash
       OR (NEW).settlement_epoch IS DISTINCT FROM allowance_epoch
       OR (NEW).upload_fence IS DISTINCT FROM allowance_fence
       OR (NEW).merchant_account_id IS NOT DISTINCT FROM allowance_account THEN
        RAISE EXCEPTION 'offline presentation does not bind the issued allowance';
    END IF;

    canonical_presentation :=
        pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d70726573656e746174696f6e2f763100', 'hex')
        || pg_catalog.decode('0001', 'hex')
        || allowance_payload_hash
        || public.ledger_hash_length_prefixed(
               pg_catalog.convert_to((NEW).merchant_account_id, 'UTF8'))
        || public.ledger_hash_length_prefixed(
               pg_catalog.convert_to((NEW).acceptance_domain, 'UTF8'))
        || (NEW).merchant_challenge
        || public.ledger_hash_int64((NEW).settlement_epoch)
        || public.ledger_hash_int64((NEW).upload_fence)
        || public.ledger_hash_int64((NEW).presentation_counter)
        || public.ledger_hash_length_prefixed(
               pg_catalog.convert_to((NEW).device_key_id, 'UTF8'));
    calculated_payload_hash := pg_catalog.decode(
        pg_catalog.sha256(canonical_presentation), 'hex');
    calculated_envelope_hash := pg_catalog.decode(pg_catalog.sha256(
        pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d70726573656e746174696f6e2d656e76656c6f70652f763100', 'hex')
        || public.ledger_hash_length_prefixed(canonical_presentation)
        || public.ledger_hash_length_prefixed((NEW).presentation_signature)), 'hex');
    calculated_effect_hash := pg_catalog.decode(pg_catalog.sha256(
        pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d726564656d7074696f6e2d6566666563742f763100', 'hex')
        || public.ledger_hash_length_prefixed(
               pg_catalog.convert_to((NEW).effect_id, 'UTF8'))
        || public.ledger_hash_length_prefixed(
               pg_catalog.convert_to((NEW).ledger_transaction_id, 'UTF8'))
        || (NEW).posting_request_hash), 'hex');
    IF (NEW).presentation_payload IS DISTINCT FROM canonical_presentation
       OR (NEW).presentation_payload_hash IS DISTINCT FROM calculated_payload_hash
       OR (NEW).presentation_hash IS DISTINCT FROM calculated_envelope_hash
       OR (NEW).challenge_hash IS DISTINCT FROM pg_catalog.decode(
              pg_catalog.sha256((NEW).merchant_challenge), 'hex')
       OR (NEW).effect_hash IS DISTINCT FROM calculated_effect_hash THEN
        RAISE EXCEPTION 'offline presentation/effect canonical envelope verification failed';
    END IF;

    SELECT pg_catalog.count(*) INTO matching_effects
      FROM public.ledger_transactions
     WHERE transaction_id=(NEW).ledger_transaction_id
       AND effect_id=(NEW).effect_id
       AND request_hash=(NEW).posting_request_hash
       AND status='POSTED' AND transaction_kind='OFFLINE_REDEMPTION';
    SELECT coalesce(pg_catalog.sum(amount_atoms), 0) INTO matching_debit
      FROM public.ledger_lines
     WHERE transaction_id=(NEW).ledger_transaction_id
       AND account_id=allowance_account AND asset_id=allowance_asset
       AND side='DEBIT';
    SELECT coalesce(pg_catalog.sum(amount_atoms), 0) INTO matching_credit
      FROM public.ledger_lines
     WHERE transaction_id=(NEW).ledger_transaction_id
       AND account_id=(NEW).merchant_account_id AND asset_id=allowance_asset
       AND side='CREDIT';
    SELECT coalesce(pg_catalog.sum(amount_atoms), 0) INTO matching_source_credit
      FROM public.ledger_lines
     WHERE transaction_id=(NEW).ledger_transaction_id
       AND account_id=allowance_account AND asset_id=allowance_asset
       AND side='CREDIT';
    SELECT coalesce(pg_catalog.sum(amount_atoms), 0) INTO matching_merchant_debit
      FROM public.ledger_lines
     WHERE transaction_id=(NEW).ledger_transaction_id
       AND account_id=(NEW).merchant_account_id AND asset_id=allowance_asset
       AND side='DEBIT';
    SELECT pg_catalog.count(*) INTO matching_domain
      FROM public.offline_acceptance_domains
     WHERE acceptance_domain=(NEW).acceptance_domain
       AND first_settlement_epoch <= allowance_epoch
       AND (last_settlement_epoch IS NULL
            OR last_settlement_epoch >= allowance_epoch);
    IF matching_effects <> 1 OR matching_debit <> allowance_amount
       OR matching_credit <> allowance_amount OR matching_source_credit <> 0
       OR matching_merchant_debit <> 0 OR matching_domain <> 1 THEN
        RAISE EXCEPTION 'offline redemption lacks exact ledger/domain linkage';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE OR REPLACE FUNCTION public.enforce_offline_closure_canonical_evidence()
RETURNS TRIGGER AS $$
DECLARE
    canonical_payload_value BYTES;
    calculated_payload_hash BYTES;
    calculated_evidence_hash BYTES;
    valid_keys INT8;
BEGIN
    canonical_payload_value :=
        pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d616363657074616e63652d646f6d61696e2d636c6f737572652f763100', 'hex')
        || pg_catalog.decode('0001', 'hex')
        || public.ledger_hash_length_prefixed(
               pg_catalog.convert_to((NEW).acceptance_domain, 'UTF8'))
        || public.ledger_hash_length_prefixed(
               pg_catalog.convert_to((NEW).account_id, 'UTF8'))
        || public.ledger_hash_length_prefixed(
               pg_catalog.convert_to((NEW).asset_id, 'UTF8'))
        || public.ledger_hash_length_prefixed(
               pg_catalog.convert_to((NEW).origin_region, 'UTF8'))
        || (NEW).device_identity_hash
        || public.ledger_hash_int64((NEW).closed_settlement_epoch)
        || public.ledger_hash_int64((NEW).closed_upload_fence)
        || public.ledger_hash_length_prefixed(
               pg_catalog.convert_to((NEW).key_id, 'UTF8'));
    calculated_payload_hash := pg_catalog.decode(
        pg_catalog.sha256(canonical_payload_value), 'hex');
    calculated_evidence_hash := pg_catalog.decode(pg_catalog.sha256(
        pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d636c6f737572652d65766964656e63652f763100', 'hex')
        || public.ledger_hash_length_prefixed(canonical_payload_value)
        || public.ledger_hash_length_prefixed((NEW).signature)), 'hex');
    SELECT pg_catalog.count(*) INTO valid_keys
      FROM public.offline_acceptance_domain_key_activations AS activation
      LEFT JOIN public.offline_acceptance_domain_key_terminations AS termination
        ON termination.acceptance_domain=activation.acceptance_domain
       AND termination.key_id=activation.key_id
     WHERE activation.acceptance_domain=(NEW).acceptance_domain
       AND activation.key_id=(NEW).key_id
       AND activation.activated_epoch <= (NEW).closed_settlement_epoch
       AND (termination.terminated_epoch IS NULL
            OR termination.terminated_epoch > (NEW).closed_settlement_epoch);
    IF (NEW).canonical_payload IS DISTINCT FROM canonical_payload_value
       OR (NEW).payload_hash IS DISTINCT FROM calculated_payload_hash
       OR (NEW).evidence_hash IS DISTINCT FROM calculated_evidence_hash
       OR (NEW).signature IS NULL OR pg_catalog.length((NEW).signature)=0
       OR valid_keys <> 1 THEN
        RAISE EXCEPTION 'offline closure canonical envelope/key-window verification failed';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER offline_closure_canonical_evidence_guard
BEFORE INSERT ON offline_domain_closure_evidence
FOR EACH ROW EXECUTE FUNCTION public.enforce_offline_closure_canonical_evidence();

CREATE OR REPLACE FUNCTION public.enforce_offline_complete_domain_closure()
RETURNS TRIGGER AS $$
DECLARE
    allowance_account STRING;
    allowance_asset STRING;
    allowance_region STRING;
    allowance_device BYTES;
    allowance_epoch INT8;
    allowance_fence INT8;
    allowance_state STRING;
    required_domains INT8;
    valid_links INT8;
    all_links INT8;
    canonical_link_bytes BYTES;
    calculated_closure_hash BYTES;
    calculated_proof_hash BYTES;
BEGIN
    IF (NEW).closure_set_hash IS NULL
       OR pg_catalog.length((NEW).closure_set_hash) <> 32 THEN
        RAISE EXCEPTION 'offline termination requires closure-set hash';
    END IF;
    SELECT account_id, asset_id, origin_region, device_identity_hash,
           issuer_epoch, device_counter, state
      INTO allowance_account, allowance_asset, allowance_region,
           allowance_device, allowance_epoch, allowance_fence,
           allowance_state
      FROM public.offline_allowances
     WHERE allowance_id=(NEW).allowance_id;
    IF allowance_epoch IS NULL
       OR allowance_epoch IS DISTINCT FROM (NEW).issuer_epoch
       OR allowance_fence IS DISTINCT FROM (NEW).device_counter
       OR allowance_state IS DISTINCT FROM (NEW).terminal_kind THEN
        RAISE EXCEPTION 'offline termination proof does not bind terminal allowance';
    END IF;
    SELECT pg_catalog.count(*) INTO required_domains
      FROM public.offline_acceptance_domains
     WHERE first_settlement_epoch <= allowance_epoch
       AND (last_settlement_epoch IS NULL
            OR last_settlement_epoch >= allowance_epoch);
    SELECT pg_catalog.count(*) INTO all_links
      FROM public.offline_termination_closure_links
     WHERE allowance_id=(NEW).allowance_id;
    SELECT pg_catalog.count(*) INTO valid_links
      FROM public.offline_termination_closure_links AS link
      JOIN public.offline_domain_closure_evidence AS evidence
        ON evidence.evidence_hash=link.evidence_hash
       AND evidence.acceptance_domain=link.acceptance_domain
      JOIN public.offline_acceptance_domains AS domain
        ON domain.acceptance_domain=link.acceptance_domain
      JOIN public.offline_acceptance_domain_key_activations AS activation
        ON activation.acceptance_domain=evidence.acceptance_domain
       AND activation.key_id=evidence.key_id
       AND activation.activated_epoch <= evidence.closed_settlement_epoch
      LEFT JOIN public.offline_acceptance_domain_key_terminations AS termination
        ON termination.acceptance_domain=activation.acceptance_domain
       AND termination.key_id=activation.key_id
     WHERE link.allowance_id=(NEW).allowance_id
       AND domain.first_settlement_epoch <= allowance_epoch
       AND (domain.last_settlement_epoch IS NULL
            OR domain.last_settlement_epoch >= allowance_epoch)
       AND (termination.terminated_epoch IS NULL
            OR termination.terminated_epoch > evidence.closed_settlement_epoch)
       AND evidence.account_id=allowance_account
       AND evidence.asset_id=allowance_asset
       AND evidence.origin_region=allowance_region
       AND evidence.device_identity_hash=allowance_device
       AND (evidence.closed_settlement_epoch > allowance_epoch
            OR (evidence.closed_settlement_epoch=allowance_epoch
                AND evidence.closed_upload_fence >= allowance_fence));
    IF required_domains=0 OR all_links<>required_domains
       OR valid_links<>required_domains THEN
        RAISE EXCEPTION 'offline termination lacks complete signed domain closure';
    END IF;
    SELECT pg_catalog.decode(pg_catalog.string_agg(pg_catalog.encode(
               public.ledger_hash_length_prefixed(
                   pg_catalog.convert_to(link.acceptance_domain, 'UTF8'))
               || link.evidence_hash, 'hex'), '' ORDER BY link.acceptance_domain), 'hex')
      INTO canonical_link_bytes
      FROM public.offline_termination_closure_links AS link
     WHERE link.allowance_id=(NEW).allowance_id;
    calculated_closure_hash := pg_catalog.decode(pg_catalog.sha256(
        pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d636c6f737572652d7365742f763100', 'hex')
        || public.ledger_hash_uint32(required_domains)
        || canonical_link_bytes), 'hex');
    calculated_proof_hash := pg_catalog.decode(pg_catalog.sha256(
        pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d6e6f6e2d726564656d7074696f6e2d70726f6f662f763100', 'hex')
        || public.ledger_hash_length_prefixed(
               pg_catalog.convert_to((NEW).allowance_id, 'UTF8'))
        || (NEW).payload_hash
        || public.ledger_hash_int64((NEW).issuer_epoch)
        || public.ledger_hash_int64((NEW).device_counter)
        || public.ledger_hash_length_prefixed(
               pg_catalog.convert_to((NEW).terminal_kind, 'UTF8'))
        || public.ledger_hash_int64((NEW).fence_version)
        || (NEW).policy_evidence_hash || (NEW).closure_set_hash), 'hex');
    IF calculated_closure_hash IS DISTINCT FROM (NEW).closure_set_hash
       OR calculated_proof_hash IS DISTINCT FROM (NEW).proof_hash
       OR EXISTS (SELECT 1 FROM public.offline_redemption_receipts
                   WHERE allowance_id=(NEW).allowance_id) THEN
        RAISE EXCEPTION 'offline termination closure/proof hash verification failed';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER offline_proof_requires_complete_domain_closure
BEFORE INSERT ON offline_non_redemption_proofs
FOR EACH ROW EXECUTE FUNCTION public.enforce_offline_complete_domain_closure();

-- Only after every database guard exists do data-plane roles lose raw
-- financial authority. They retain SELECT plus EXECUTE on 023's functions.
REVOKE INSERT, UPDATE ON TABLE offline_device_counters,
    escrow_offline_issued, offline_allowances FROM offline_runtime;
REVOKE INSERT ON TABLE offline_redemption_receipts,
    offline_non_redemption_proofs, offline_domain_closure_evidence,
    offline_termination_closure_links FROM offline_runtime;
REVOKE UPDATE ON TABLE escrow_authorities, escrow_regional_rights
    FROM offline_runtime;
REVOKE INSERT ON TABLE offline_acceptance_domains,
    offline_acceptance_domain_key_activations,
    offline_acceptance_domain_key_terminations
    FROM offline_configuration_runtime;

REVOKE ALL ON FUNCTION public.assert_offline_authority_contract_ready() FROM public;
REVOKE ALL ON FUNCTION public.enforce_offline_redemption_ledger_effect() FROM public;
REVOKE ALL ON FUNCTION public.enforce_offline_closure_canonical_evidence() FROM public;
REVOKE ALL ON FUNCTION public.enforce_offline_complete_domain_closure() FROM public;
GRANT EXECUTE ON FUNCTION public.assert_offline_authority_contract_ready()
    TO ledger_admin, ledger_auditor;
