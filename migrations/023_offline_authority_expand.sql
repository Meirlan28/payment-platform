-- EXPAND: append-only acceptance-domain key history and narrow offline
-- authority procedures. Compatibility grants remain until migration 024, so
-- both the old direct writer and the procedure-aware writer can run here.

CREATE TABLE IF NOT EXISTS offline_acceptance_domain_key_activations (
    acceptance_domain STRING NOT NULL
        REFERENCES offline_acceptance_domains (acceptance_domain),
    key_id             STRING NOT NULL CHECK (length(key_id) > 0),
    activated_epoch    INT8 NOT NULL CHECK (activated_epoch > 0),
    activated_at       TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (acceptance_domain, activated_epoch),
    UNIQUE (acceptance_domain, key_id),
    -- A key version is never shared across independently attesting domains.
    UNIQUE (key_id)
);

CREATE TABLE IF NOT EXISTS offline_acceptance_domain_key_terminations (
    acceptance_domain STRING NOT NULL,
    key_id             STRING NOT NULL,
    terminated_epoch   INT8 NOT NULL CHECK (terminated_epoch > 0),
    reason             STRING NOT NULL CHECK (reason IN ('RETIRED', 'REVOKED')),
    terminated_at      TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (acceptance_domain, key_id),
    UNIQUE (acceptance_domain, terminated_epoch),
    FOREIGN KEY (acceptance_domain, key_id)
        REFERENCES offline_acceptance_domain_key_activations
            (acceptance_domain, key_id)
);

-- Install the compatibility bridge before the catch-up INSERT. A legacy
-- control-plane writer which commits after this trigger exists creates its
-- initial key activation in the same transaction; rows committed earlier are
-- covered by the idempotent catch-up immediately below. The 024 readiness
-- assertion independently rejects any pre-trigger transaction that races the
-- catch-up and commits afterward.
CREATE OR REPLACE FUNCTION public.bootstrap_offline_domain_initial_key()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.offline_acceptance_domain_key_activations
        (acceptance_domain, key_id, activated_epoch)
    VALUES ((NEW).acceptance_domain, (NEW).closure_key_id,
            (NEW).first_settlement_epoch);
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

CREATE TRIGGER offline_domain_initial_key_activation
AFTER INSERT ON offline_acceptance_domains
FOR EACH ROW EXECUTE FUNCTION public.bootstrap_offline_domain_initial_key();

INSERT INTO offline_acceptance_domain_key_activations
    (acceptance_domain, key_id, activated_epoch)
SELECT acceptance_domain, closure_key_id, first_settlement_epoch
  FROM offline_acceptance_domains
ON CONFLICT (acceptance_domain, activated_epoch) DO NOTHING;

CREATE OR REPLACE VIEW offline_acceptance_domain_key_windows AS
SELECT activation.acceptance_domain,
       activation.key_id,
       activation.activated_epoch AS first_settlement_epoch,
       CASE
         WHEN termination.terminated_epoch IS NULL
           THEN domain.last_settlement_epoch
         WHEN domain.last_settlement_epoch IS NULL
           THEN termination.terminated_epoch - 1
         ELSE least(domain.last_settlement_epoch,
                    termination.terminated_epoch - 1)
       END AS last_settlement_epoch,
       termination.reason AS termination_reason
  FROM offline_acceptance_domain_key_activations AS activation
  JOIN offline_acceptance_domains AS domain USING (acceptance_domain)
  LEFT JOIN offline_acceptance_domain_key_terminations AS termination
    ON termination.acceptance_domain=activation.acceptance_domain
   AND termination.key_id=activation.key_id;

CREATE OR REPLACE FUNCTION public.reject_offline_key_history_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'offline acceptance-domain key history is append-only';
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER offline_key_activation_no_update
BEFORE UPDATE ON offline_acceptance_domain_key_activations
FOR EACH ROW EXECUTE FUNCTION public.reject_offline_key_history_mutation();
CREATE TRIGGER offline_key_activation_no_delete
BEFORE DELETE ON offline_acceptance_domain_key_activations
FOR EACH ROW EXECUTE FUNCTION public.reject_offline_key_history_mutation();
CREATE TRIGGER offline_key_termination_no_update
BEFORE UPDATE ON offline_acceptance_domain_key_terminations
FOR EACH ROW EXECUTE FUNCTION public.reject_offline_key_history_mutation();
CREATE TRIGGER offline_key_termination_no_delete
BEFORE DELETE ON offline_acceptance_domain_key_terminations
FOR EACH ROW EXECUTE FUNCTION public.reject_offline_key_history_mutation();

CREATE OR REPLACE FUNCTION public.enforce_offline_key_activation_window()
RETURNS TRIGGER AS $$
DECLARE
    domain_first INT8;
    domain_last INT8;
    overlapping INT8;
BEGIN
    SELECT first_settlement_epoch, last_settlement_epoch
      INTO domain_first, domain_last
      FROM public.offline_acceptance_domains
     WHERE acceptance_domain=(NEW).acceptance_domain
     FOR UPDATE;
    IF domain_first IS NULL
       OR (NEW).activated_epoch < domain_first
       OR (domain_last IS NOT NULL AND (NEW).activated_epoch > domain_last) THEN
        RAISE EXCEPTION 'offline key activation is outside domain coverage';
    END IF;
    SELECT pg_catalog.count(*) INTO overlapping
      FROM public.offline_acceptance_domain_key_activations AS activation
      LEFT JOIN public.offline_acceptance_domain_key_terminations AS termination
        ON termination.acceptance_domain=activation.acceptance_domain
       AND termination.key_id=activation.key_id
     WHERE activation.acceptance_domain=(NEW).acceptance_domain
       AND (termination.terminated_epoch IS NULL
            OR termination.terminated_epoch > (NEW).activated_epoch);
    IF overlapping <> 0 THEN
        RAISE EXCEPTION 'offline key activation window overlaps existing history';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE OR REPLACE FUNCTION public.enforce_offline_key_termination_window()
RETURNS TRIGGER AS $$
DECLARE
    activation_epoch INT8;
    domain_last INT8;
    later_activations INT8;
    latest_evidence_epoch INT8;
    locked_domain STRING;
BEGIN
    SELECT acceptance_domain, last_settlement_epoch
      INTO locked_domain, domain_last
      FROM public.offline_acceptance_domains
     WHERE acceptance_domain=(NEW).acceptance_domain
     FOR UPDATE;
    SELECT activation.activated_epoch
      INTO activation_epoch
      FROM public.offline_acceptance_domain_key_activations AS activation
     WHERE activation.acceptance_domain=(NEW).acceptance_domain
       AND activation.key_id=(NEW).key_id;
    IF activation_epoch IS NULL OR (NEW).terminated_epoch <= activation_epoch
       OR (domain_last IS NOT NULL
           AND ((domain_last < 9223372036854775807
                 AND (NEW).terminated_epoch > domain_last + 1)
                OR (domain_last = 9223372036854775807
                    AND (NEW).terminated_epoch > domain_last))) THEN
        RAISE EXCEPTION 'invalid offline key termination boundary';
    END IF;
    SELECT pg_catalog.count(*) INTO later_activations
      FROM public.offline_acceptance_domain_key_activations
     WHERE acceptance_domain=(NEW).acceptance_domain
       AND activated_epoch > activation_epoch;
    IF later_activations <> 0 THEN
        RAISE EXCEPTION 'offline key history must be terminated before the next activation';
    END IF;
    SELECT pg_catalog.max(closed_settlement_epoch) INTO latest_evidence_epoch
      FROM public.offline_domain_closure_evidence
     WHERE acceptance_domain=(NEW).acceptance_domain
       AND key_id=(NEW).key_id;
    IF latest_evidence_epoch IS NOT NULL
       AND (NEW).terminated_epoch <= latest_evidence_epoch THEN
        RAISE EXCEPTION 'offline key termination would invalidate historical evidence';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER offline_key_activation_window_guard
BEFORE INSERT ON offline_acceptance_domain_key_activations
FOR EACH ROW EXECUTE FUNCTION public.enforce_offline_key_activation_window();
CREATE TRIGGER offline_key_termination_window_guard
BEFORE INSERT ON offline_acceptance_domain_key_terminations
FOR EACH ROW EXECUTE FUNCTION public.enforce_offline_key_termination_window();

CREATE OR REPLACE FUNCTION public.configure_offline_acceptance_domain(
    p_domain STRING,
    p_initial_key_id STRING,
    p_first_epoch INT8,
    p_last_epoch INT8
)
RETURNS BOOL AS $$
DECLARE
    inserted_domain STRING;
    stored_key STRING;
    stored_first INT8;
    stored_last INT8;
BEGIN
    IF p_domain IS NULL OR pg_catalog.length(p_domain) NOT BETWEEN 1 AND 1024
       OR p_initial_key_id IS NULL
       OR pg_catalog.length(p_initial_key_id) NOT BETWEEN 1 AND 1024
       OR p_first_epoch IS NULL OR p_first_epoch <= 0
       OR (p_last_epoch IS NOT NULL AND p_last_epoch < p_first_epoch) THEN
        RAISE EXCEPTION 'invalid offline acceptance-domain configuration';
    END IF;
    INSERT INTO public.offline_acceptance_domains
        (acceptance_domain, closure_key_id, first_settlement_epoch,
         last_settlement_epoch)
    VALUES (p_domain, p_initial_key_id, p_first_epoch, p_last_epoch)
    ON CONFLICT (acceptance_domain) DO NOTHING
    RETURNING acceptance_domain INTO inserted_domain;
    IF inserted_domain IS NOT NULL THEN
        RETURN true;
    END IF;
    SELECT closure_key_id, first_settlement_epoch, last_settlement_epoch
      INTO stored_key, stored_first, stored_last
      FROM public.offline_acceptance_domains
     WHERE acceptance_domain=p_domain;
    IF stored_key IS DISTINCT FROM p_initial_key_id
       OR stored_first IS DISTINCT FROM p_first_epoch
       OR stored_last IS DISTINCT FROM p_last_epoch THEN
        RAISE EXCEPTION 'offline acceptance-domain configuration conflict';
    END IF;
    RETURN false;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.rotate_offline_acceptance_domain_key(
    p_domain STRING,
    p_expected_key_id STRING,
    p_new_key_id STRING,
    p_effective_epoch INT8,
    p_prior_key_reason STRING
)
RETURNS BOOL AS $$
DECLARE
    locked_domain STRING;
    current_key STRING;
    current_epoch INT8;
    exact_retry INT8;
BEGIN
    IF p_domain IS NULL OR p_expected_key_id IS NULL OR p_new_key_id IS NULL
       OR p_expected_key_id=p_new_key_id OR p_effective_epoch IS NULL
       OR p_effective_epoch <= 0
       OR p_prior_key_reason NOT IN ('RETIRED', 'REVOKED') THEN
        RAISE EXCEPTION 'invalid offline key rotation';
    END IF;
    SELECT acceptance_domain INTO locked_domain
      FROM public.offline_acceptance_domains
     WHERE acceptance_domain=p_domain FOR UPDATE;
    IF locked_domain IS NULL THEN
        RAISE EXCEPTION 'offline acceptance domain is not configured';
    END IF;

    SELECT pg_catalog.count(*) INTO exact_retry
      FROM public.offline_acceptance_domain_key_terminations AS termination
      JOIN public.offline_acceptance_domain_key_activations AS activation
        ON activation.acceptance_domain=termination.acceptance_domain
       AND activation.activated_epoch=termination.terminated_epoch
     WHERE termination.acceptance_domain=p_domain
       AND termination.key_id=p_expected_key_id
       AND termination.terminated_epoch=p_effective_epoch
       AND termination.reason=p_prior_key_reason
       AND activation.key_id=p_new_key_id;
    IF exact_retry = 1 THEN
        RETURN false;
    END IF;

    SELECT activation.key_id, activation.activated_epoch
      INTO current_key, current_epoch
      FROM public.offline_acceptance_domain_key_activations AS activation
      LEFT JOIN public.offline_acceptance_domain_key_terminations AS termination
        ON termination.acceptance_domain=activation.acceptance_domain
       AND termination.key_id=activation.key_id
     WHERE activation.acceptance_domain=p_domain
       AND termination.key_id IS NULL;
    IF current_key IS DISTINCT FROM p_expected_key_id
       OR p_effective_epoch <= current_epoch THEN
        RAISE EXCEPTION 'offline key rotation compare-and-swap failed';
    END IF;
    INSERT INTO public.offline_acceptance_domain_key_terminations
        (acceptance_domain, key_id, terminated_epoch, reason)
    VALUES (p_domain, p_expected_key_id, p_effective_epoch,
            p_prior_key_reason);
    INSERT INTO public.offline_acceptance_domain_key_activations
        (acceptance_domain, key_id, activated_epoch)
    VALUES (p_domain, p_new_key_id, p_effective_epoch);
    RETURN true;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.terminate_offline_acceptance_domain_key(
    p_domain STRING,
    p_expected_key_id STRING,
    p_effective_epoch INT8,
    p_reason STRING
)
RETURNS BOOL AS $$
DECLARE
    locked_domain STRING;
    current_key STRING;
    current_epoch INT8;
    stored_epoch INT8;
    stored_reason STRING;
BEGIN
    IF p_domain IS NULL OR p_expected_key_id IS NULL
       OR p_effective_epoch IS NULL OR p_effective_epoch <= 0
       OR p_reason NOT IN ('RETIRED', 'REVOKED') THEN
        RAISE EXCEPTION 'invalid offline key termination';
    END IF;
    SELECT acceptance_domain INTO locked_domain
      FROM public.offline_acceptance_domains
     WHERE acceptance_domain=p_domain FOR UPDATE;
    IF locked_domain IS NULL THEN
        RAISE EXCEPTION 'offline acceptance domain is not configured';
    END IF;
    SELECT terminated_epoch, reason INTO stored_epoch, stored_reason
      FROM public.offline_acceptance_domain_key_terminations
     WHERE acceptance_domain=p_domain AND key_id=p_expected_key_id;
    IF stored_epoch IS NOT NULL THEN
        IF stored_epoch IS DISTINCT FROM p_effective_epoch
           OR stored_reason IS DISTINCT FROM p_reason THEN
            RAISE EXCEPTION 'offline key termination conflict';
        END IF;
        RETURN false;
    END IF;
    SELECT activation.key_id, activation.activated_epoch
      INTO current_key, current_epoch
      FROM public.offline_acceptance_domain_key_activations AS activation
      LEFT JOIN public.offline_acceptance_domain_key_terminations AS termination
        ON termination.acceptance_domain=activation.acceptance_domain
       AND termination.key_id=activation.key_id
     WHERE activation.acceptance_domain=p_domain
       AND termination.key_id IS NULL;
    IF current_key IS DISTINCT FROM p_expected_key_id
       OR p_effective_epoch <= current_epoch THEN
        RAISE EXCEPTION 'offline key termination compare-and-swap failed';
    END IF;
    INSERT INTO public.offline_acceptance_domain_key_terminations
        (acceptance_domain, key_id, terminated_epoch, reason)
    VALUES (p_domain, p_expected_key_id, p_effective_epoch, p_reason);
    RETURN true;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.enroll_offline_device(
    p_account_id STRING,
    p_asset_id STRING,
    p_origin_region STRING,
    p_device_identity_hash BYTES,
    p_issuer_epoch INT8
)
RETURNS BOOL AS $$
DECLARE
    inserted_account STRING;
    stored_epoch INT8;
BEGIN
    IF p_account_id IS NULL OR p_asset_id IS NULL OR p_origin_region IS NULL
       OR p_device_identity_hash IS NULL
       OR pg_catalog.length(p_device_identity_hash) <> 32
       OR p_issuer_epoch IS NULL OR p_issuer_epoch <= 0 THEN
        RAISE EXCEPTION 'invalid offline device enrollment';
    END IF;
    INSERT INTO public.offline_device_counters
        (account_id, asset_id, origin_region, device_identity_hash, issuer_epoch)
    VALUES (p_account_id, p_asset_id, p_origin_region,
            p_device_identity_hash, p_issuer_epoch)
    ON CONFLICT (account_id, asset_id, origin_region, device_identity_hash)
    DO NOTHING RETURNING account_id INTO inserted_account;
    IF inserted_account IS NOT NULL THEN
        RETURN true;
    END IF;
    SELECT issuer_epoch INTO stored_epoch
      FROM public.offline_device_counters
     WHERE account_id=p_account_id AND asset_id=p_asset_id
       AND origin_region=p_origin_region
       AND device_identity_hash=p_device_identity_hash;
    IF stored_epoch IS DISTINCT FROM p_issuer_epoch THEN
        RAISE EXCEPTION 'offline device enrollment conflict';
    END IF;
    RETURN false;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.advance_offline_issuer_epoch(
    p_account_id STRING,
    p_asset_id STRING,
    p_origin_region STRING,
    p_device_identity_hash BYTES,
    p_current_epoch INT8,
    p_next_epoch INT8
)
RETURNS BOOL AS $$
DECLARE
    changed_account STRING;
    stored_epoch INT8;
BEGIN
    IF p_next_epoch IS NULL OR p_current_epoch IS NULL
       OR p_next_epoch <> p_current_epoch + 1 THEN
        RAISE EXCEPTION 'invalid offline issuer epoch advance';
    END IF;
    UPDATE public.offline_device_counters
       SET issuer_epoch=p_next_epoch, last_counter=0,
           fence_version=fence_version+1,
           updated_at=pg_catalog.transaction_timestamp()
     WHERE account_id=p_account_id AND asset_id=p_asset_id
       AND origin_region=p_origin_region
       AND device_identity_hash=p_device_identity_hash
       AND issuer_epoch=p_current_epoch
    RETURNING account_id INTO changed_account;
    IF changed_account IS NOT NULL THEN
        RETURN true;
    END IF;
    SELECT issuer_epoch INTO stored_epoch
      FROM public.offline_device_counters
     WHERE account_id=p_account_id AND asset_id=p_asset_id
       AND origin_region=p_origin_region
       AND device_identity_hash=p_device_identity_hash;
    IF stored_epoch IS DISTINCT FROM p_next_epoch THEN
        RAISE EXCEPTION 'offline issuer epoch compare-and-swap failed';
    END IF;
    RETURN false;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.prepare_offline_allowance(
    p_allowance_id STRING,
    p_account_id STRING,
    p_asset_id STRING,
    p_origin_region STRING,
    p_device_identity_hash BYTES,
    p_amount DECIMAL,
    p_key_id STRING
)
RETURNS BOOL AS $$
DECLARE
    existing_id STRING;
    stored_account STRING;
    stored_asset STRING;
    stored_region STRING;
    stored_device BYTES;
    stored_amount DECIMAL;
    stored_key STRING;
    issuer_epoch_value INT8;
    last_counter_value INT8;
    next_counter INT8;
    configured_domains INT8;
    key_covered_domains INT8;
    amount_text STRING;
    canonical_payload_value BYTES;
    payload_hash_value BYTES;
BEGIN
    IF p_allowance_id IS NULL OR pg_catalog.length(p_allowance_id) NOT BETWEEN 1 AND 1024
       OR p_account_id IS NULL OR pg_catalog.length(p_account_id) NOT BETWEEN 1 AND 1024
       OR p_asset_id IS NULL OR pg_catalog.length(p_asset_id) NOT BETWEEN 1 AND 1024
       OR p_origin_region IS NULL OR pg_catalog.length(p_origin_region) NOT BETWEEN 1 AND 1024
       OR p_device_identity_hash IS NULL OR pg_catalog.length(p_device_identity_hash) <> 32
       OR p_amount IS NULL OR p_amount <= 0 OR p_amount <> pg_catalog.trunc(p_amount)
       OR p_key_id IS NULL OR pg_catalog.length(p_key_id) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'invalid offline allowance preparation';
    END IF;
    SELECT allowance_id, account_id, asset_id, origin_region,
           device_identity_hash, amount
      INTO existing_id, stored_account, stored_asset, stored_region,
           stored_device, stored_amount
      FROM public.offline_allowances
     WHERE allowance_id=p_allowance_id FOR UPDATE;
    IF existing_id IS NOT NULL THEN
        IF stored_account IS DISTINCT FROM p_account_id
           OR stored_asset IS DISTINCT FROM p_asset_id
           OR stored_region IS DISTINCT FROM p_origin_region
           OR stored_device IS DISTINCT FROM p_device_identity_hash
           OR stored_amount IS DISTINCT FROM p_amount THEN
            RAISE EXCEPTION 'offline allowance id conflict';
        END IF;
        RETURN false;
    END IF;

    SELECT issuer_epoch, last_counter
      INTO issuer_epoch_value, last_counter_value
      FROM public.offline_device_counters
     WHERE account_id=p_account_id AND asset_id=p_asset_id
       AND origin_region=p_origin_region
       AND device_identity_hash=p_device_identity_hash
     FOR UPDATE;
    IF issuer_epoch_value IS NULL OR last_counter_value = 9223372036854775807 THEN
        RAISE EXCEPTION 'offline device is absent or its counter is exhausted';
    END IF;
    SELECT pg_catalog.count(*) INTO configured_domains
      FROM public.offline_acceptance_domains
     WHERE first_settlement_epoch <= issuer_epoch_value
       AND (last_settlement_epoch IS NULL
            OR last_settlement_epoch >= issuer_epoch_value);
    SELECT pg_catalog.count(*) INTO key_covered_domains
      FROM public.offline_acceptance_domains AS domain
     WHERE domain.first_settlement_epoch <= issuer_epoch_value
       AND (domain.last_settlement_epoch IS NULL
            OR domain.last_settlement_epoch >= issuer_epoch_value)
       AND EXISTS (
           SELECT 1
             FROM public.offline_acceptance_domain_key_activations AS activation
             LEFT JOIN public.offline_acceptance_domain_key_terminations AS termination
               ON termination.acceptance_domain=activation.acceptance_domain
              AND termination.key_id=activation.key_id
            WHERE activation.acceptance_domain=domain.acceptance_domain
              AND activation.activated_epoch <= issuer_epoch_value
              AND (termination.terminated_epoch IS NULL
                   OR termination.terminated_epoch > issuer_epoch_value)
       );
    IF configured_domains = 0 OR key_covered_domains <> configured_domains THEN
        RAISE EXCEPTION 'offline acceptance-domain keys do not cover issuer epoch';
    END IF;

    next_counter := last_counter_value + 1;
    UPDATE public.offline_device_counters
       SET last_counter=next_counter,
           updated_at=pg_catalog.transaction_timestamp()
     WHERE account_id=p_account_id AND asset_id=p_asset_id
       AND origin_region=p_origin_region
       AND device_identity_hash=p_device_identity_hash
       AND last_counter=last_counter_value;

    amount_text := p_amount::STRING;
    canonical_payload_value :=
        pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d616c6c6f77616e63652f763100', 'hex')
        || pg_catalog.decode('0001', 'hex')
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(p_account_id, 'UTF8'))
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(p_asset_id, 'UTF8'))
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(p_origin_region, 'UTF8'))
        || p_device_identity_hash
        || public.ledger_hash_int64(next_counter)
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(amount_text, 'UTF8'))
        || public.ledger_hash_int64(issuer_epoch_value)
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(p_allowance_id, 'UTF8'))
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(p_key_id, 'UTF8'));
    payload_hash_value := pg_catalog.decode(pg_catalog.sha256(canonical_payload_value), 'hex');
    INSERT INTO public.offline_allowances
        (allowance_id, account_id, asset_id, origin_region, device_identity_hash,
         device_counter, amount, issuer_epoch, key_id, canonical_payload,
         payload_hash)
    VALUES (p_allowance_id, p_account_id, p_asset_id, p_origin_region,
            p_device_identity_hash, next_counter, p_amount,
            issuer_epoch_value, p_key_id, canonical_payload_value,
            payload_hash_value);
    RETURN true;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.activate_offline_allowance(
    p_allowance_id STRING,
    p_payload_hash BYTES,
    p_signature BYTES
)
RETURNS BOOL AS $$
DECLARE
    stored_state STRING;
    stored_account STRING;
    stored_asset STRING;
    stored_region STRING;
    stored_device BYTES;
    stored_counter INT8;
    stored_amount DECIMAL;
    stored_epoch INT8;
    stored_key STRING;
    stored_payload BYTES;
    stored_hash BYTES;
    stored_signature BYTES;
    current_epoch INT8;
    calculated_payload BYTES;
    amount_text STRING;
    changed_account STRING;
BEGIN
    IF p_payload_hash IS NULL OR pg_catalog.length(p_payload_hash) <> 32
       OR p_signature IS NULL OR pg_catalog.length(p_signature) = 0 THEN
        RAISE EXCEPTION 'invalid offline allowance activation';
    END IF;
    SELECT state, account_id, asset_id, origin_region, device_identity_hash,
           device_counter, amount, issuer_epoch, key_id, canonical_payload,
           payload_hash, signature
      INTO stored_state, stored_account, stored_asset, stored_region,
           stored_device, stored_counter, stored_amount, stored_epoch,
           stored_key, stored_payload, stored_hash, stored_signature
      FROM public.offline_allowances
     WHERE allowance_id=p_allowance_id FOR UPDATE;
    IF stored_state IS NULL THEN
        RAISE EXCEPTION 'offline allowance is not prepared';
    END IF;
    amount_text := stored_amount::STRING;
    calculated_payload :=
        pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d616c6c6f77616e63652f763100', 'hex')
        || pg_catalog.decode('0001', 'hex')
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(stored_account, 'UTF8'))
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(stored_asset, 'UTF8'))
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(stored_region, 'UTF8'))
        || stored_device || public.ledger_hash_int64(stored_counter)
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(amount_text, 'UTF8'))
        || public.ledger_hash_int64(stored_epoch)
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(p_allowance_id, 'UTF8'))
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(stored_key, 'UTF8'));
    IF stored_payload IS DISTINCT FROM calculated_payload
       OR stored_hash IS DISTINCT FROM pg_catalog.decode(pg_catalog.sha256(calculated_payload), 'hex')
       OR stored_hash IS DISTINCT FROM p_payload_hash THEN
        RAISE EXCEPTION 'offline allowance canonical payload verification failed';
    END IF;
    IF stored_state <> 'PREPARED' THEN
        IF stored_signature IS DISTINCT FROM p_signature THEN
            RAISE EXCEPTION 'offline allowance activation conflict';
        END IF;
        RETURN false;
    END IF;
    SELECT issuer_epoch INTO current_epoch
      FROM public.offline_device_counters
     WHERE account_id=stored_account AND asset_id=stored_asset
       AND origin_region=stored_region AND device_identity_hash=stored_device
     FOR UPDATE;
    IF current_epoch IS DISTINCT FROM stored_epoch THEN
        RAISE EXCEPTION 'offline allowance issuer epoch is fenced';
    END IF;
    UPDATE public.escrow_regional_rights
       SET available=available-stored_amount, version=version+1,
           updated_at=pg_catalog.transaction_timestamp()
     WHERE account_id=stored_account AND asset_id=stored_asset
       AND region=stored_region AND available >= stored_amount
    RETURNING account_id INTO changed_account;
    IF changed_account IS NULL THEN
        RAISE EXCEPTION 'offline allowance has insufficient regional rights';
    END IF;
    INSERT INTO public.escrow_offline_issued
        (account_id, asset_id, origin_region, amount)
    VALUES (stored_account, stored_asset, stored_region, stored_amount)
    ON CONFLICT (account_id, asset_id, origin_region) DO UPDATE
       SET amount=public.escrow_offline_issued.amount+excluded.amount,
           version=public.escrow_offline_issued.version+1,
           updated_at=pg_catalog.transaction_timestamp();
    UPDATE public.offline_allowances
       SET signature=p_signature, state='ISSUED',
           issued_at=pg_catalog.transaction_timestamp()
     WHERE allowance_id=p_allowance_id AND state='PREPARED';
    RETURN true;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

-- Redemption validates the exact canonical presentation and signature
-- envelope bytes. Cryptographic signature/attestation validation remains at
-- the production HSM/secure-element adapter boundary; SQL does not claim it.
CREATE OR REPLACE FUNCTION public.redeem_offline_presentation(
    p_allowance_id STRING,
    p_allowance_payload_hash BYTES,
    p_effect_hash BYTES,
    p_effect_id STRING,
    p_ledger_transaction_id STRING,
    p_posting_request_hash BYTES,
    p_presentation_payload_hash BYTES,
    p_presentation_hash BYTES,
    p_merchant_account_id STRING,
    p_acceptance_domain STRING,
    p_challenge_hash BYTES,
    p_merchant_challenge BYTES,
    p_settlement_epoch INT8,
    p_upload_fence INT8,
    p_presentation_counter INT8,
    p_device_identity_hash BYTES,
    p_device_key_id STRING,
    p_presentation_payload BYTES,
    p_presentation_signature BYTES
)
RETURNS BOOL AS $$
DECLARE
    stored_state STRING;
    stored_account STRING;
    stored_asset STRING;
    stored_region STRING;
    stored_device BYTES;
    stored_counter INT8;
    stored_amount DECIMAL;
    stored_epoch INT8;
    stored_allowance_hash BYTES;
    matching_effects INT8;
    matching_debit DECIMAL;
    matching_credit DECIMAL;
    matching_source_credit DECIMAL;
    matching_merchant_debit DECIMAL;
    matching_domain INT8;
    canonical_presentation BYTES;
    calculated_payload_hash BYTES;
    calculated_envelope_hash BYTES;
    calculated_effect_hash BYTES;
    existing_receipts INT8;
    exact_receipts INT8;
    changed_account STRING;
BEGIN
    IF p_allowance_id IS NULL OR pg_catalog.length(p_allowance_id) NOT BETWEEN 1 AND 1024
       OR p_effect_id IS NULL OR pg_catalog.length(p_effect_id) NOT BETWEEN 1 AND 1024
       OR p_ledger_transaction_id IS NULL
       OR pg_catalog.length(p_ledger_transaction_id) NOT BETWEEN 1 AND 1024
       OR p_merchant_account_id IS NULL
       OR pg_catalog.length(p_merchant_account_id) NOT BETWEEN 1 AND 1024
       OR p_acceptance_domain IS NULL
       OR pg_catalog.length(p_acceptance_domain) NOT BETWEEN 1 AND 1024
       OR p_device_key_id IS NULL
       OR pg_catalog.length(p_device_key_id) NOT BETWEEN 1 AND 1024
       OR p_allowance_payload_hash IS NULL OR pg_catalog.length(p_allowance_payload_hash) <> 32
       OR p_effect_hash IS NULL OR pg_catalog.length(p_effect_hash) <> 32
       OR p_posting_request_hash IS NULL OR pg_catalog.length(p_posting_request_hash) <> 32
       OR p_presentation_payload_hash IS NULL OR pg_catalog.length(p_presentation_payload_hash) <> 32
       OR p_presentation_hash IS NULL OR pg_catalog.length(p_presentation_hash) <> 32
       OR p_challenge_hash IS NULL OR pg_catalog.length(p_challenge_hash) <> 32
       OR p_merchant_challenge IS NULL OR pg_catalog.length(p_merchant_challenge) <> 32
       OR p_device_identity_hash IS NULL OR pg_catalog.length(p_device_identity_hash) <> 32
       OR p_presentation_payload IS NULL OR pg_catalog.length(p_presentation_payload) = 0
       OR p_presentation_signature IS NULL OR pg_catalog.length(p_presentation_signature) = 0
       OR p_settlement_epoch IS NULL OR p_settlement_epoch <= 0
       OR p_upload_fence IS NULL OR p_upload_fence <= 0
       OR p_presentation_counter IS NULL OR p_presentation_counter <= 0 THEN
        RAISE EXCEPTION 'offline redemption requires complete presentation evidence';
    END IF;
    calculated_effect_hash := pg_catalog.decode(pg_catalog.sha256(
        pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d726564656d7074696f6e2d6566666563742f763100', 'hex')
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(p_effect_id, 'UTF8'))
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(p_ledger_transaction_id, 'UTF8'))
        || p_posting_request_hash), 'hex');
    IF calculated_effect_hash IS DISTINCT FROM p_effect_hash THEN
        RAISE EXCEPTION 'offline redemption effect hash mismatch';
    END IF;
    SELECT state, account_id, asset_id, origin_region, device_identity_hash,
           device_counter, amount, issuer_epoch, payload_hash
      INTO stored_state, stored_account, stored_asset, stored_region,
           stored_device, stored_counter, stored_amount, stored_epoch,
           stored_allowance_hash
      FROM public.offline_allowances
     WHERE allowance_id=p_allowance_id FOR UPDATE;
    IF stored_state IS NULL THEN
        RAISE EXCEPTION 'offline allowance is not found';
    END IF;
    IF stored_allowance_hash IS DISTINCT FROM p_allowance_payload_hash
       OR stored_device IS DISTINCT FROM p_device_identity_hash
       OR stored_epoch IS DISTINCT FROM p_settlement_epoch
       OR stored_counter IS DISTINCT FROM p_upload_fence
       OR stored_account IS NOT DISTINCT FROM p_merchant_account_id THEN
        RAISE EXCEPTION 'offline presentation does not bind the allowance';
    END IF;
    canonical_presentation :=
        pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d70726573656e746174696f6e2f763100', 'hex')
        || pg_catalog.decode('0001', 'hex')
        || p_allowance_payload_hash
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(p_merchant_account_id, 'UTF8'))
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(p_acceptance_domain, 'UTF8'))
        || p_merchant_challenge
        || public.ledger_hash_int64(p_settlement_epoch)
        || public.ledger_hash_int64(p_upload_fence)
        || public.ledger_hash_int64(p_presentation_counter)
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(p_device_key_id, 'UTF8'));
    calculated_payload_hash := pg_catalog.decode(pg_catalog.sha256(canonical_presentation), 'hex');
    calculated_envelope_hash := pg_catalog.decode(pg_catalog.sha256(
        pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d70726573656e746174696f6e2d656e76656c6f70652f763100', 'hex')
        || public.ledger_hash_length_prefixed(canonical_presentation)
        || public.ledger_hash_length_prefixed(p_presentation_signature)), 'hex');
    IF p_presentation_payload IS DISTINCT FROM canonical_presentation
       OR p_presentation_payload_hash IS DISTINCT FROM calculated_payload_hash
       OR p_presentation_hash IS DISTINCT FROM calculated_envelope_hash
       OR p_challenge_hash IS DISTINCT FROM
            pg_catalog.decode(pg_catalog.sha256(p_merchant_challenge), 'hex') THEN
        RAISE EXCEPTION 'offline presentation canonical envelope mismatch';
    END IF;
    SELECT pg_catalog.count(*) INTO existing_receipts
      FROM public.offline_redemption_receipts WHERE allowance_id=p_allowance_id;
    IF existing_receipts <> 0 THEN
        SELECT pg_catalog.count(*) INTO exact_receipts
          FROM public.offline_redemption_receipts
         WHERE allowance_id=p_allowance_id
           AND payload_hash=p_allowance_payload_hash AND effect_hash=p_effect_hash
           AND effect_id=p_effect_id
           AND ledger_transaction_id=p_ledger_transaction_id
           AND posting_request_hash=p_posting_request_hash
           AND presentation_payload_hash=p_presentation_payload_hash
           AND presentation_hash=p_presentation_hash
           AND merchant_account_id=p_merchant_account_id
           AND acceptance_domain=p_acceptance_domain
           AND challenge_hash=p_challenge_hash
           AND merchant_challenge=p_merchant_challenge
           AND settlement_epoch=p_settlement_epoch
           AND upload_fence=p_upload_fence
           AND presentation_counter=p_presentation_counter
           AND device_identity_hash=p_device_identity_hash
           AND device_key_id=p_device_key_id
           AND presentation_payload=p_presentation_payload
           AND presentation_signature=p_presentation_signature;
        IF exact_receipts <> 1 THEN
            RAISE EXCEPTION 'offline redemption receipt conflict';
        END IF;
        RETURN false;
    END IF;
    IF stored_state IN ('REVOKED', 'EXPIRED') THEN
        RAISE EXCEPTION 'offline allowance is terminal';
    END IF;
    IF stored_state <> 'ISSUED' THEN
        RAISE EXCEPTION 'offline allowance is not issued';
    END IF;
    SELECT pg_catalog.count(*) INTO matching_effects
      FROM public.ledger_transactions
     WHERE transaction_id=p_ledger_transaction_id AND effect_id=p_effect_id
       AND request_hash=p_posting_request_hash AND status='POSTED'
       AND transaction_kind='OFFLINE_REDEMPTION';
    SELECT coalesce(pg_catalog.sum(amount_atoms), 0) INTO matching_debit
      FROM public.ledger_lines
     WHERE transaction_id=p_ledger_transaction_id
       AND account_id=stored_account AND asset_id=stored_asset AND side='DEBIT';
    SELECT coalesce(pg_catalog.sum(amount_atoms), 0) INTO matching_credit
      FROM public.ledger_lines
     WHERE transaction_id=p_ledger_transaction_id
       AND account_id=p_merchant_account_id AND asset_id=stored_asset AND side='CREDIT';
    SELECT coalesce(pg_catalog.sum(amount_atoms), 0) INTO matching_source_credit
      FROM public.ledger_lines
     WHERE transaction_id=p_ledger_transaction_id
       AND account_id=stored_account AND asset_id=stored_asset AND side='CREDIT';
    SELECT coalesce(pg_catalog.sum(amount_atoms), 0) INTO matching_merchant_debit
      FROM public.ledger_lines
     WHERE transaction_id=p_ledger_transaction_id
       AND account_id=p_merchant_account_id AND asset_id=stored_asset AND side='DEBIT';
    SELECT pg_catalog.count(*) INTO matching_domain
      FROM public.offline_acceptance_domains
     WHERE acceptance_domain=p_acceptance_domain
       AND first_settlement_epoch <= stored_epoch
       AND (last_settlement_epoch IS NULL OR last_settlement_epoch >= stored_epoch);
    IF matching_effects <> 1 OR matching_debit <> stored_amount
       OR matching_credit <> stored_amount OR matching_source_credit <> 0
       OR matching_merchant_debit <> 0 OR matching_domain <> 1 THEN
        RAISE EXCEPTION 'offline redemption lacks exact ledger/domain linkage';
    END IF;
    INSERT INTO public.offline_redemption_receipts
        (allowance_id, payload_hash, effect_hash, effect_id,
         ledger_transaction_id, posting_request_hash,
         presentation_payload_hash, presentation_hash, merchant_account_id,
         acceptance_domain, challenge_hash, merchant_challenge,
         settlement_epoch, upload_fence, presentation_counter,
         device_identity_hash, device_key_id, presentation_payload,
         presentation_signature)
    VALUES (p_allowance_id, p_allowance_payload_hash, p_effect_hash, p_effect_id,
            p_ledger_transaction_id, p_posting_request_hash,
            p_presentation_payload_hash, p_presentation_hash,
            p_merchant_account_id, p_acceptance_domain, p_challenge_hash,
            p_merchant_challenge, p_settlement_epoch, p_upload_fence,
            p_presentation_counter, p_device_identity_hash, p_device_key_id,
            p_presentation_payload, p_presentation_signature);
    UPDATE public.escrow_offline_issued
       SET amount=amount-stored_amount, version=version+1,
           updated_at=pg_catalog.transaction_timestamp()
     WHERE account_id=stored_account AND asset_id=stored_asset
       AND origin_region=stored_region AND amount >= stored_amount
    RETURNING account_id INTO changed_account;
    IF changed_account IS NULL THEN
        RAISE EXCEPTION 'offline issued authority is inconsistent';
    END IF;
    changed_account := NULL;
    UPDATE public.escrow_authorities
       SET total_authority=total_authority-stored_amount, version=version+1
     WHERE account_id=stored_account AND asset_id=stored_asset
       AND total_authority >= stored_amount
    RETURNING account_id INTO changed_account;
    IF changed_account IS NULL THEN
        RAISE EXCEPTION 'offline total authority is inconsistent';
    END IF;
    UPDATE public.offline_allowances
       SET state='REDEEMED', redeemed_at=pg_catalog.transaction_timestamp()
     WHERE allowance_id=p_allowance_id AND state='ISSUED';
    RETURN true;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.record_offline_domain_closure(
    p_allowance_id STRING,
    p_evidence_hash BYTES,
    p_acceptance_domain STRING,
    p_account_id STRING,
    p_asset_id STRING,
    p_origin_region STRING,
    p_device_identity_hash BYTES,
    p_closed_settlement_epoch INT8,
    p_closed_upload_fence INT8,
    p_key_id STRING,
    p_payload_hash BYTES,
    p_canonical_payload BYTES,
    p_signature BYTES
)
RETURNS BOOL AS $$
DECLARE
    allowance_epoch INT8;
    allowance_counter INT8;
    allowance_account STRING;
    allowance_asset STRING;
    allowance_region STRING;
    allowance_device BYTES;
    valid_keys INT8;
    calculated_payload BYTES;
    calculated_payload_hash BYTES;
    calculated_evidence_hash BYTES;
    inserted_hash BYTES;
    exact_evidence INT8;
    exact_link INT8;
BEGIN
    SELECT account_id, asset_id, origin_region, device_identity_hash,
           issuer_epoch, device_counter
      INTO allowance_account, allowance_asset, allowance_region,
           allowance_device, allowance_epoch, allowance_counter
      FROM public.offline_allowances
     WHERE allowance_id=p_allowance_id FOR UPDATE;
    IF allowance_epoch IS NULL
       OR allowance_account IS DISTINCT FROM p_account_id
       OR allowance_asset IS DISTINCT FROM p_asset_id
       OR allowance_region IS DISTINCT FROM p_origin_region
       OR allowance_device IS DISTINCT FROM p_device_identity_hash
       OR p_closed_settlement_epoch < allowance_epoch
       OR (p_closed_settlement_epoch=allowance_epoch
           AND p_closed_upload_fence < allowance_counter) THEN
        RAISE EXCEPTION 'offline closure does not cover allowance namespace';
    END IF;
    SELECT pg_catalog.count(*) INTO valid_keys
      FROM public.offline_acceptance_domain_key_activations AS activation
      JOIN public.offline_acceptance_domains AS domain USING (acceptance_domain)
      LEFT JOIN public.offline_acceptance_domain_key_terminations AS termination
        ON termination.acceptance_domain=activation.acceptance_domain
       AND termination.key_id=activation.key_id
     WHERE activation.acceptance_domain=p_acceptance_domain
       AND activation.key_id=p_key_id
       AND domain.first_settlement_epoch <= allowance_epoch
       AND (domain.last_settlement_epoch IS NULL
            OR domain.last_settlement_epoch >= allowance_epoch)
       AND activation.activated_epoch <= p_closed_settlement_epoch
       AND (termination.terminated_epoch IS NULL
            OR termination.terminated_epoch > p_closed_settlement_epoch);
    IF valid_keys <> 1 THEN
        RAISE EXCEPTION 'offline closure key is invalid at logical epoch';
    END IF;
    calculated_payload :=
        pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d616363657074616e63652d646f6d61696e2d636c6f737572652f763100', 'hex')
        || pg_catalog.decode('0001', 'hex')
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(p_acceptance_domain, 'UTF8'))
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(p_account_id, 'UTF8'))
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(p_asset_id, 'UTF8'))
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(p_origin_region, 'UTF8'))
        || p_device_identity_hash
        || public.ledger_hash_int64(p_closed_settlement_epoch)
        || public.ledger_hash_int64(p_closed_upload_fence)
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(p_key_id, 'UTF8'));
    calculated_payload_hash := pg_catalog.decode(pg_catalog.sha256(calculated_payload), 'hex');
    calculated_evidence_hash := pg_catalog.decode(pg_catalog.sha256(
        pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d636c6f737572652d65766964656e63652f763100', 'hex')
        || public.ledger_hash_length_prefixed(calculated_payload)
        || public.ledger_hash_length_prefixed(p_signature)), 'hex');
    IF p_canonical_payload IS DISTINCT FROM calculated_payload
       OR p_payload_hash IS DISTINCT FROM calculated_payload_hash
       OR p_evidence_hash IS DISTINCT FROM calculated_evidence_hash
       OR p_signature IS NULL OR pg_catalog.length(p_signature)=0 THEN
        RAISE EXCEPTION 'offline closure canonical envelope mismatch';
    END IF;
    INSERT INTO public.offline_domain_closure_evidence
        (evidence_hash, acceptance_domain, account_id, asset_id, origin_region,
         device_identity_hash, closed_settlement_epoch, closed_upload_fence,
         key_id, payload_hash, canonical_payload, signature)
    VALUES (p_evidence_hash, p_acceptance_domain, p_account_id, p_asset_id,
            p_origin_region, p_device_identity_hash,
            p_closed_settlement_epoch, p_closed_upload_fence, p_key_id,
            p_payload_hash, p_canonical_payload, p_signature)
    ON CONFLICT (evidence_hash) DO NOTHING
    RETURNING evidence_hash INTO inserted_hash;
    IF inserted_hash IS NULL THEN
        SELECT pg_catalog.count(*) INTO exact_evidence
          FROM public.offline_domain_closure_evidence
         WHERE evidence_hash=p_evidence_hash
           AND acceptance_domain=p_acceptance_domain
           AND account_id=p_account_id AND asset_id=p_asset_id
           AND origin_region=p_origin_region
           AND device_identity_hash=p_device_identity_hash
           AND closed_settlement_epoch=p_closed_settlement_epoch
           AND closed_upload_fence=p_closed_upload_fence
           AND key_id=p_key_id AND payload_hash=p_payload_hash
           AND canonical_payload=p_canonical_payload AND signature=p_signature;
        IF exact_evidence <> 1 THEN
            RAISE EXCEPTION 'offline closure evidence hash conflict';
        END IF;
    END IF;
    INSERT INTO public.offline_termination_closure_links
        (allowance_id, acceptance_domain, evidence_hash)
    VALUES (p_allowance_id, p_acceptance_domain, p_evidence_hash)
    ON CONFLICT (allowance_id, acceptance_domain) DO NOTHING;
    SELECT pg_catalog.count(*) INTO exact_link
      FROM public.offline_termination_closure_links
     WHERE allowance_id=p_allowance_id
       AND acceptance_domain=p_acceptance_domain
       AND evidence_hash=p_evidence_hash;
    IF exact_link <> 1 THEN
        RAISE EXCEPTION 'offline closure link conflict';
    END IF;
    RETURN inserted_hash IS NOT NULL;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.terminate_offline_allowance(
    p_allowance_id STRING,
    p_terminal_kind STRING,
    p_payload_hash BYTES,
    p_issuer_epoch INT8,
    p_device_counter INT8,
    p_policy_evidence_hash BYTES,
    p_closure_set_hash BYTES
)
RETURNS INT8 AS $$
DECLARE
    stored_state STRING;
    stored_account STRING;
    stored_asset STRING;
    stored_region STRING;
    stored_device BYTES;
    stored_amount DECIMAL;
    stored_payload_hash BYTES;
    stored_issuer_epoch INT8;
    stored_device_counter INT8;
    required_domains INT8;
    valid_links INT8;
    all_links INT8;
    canonical_link_bytes BYTES;
    calculated_closure_set_hash BYTES;
    current_epoch INT8;
    last_counter_value INT8;
    current_fence INT8;
    next_fence INT8;
    existing_fence INT8;
    existing_kind STRING;
    existing_payload_hash BYTES;
    existing_policy_hash BYTES;
    existing_closure_hash BYTES;
    existing_proof_hash BYTES;
    calculated_proof_hash BYTES;
    changed_account STRING;
BEGIN
    IF p_terminal_kind NOT IN ('REVOKED', 'EXPIRED')
       OR p_payload_hash IS NULL OR pg_catalog.length(p_payload_hash) <> 32
       OR p_policy_evidence_hash IS NULL OR pg_catalog.length(p_policy_evidence_hash) <> 32
       OR p_closure_set_hash IS NULL OR pg_catalog.length(p_closure_set_hash) <> 32
       OR p_issuer_epoch IS NULL OR p_issuer_epoch <= 0
       OR p_device_counter IS NULL OR p_device_counter <= 0 THEN
        RAISE EXCEPTION 'invalid offline termination request';
    END IF;
    SELECT state, account_id, asset_id, origin_region, device_identity_hash,
           amount, payload_hash, issuer_epoch, device_counter
      INTO stored_state, stored_account, stored_asset, stored_region,
           stored_device, stored_amount, stored_payload_hash,
           stored_issuer_epoch, stored_device_counter
      FROM public.offline_allowances
     WHERE allowance_id=p_allowance_id FOR UPDATE;
    IF stored_state IS NULL OR stored_payload_hash IS DISTINCT FROM p_payload_hash
       OR stored_issuer_epoch IS DISTINCT FROM p_issuer_epoch
       OR stored_device_counter IS DISTINCT FROM p_device_counter THEN
        RAISE EXCEPTION 'offline termination allowance mismatch';
    END IF;
    SELECT terminal_kind, fence_version, payload_hash, policy_evidence_hash,
           closure_set_hash, proof_hash
      INTO existing_kind, existing_fence, existing_payload_hash,
           existing_policy_hash, existing_closure_hash, existing_proof_hash
      FROM public.offline_non_redemption_proofs
     WHERE allowance_id=p_allowance_id;
    IF existing_fence IS NOT NULL THEN
        calculated_proof_hash := pg_catalog.decode(pg_catalog.sha256(
            pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d6e6f6e2d726564656d7074696f6e2d70726f6f662f763100', 'hex')
            || public.ledger_hash_length_prefixed(pg_catalog.convert_to(p_allowance_id, 'UTF8'))
            || p_payload_hash || public.ledger_hash_int64(p_issuer_epoch)
            || public.ledger_hash_int64(p_device_counter)
            || public.ledger_hash_length_prefixed(pg_catalog.convert_to(p_terminal_kind, 'UTF8'))
            || public.ledger_hash_int64(existing_fence)
            || p_policy_evidence_hash || p_closure_set_hash), 'hex');
        IF existing_kind IS DISTINCT FROM p_terminal_kind
           OR existing_payload_hash IS DISTINCT FROM p_payload_hash
           OR existing_policy_hash IS DISTINCT FROM p_policy_evidence_hash
           OR existing_closure_hash IS DISTINCT FROM p_closure_set_hash
           OR existing_proof_hash IS DISTINCT FROM calculated_proof_hash THEN
            RAISE EXCEPTION 'offline termination proof conflict';
        END IF;
        RETURN existing_fence;
    END IF;
    IF stored_state='REDEEMED' THEN
        RAISE EXCEPTION 'offline allowance was already redeemed';
    END IF;
    IF stored_state <> 'ISSUED' THEN
        RAISE EXCEPTION 'offline allowance is not issued';
    END IF;
    SELECT pg_catalog.count(*) INTO required_domains
      FROM public.offline_acceptance_domains
     WHERE first_settlement_epoch <= p_issuer_epoch
       AND (last_settlement_epoch IS NULL
            OR last_settlement_epoch >= p_issuer_epoch);
    SELECT pg_catalog.count(*) INTO all_links
      FROM public.offline_termination_closure_links
     WHERE allowance_id=p_allowance_id;
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
     WHERE link.allowance_id=p_allowance_id
       AND domain.first_settlement_epoch <= p_issuer_epoch
       AND (domain.last_settlement_epoch IS NULL
            OR domain.last_settlement_epoch >= p_issuer_epoch)
       AND (termination.terminated_epoch IS NULL
            OR termination.terminated_epoch > evidence.closed_settlement_epoch)
       AND evidence.account_id=stored_account
       AND evidence.asset_id=stored_asset
       AND evidence.origin_region=stored_region
       AND evidence.device_identity_hash=stored_device
       AND (evidence.closed_settlement_epoch > p_issuer_epoch
            OR (evidence.closed_settlement_epoch=p_issuer_epoch
                AND evidence.closed_upload_fence >= p_device_counter));
    IF required_domains=0 OR all_links<>required_domains
       OR valid_links<>required_domains THEN
        RAISE EXCEPTION 'offline termination lacks complete valid domain closure';
    END IF;
    SELECT pg_catalog.decode(pg_catalog.string_agg(pg_catalog.encode(
               public.ledger_hash_length_prefixed(
                   pg_catalog.convert_to(link.acceptance_domain, 'UTF8'))
               || link.evidence_hash, 'hex'), '' ORDER BY link.acceptance_domain), 'hex')
      INTO canonical_link_bytes
      FROM public.offline_termination_closure_links AS link
     WHERE link.allowance_id=p_allowance_id;
    calculated_closure_set_hash := pg_catalog.decode(pg_catalog.sha256(
        pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d636c6f737572652d7365742f763100', 'hex')
        || public.ledger_hash_uint32(required_domains)
        || canonical_link_bytes), 'hex');
    IF calculated_closure_set_hash IS DISTINCT FROM p_closure_set_hash THEN
        RAISE EXCEPTION 'offline closure-set hash mismatch';
    END IF;
    IF EXISTS (SELECT 1 FROM public.offline_redemption_receipts
                WHERE allowance_id=p_allowance_id) THEN
        RAISE EXCEPTION 'offline allowance was already redeemed';
    END IF;
    SELECT issuer_epoch, last_counter, fence_version
      INTO current_epoch, last_counter_value, current_fence
      FROM public.offline_device_counters
     WHERE account_id=stored_account AND asset_id=stored_asset
       AND origin_region=stored_region AND device_identity_hash=stored_device
     FOR UPDATE;
    IF current_epoch < p_issuer_epoch OR last_counter_value < p_device_counter
       OR current_fence=9223372036854775807 THEN
        RAISE EXCEPTION 'offline termination fence conflict';
    END IF;
    next_fence := current_fence + 1;
    UPDATE public.offline_device_counters
       SET fence_version=next_fence,
           updated_at=pg_catalog.transaction_timestamp()
     WHERE account_id=stored_account AND asset_id=stored_asset
       AND origin_region=stored_region AND device_identity_hash=stored_device
       AND fence_version=current_fence;
    UPDATE public.escrow_offline_issued
       SET amount=amount-stored_amount, version=version+1,
           updated_at=pg_catalog.transaction_timestamp()
     WHERE account_id=stored_account AND asset_id=stored_asset
       AND origin_region=stored_region AND amount >= stored_amount
    RETURNING account_id INTO changed_account;
    IF changed_account IS NULL THEN
        RAISE EXCEPTION 'offline issued authority is inconsistent';
    END IF;
    changed_account := NULL;
    UPDATE public.escrow_regional_rights
       SET available=available+stored_amount, version=version+1,
           updated_at=pg_catalog.transaction_timestamp()
     WHERE account_id=stored_account AND asset_id=stored_asset
       AND region=stored_region
    RETURNING account_id INTO changed_account;
    IF changed_account IS NULL THEN
        RAISE EXCEPTION 'offline regional authority is missing';
    END IF;
    UPDATE public.offline_allowances
       SET state=p_terminal_kind, terminal_at=pg_catalog.transaction_timestamp()
     WHERE allowance_id=p_allowance_id AND state='ISSUED';
    calculated_proof_hash := pg_catalog.decode(pg_catalog.sha256(
        pg_catalog.decode('7061796d656e742d706c6174666f726d2f6f66666c696e652d6e6f6e2d726564656d7074696f6e2d70726f6f662f763100', 'hex')
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(p_allowance_id, 'UTF8'))
        || p_payload_hash || public.ledger_hash_int64(p_issuer_epoch)
        || public.ledger_hash_int64(p_device_counter)
        || public.ledger_hash_length_prefixed(pg_catalog.convert_to(p_terminal_kind, 'UTF8'))
        || public.ledger_hash_int64(next_fence)
        || p_policy_evidence_hash || p_closure_set_hash), 'hex');
    INSERT INTO public.offline_non_redemption_proofs
        (allowance_id, terminal_kind, payload_hash, issuer_epoch,
         device_counter, fence_version, policy_evidence_hash,
         closure_set_hash, proof_hash)
    VALUES (p_allowance_id, p_terminal_kind, p_payload_hash, p_issuer_epoch,
            p_device_counter, next_fence, p_policy_evidence_hash,
            p_closure_set_hash, calculated_proof_hash);
    RETURN next_fence;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

REVOKE ALL ON TABLE offline_acceptance_domain_key_activations,
    offline_acceptance_domain_key_terminations FROM public;
REVOKE ALL ON offline_acceptance_domain_key_windows FROM public;
GRANT ALL ON TABLE offline_acceptance_domain_key_activations,
    offline_acceptance_domain_key_terminations TO ledger_admin;
GRANT SELECT ON offline_acceptance_domain_key_windows TO ledger_admin;
GRANT SELECT ON TABLE offline_acceptance_domain_key_activations,
    offline_acceptance_domain_key_terminations TO offline_runtime,
    offline_configuration_runtime, ledger_reader, ledger_auditor,
    reconciliation_runtime;
GRANT SELECT ON offline_acceptance_domain_key_windows TO offline_runtime,
    offline_configuration_runtime, ledger_reader, ledger_auditor,
    reconciliation_runtime;

-- The legacy control plane still owns INSERT on offline_acceptance_domains
-- until 024. The bootstrap trigger makes that old write shape compatible.
-- New key-history tables are never granted raw INSERT: rotation/termination
-- are available only through the compare-and-swap procedures below.

REVOKE ALL ON FUNCTION public.reject_offline_key_history_mutation() FROM public;
REVOKE ALL ON FUNCTION public.enforce_offline_key_activation_window() FROM public;
REVOKE ALL ON FUNCTION public.enforce_offline_key_termination_window() FROM public;
REVOKE ALL ON FUNCTION public.bootstrap_offline_domain_initial_key() FROM public;
REVOKE ALL ON FUNCTION public.configure_offline_acceptance_domain(
    STRING, STRING, INT8, INT8) FROM public;
REVOKE ALL ON FUNCTION public.rotate_offline_acceptance_domain_key(
    STRING, STRING, STRING, INT8, STRING) FROM public;
REVOKE ALL ON FUNCTION public.terminate_offline_acceptance_domain_key(
    STRING, STRING, INT8, STRING) FROM public;
REVOKE ALL ON FUNCTION public.enroll_offline_device(
    STRING, STRING, STRING, BYTES, INT8) FROM public;
REVOKE ALL ON FUNCTION public.advance_offline_issuer_epoch(
    STRING, STRING, STRING, BYTES, INT8, INT8) FROM public;
REVOKE ALL ON FUNCTION public.prepare_offline_allowance(
    STRING, STRING, STRING, STRING, BYTES, DECIMAL, STRING) FROM public;
REVOKE ALL ON FUNCTION public.activate_offline_allowance(
    STRING, BYTES, BYTES) FROM public;
REVOKE ALL ON FUNCTION public.redeem_offline_presentation(
    STRING, BYTES, BYTES, STRING, STRING, BYTES, BYTES, BYTES,
    STRING, STRING, BYTES, BYTES, INT8, INT8, INT8, BYTES,
    STRING, BYTES, BYTES) FROM public;
REVOKE ALL ON FUNCTION public.record_offline_domain_closure(
    STRING, BYTES, STRING, STRING, STRING, STRING, BYTES,
    INT8, INT8, STRING, BYTES, BYTES, BYTES) FROM public;
REVOKE ALL ON FUNCTION public.terminate_offline_allowance(
    STRING, STRING, BYTES, INT8, INT8, BYTES, BYTES) FROM public;

GRANT EXECUTE ON FUNCTION public.configure_offline_acceptance_domain(
    STRING, STRING, INT8, INT8),
    public.rotate_offline_acceptance_domain_key(
    STRING, STRING, STRING, INT8, STRING),
    public.terminate_offline_acceptance_domain_key(
    STRING, STRING, INT8, STRING)
    TO offline_configuration_runtime;
GRANT EXECUTE ON FUNCTION public.enroll_offline_device(
    STRING, STRING, STRING, BYTES, INT8),
    public.advance_offline_issuer_epoch(
    STRING, STRING, STRING, BYTES, INT8, INT8),
    public.prepare_offline_allowance(
    STRING, STRING, STRING, STRING, BYTES, DECIMAL, STRING),
    public.activate_offline_allowance(STRING, BYTES, BYTES),
    public.redeem_offline_presentation(
    STRING, BYTES, BYTES, STRING, STRING, BYTES, BYTES, BYTES,
    STRING, STRING, BYTES, BYTES, INT8, INT8, INT8, BYTES,
    STRING, BYTES, BYTES),
    public.record_offline_domain_closure(
    STRING, BYTES, STRING, STRING, STRING, STRING, BYTES,
    INT8, INT8, STRING, BYTES, BYTES, BYTES),
    public.terminate_offline_allowance(
    STRING, STRING, BYTES, INT8, INT8, BYTES, BYTES)
    TO offline_runtime;
