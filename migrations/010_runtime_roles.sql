-- Least-privilege runtime roles and append-only control evidence introduced
-- after the core services existed. Login users/certificate CNs are created by
-- the jurisdiction-local deployment bootstrap and are granted these NOLOGIN
-- roles; no password or production identity is embedded in a migration.

CREATE ROLE IF NOT EXISTS id_allocator NOLOGIN;
CREATE ROLE IF NOT EXISTS outbox_publisher_runtime NOLOGIN;
CREATE ROLE IF NOT EXISTS reconciliation_runtime NOLOGIN;
CREATE ROLE IF NOT EXISTS cashback_repair_runtime NOLOGIN;

GRANT USAGE ON SCHEMA public TO id_allocator, outbox_publisher_runtime,
    reconciliation_runtime, cashback_repair_runtime;

REVOKE ALL ON TABLE id_issuers, reconciliation_runs,
    reconciliation_breaks, cashback_repair_manifests FROM public;

GRANT ALL ON TABLE id_issuers, reconciliation_runs,
    reconciliation_breaks, cashback_repair_manifests TO ledger_admin;

-- Allocators can only advance counters. The trigger below prevents namespace,
-- incarnation and counter rollback even if a runtime identity is compromised.
GRANT SELECT, UPDATE ON TABLE id_issuers TO id_allocator;

-- Publisher workers need no permission to create or alter a financial fact.
GRANT SELECT, UPDATE ON TABLE outbox_messages TO outbox_publisher_runtime;

-- Reconciliation observes a single SERIALIZABLE snapshot and persists only
-- its run/evidence rows. It cannot post a correction transaction.
GRANT SELECT ON TABLE assets, books, accounts, account_balances,
    ledger_transactions, ledger_lines, payment_operations, payment_effects,
    idempotency_records, escrow_authorities, escrow_regional_rights,
    escrow_transfers, escrow_consumed_certificates, outbox_messages,
    transport_inbox_messages, external_attempts, offline_allowances,
    escrow_offline_issued, offline_redemption_receipts,
    offline_non_redemption_proofs TO reconciliation_runtime;
GRANT SELECT ON escrow_authority_conservation TO reconciliation_runtime;
GRANT SELECT, INSERT, UPDATE ON TABLE reconciliation_runs,
    reconciliation_breaks TO reconciliation_runtime;

-- Repair planning/execution is deliberately a second capability. The runtime
-- identity also needs ledger_writer to post the reviewed correction template;
-- this role alone cannot mutate the journal or payment aggregate.
GRANT SELECT ON TABLE cashback_repair_manifests, payment_operations,
    payment_effects, ledger_transactions, ledger_lines TO cashback_repair_runtime;
GRANT INSERT, UPDATE ON TABLE cashback_repair_manifests TO cashback_repair_runtime;

GRANT SELECT ON TABLE reconciliation_runs, reconciliation_breaks,
    cashback_repair_manifests, id_issuers TO ledger_reader, ledger_auditor;
GRANT SELECT ON TABLE idempotency_records TO ledger_auditor;

CREATE OR REPLACE FUNCTION public.enforce_id_issuer_monotonic_update()
RETURNS TRIGGER AS $$
BEGIN
    IF (OLD).issuer_prefix IS DISTINCT FROM (NEW).issuer_prefix
       OR (OLD).incarnation IS DISTINCT FROM (NEW).incarnation
       OR (OLD).retired IS DISTINCT FROM (NEW).retired
       OR (OLD).created_at IS DISTINCT FROM (NEW).created_at
       OR (NEW).next_counter <= (OLD).next_counter
       OR (NEW).next_counter - (OLD).next_counter > 1000000 THEN
        RAISE EXCEPTION 'id issuer identity is immutable and counter advance must be in 1..1000000';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER id_issuer_monotonic_update
BEFORE UPDATE ON id_issuers
FOR EACH ROW
EXECUTE FUNCTION public.enforce_id_issuer_monotonic_update();

CREATE OR REPLACE FUNCTION public.enforce_reconciliation_run_update()
RETURNS TRIGGER AS $$
BEGIN
    IF (OLD).run_id IS DISTINCT FROM (NEW).run_id
       OR (OLD).started_at IS DISTINCT FROM (NEW).started_at
       OR (OLD).status <> 'RUNNING'
       OR (NEW).status NOT IN ('PASSED', 'FAILED')
       OR (NEW).completed_at IS NULL THEN
        RAISE EXCEPTION 'reconciliation run evidence is append-only after one terminal transition';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER reconciliation_run_terminal_once
BEFORE UPDATE ON reconciliation_runs
FOR EACH ROW
EXECUTE FUNCTION public.enforce_reconciliation_run_update();

CREATE OR REPLACE FUNCTION public.enforce_reconciliation_break_update()
RETURNS TRIGGER AS $$
BEGIN
    IF (OLD).break_id IS DISTINCT FROM (NEW).break_id
       OR (OLD).run_id IS DISTINCT FROM (NEW).run_id
       OR (OLD).category IS DISTINCT FROM (NEW).category
       OR (OLD).effect_id IS DISTINCT FROM (NEW).effect_id
       OR (OLD).asset_id IS DISTINCT FROM (NEW).asset_id
       OR (OLD).amount_atoms IS DISTINCT FROM (NEW).amount_atoms
       OR (OLD).details IS DISTINCT FROM (NEW).details
       OR (OLD).created_at IS DISTINCT FROM (NEW).created_at
       OR (OLD).status NOT IN ('OPEN', 'EXPECTED_LAG')
       OR (NEW).status NOT IN ('CORRECTION_POSTED', 'RESOLVED')
       OR ((NEW).status = 'CORRECTION_POSTED'
           AND (NEW).correction_transaction_id IS NULL)
       OR ((NEW).status = 'RESOLVED' AND (NEW).resolved_at IS NULL) THEN
        RAISE EXCEPTION 'reconciliation finding identity is immutable and resolution is monotonic';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER reconciliation_break_terminal_once
BEFORE UPDATE ON reconciliation_breaks
FOR EACH ROW
EXECUTE FUNCTION public.enforce_reconciliation_break_update();

CREATE OR REPLACE FUNCTION public.enforce_cashback_manifest_update()
RETURNS TRIGGER AS $$
BEGIN
    IF (OLD).repair_id IS DISTINCT FROM (NEW).repair_id
       OR (OLD).original_payment_id IS DISTINCT FROM (NEW).original_payment_id
       OR (OLD).original_transaction_id IS DISTINCT FROM (NEW).original_transaction_id
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

CREATE TRIGGER cashback_manifest_terminal_once
BEFORE UPDATE ON cashback_repair_manifests
FOR EACH ROW
EXECUTE FUNCTION public.enforce_cashback_manifest_update();

REVOKE EXECUTE ON FUNCTION public.enforce_id_issuer_monotonic_update() FROM public;
REVOKE EXECUTE ON FUNCTION public.enforce_reconciliation_run_update() FROM public;
REVOKE EXECUTE ON FUNCTION public.enforce_reconciliation_break_update() FROM public;
REVOKE EXECUTE ON FUNCTION public.enforce_cashback_manifest_update() FROM public;
