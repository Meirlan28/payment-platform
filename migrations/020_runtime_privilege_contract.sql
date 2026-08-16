-- Contract phase for the role split expanded by 019. Production upgrades must
-- first grant the new capabilities to workload LOGIN identities, deploy/drain
-- the compatible writer, and only then include this migration. Fresh installs
-- may apply 019 and 020 consecutively before any workload starts.

REVOKE ALL ON TABLE payment_operations, holds, fx_quotes, payment_effects,
    fx_quote_consumptions, idempotency_records,
    ledger_transaction_references_shadow,
    escrow_authorities, escrow_regional_rights, escrow_transfers,
    escrow_consumed_certificates, escrow_effect_receipts,
    escrow_verification_keys, escrow_consumption_watermarks,
    escrow_consumption_transfer_locks, escrow_consumption_issuance_locks,
    outbox_messages, transport_inbox_messages, saga_instances, saga_steps,
    external_attempts, offline_device_counters, escrow_offline_issued,
    offline_allowances, offline_redemption_receipts,
    offline_non_redemption_proofs, offline_acceptance_domains,
    offline_domain_closure_evidence, offline_termination_closure_links,
    payment_capture_financials, payment_account_capabilities,
    payment_account_capability_revocations
    FROM ledger_writer;
REVOKE ALL ON escrow_authority_conservation FROM ledger_writer;

-- These are the only direct data-plane privileges retained by the trusted
-- balanced-journal posting capability.
GRANT SELECT ON TABLE assets, books, accounts, account_balances,
    ledger_transactions, ledger_lines TO ledger_writer;
GRANT INSERT ON TABLE ledger_transactions, ledger_lines TO ledger_writer;
GRANT EXECUTE ON FUNCTION public.finalize_ledger_transaction(STRING)
    TO ledger_writer;
