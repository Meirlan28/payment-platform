-- Account provisioning and funding boundaries.
--
-- Opening a customer account and crediting it are production capabilities, not
-- fixture scripts. Both are idempotent on a caller-supplied external reference
-- so a client that times out and retries can never open two accounts or credit
-- the same deposit twice. The two capabilities are deliberately separate roles:
-- a credential that can open accounts must not be able to create money, and a
-- credential that can create money must not be able to grant spend capability.
--
-- Read-only account snapshots deliberately add no new role. ledger_reader
-- already holds SELECT on account_balances (001) and escrow_regional_rights
-- (003); the query service is a network surface over that existing privilege.

CREATE TABLE IF NOT EXISTS account_provisioning_records (
    external_reference   STRING PRIMARY KEY
                         CHECK (length(external_reference) BETWEEN 1 AND 512),
    payment_principal_id STRING NOT NULL,
    asset_id             STRING NOT NULL REFERENCES assets (asset_id),
    region               STRING NOT NULL CHECK (length(region) BETWEEN 1 AND 128),
    book_id              STRING NOT NULL REFERENCES books (book_id),
    available_account_id STRING NOT NULL REFERENCES accounts (account_id),
    held_account_id      STRING NOT NULL REFERENCES accounts (account_id),
    request_hash         BYTES NOT NULL CHECK (length(request_hash) = 32),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    CHECK (available_account_id <> held_account_id),
    UNIQUE (available_account_id),
    UNIQUE (held_account_id)
);

CREATE INDEX IF NOT EXISTS account_provisioning_records_principal_idx
    ON account_provisioning_records (payment_principal_id, asset_id);

-- A deposit is the only sanctioned way new spendable value enters a customer
-- account. The ledger transaction and the escrow authority raise happen in the
-- caller's single SERIALIZABLE transaction together with this receipt, so a
-- credited balance without matching spend rights is not representable.
CREATE TABLE IF NOT EXISTS funding_records (
    external_reference       STRING PRIMARY KEY
                             CHECK (length(external_reference) BETWEEN 1 AND 512),
    account_id               STRING NOT NULL REFERENCES accounts (account_id),
    asset_id                 STRING NOT NULL REFERENCES assets (asset_id),
    region                   STRING NOT NULL CHECK (length(region) BETWEEN 1 AND 128),
    amount_atoms             DECIMAL(38,0) NOT NULL CHECK (amount_atoms > 0),
    funding_source_reference STRING NOT NULL
                             CHECK (length(funding_source_reference) BETWEEN 1 AND 512),
    ledger_transaction_id    STRING NOT NULL UNIQUE
                             REFERENCES ledger_transactions (transaction_id),
    request_hash             BYTES NOT NULL CHECK (length(request_hash) = 32),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp()
);

CREATE INDEX IF NOT EXISTS funding_records_account_idx
    ON funding_records (account_id, created_at);

-- Both receipts are immutable facts. A replayed request is answered from the
-- stored row; it never rewrites one.
CREATE OR REPLACE FUNCTION public.reject_provisioning_record_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'provisioning and funding receipts are immutable';
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER account_provisioning_records_immutable
BEFORE UPDATE OR DELETE ON account_provisioning_records
FOR EACH ROW EXECUTE FUNCTION public.reject_provisioning_record_mutation();

CREATE TRIGGER funding_records_immutable
BEFORE UPDATE OR DELETE ON funding_records
FOR EACH ROW EXECUTE FUNCTION public.reject_provisioning_record_mutation();

CREATE ROLE IF NOT EXISTS account_provisioner NOLOGIN;
CREATE ROLE IF NOT EXISTS funding_runtime NOLOGIN;

GRANT USAGE ON SCHEMA public TO account_provisioner, funding_runtime;

REVOKE ALL ON TABLE account_provisioning_records, funding_records FROM public;
REVOKE EXECUTE ON FUNCTION public.reject_provisioning_record_mutation() FROM public;

-- Provisioning may create books, accounts and capability grants. It has no
-- journal, escrow-mutation beyond zero-value initialisation, outbox, or
-- payment-lifecycle privilege, so it cannot move or create value.
GRANT SELECT ON TABLE assets, books, accounts, account_balances
    TO account_provisioner;
GRANT INSERT ON TABLE books, accounts, account_balances TO account_provisioner;
GRANT SELECT, INSERT ON TABLE payment_account_capabilities TO account_provisioner;
GRANT SELECT ON TABLE payment_account_capability_revocations TO account_provisioner;
GRANT SELECT, INSERT ON TABLE escrow_authorities, escrow_regional_rights
    TO account_provisioner;
GRANT SELECT, INSERT ON TABLE account_provisioning_records TO account_provisioner;

-- Funding may post a balanced journal transaction, raise escrow authority for
-- the credited account, and enqueue the resulting notification. It cannot
-- create accounts or grant capabilities.
GRANT SELECT ON TABLE assets, books, accounts, account_balances,
    ledger_transactions, ledger_lines TO funding_runtime;
GRANT INSERT ON TABLE ledger_transactions, ledger_lines TO funding_runtime;
GRANT EXECUTE ON FUNCTION public.finalize_ledger_transaction(STRING)
    TO funding_runtime;
GRANT SELECT, UPDATE ON TABLE escrow_authorities, escrow_regional_rights
    TO funding_runtime;
GRANT INSERT ON TABLE outbox_messages TO funding_runtime;
GRANT SELECT, INSERT ON TABLE funding_records TO funding_runtime;

GRANT SELECT ON TABLE account_provisioning_records, funding_records
    TO ledger_reader, ledger_auditor;
GRANT ALL ON TABLE account_provisioning_records, funding_records TO ledger_admin;
