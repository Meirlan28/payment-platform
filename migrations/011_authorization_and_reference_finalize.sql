-- Close two production security boundaries without changing any previously
-- checksummed migration:
--   1. account capabilities are explicit, append-only facts bound to the
--      authenticated SPIFFE principal;
--   2. reference projection is moved into the privileged ledger finalizer.
-- CockroachDB trigger bodies use the statement invoker for nested statements,
-- so granting the runtime writer access to migration-control tables would
-- unnecessarily widen the financial writer capability.

CREATE TABLE IF NOT EXISTS payment_account_capabilities (
    capability_id          STRING PRIMARY KEY,
    principal_id           STRING NOT NULL,
    book_id                STRING NOT NULL REFERENCES books (book_id),
    account_id             STRING NOT NULL REFERENCES accounts (account_id),
    permission             STRING NOT NULL CHECK (permission IN (
                               'AUTHORIZE_PAYER_AVAILABLE',
                               'AUTHORIZE_PAYER_HELD',
                               'AUTHORIZE_MERCHANT',
                               'CAPTURE_FEE',
                               'CAPTURE_TAX',
                               'CAPTURE_CASHBACK_EXPENSE',
                               'REFUND_MERCHANT_DEBIT',
                               'CHARGEBACK_MERCHANT_RESERVE'
                           )),
    policy_version         STRING NOT NULL,
    granted_by             STRING NOT NULL,
    evidence_hash          BYTES NOT NULL CHECK (length(evidence_hash) = 32),
    granted_at             TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (principal_id, book_id, account_id, permission, capability_id)
);

CREATE INDEX IF NOT EXISTS payment_account_capabilities_lookup_idx
    ON payment_account_capabilities (principal_id, book_id, account_id, permission);

CREATE TABLE IF NOT EXISTS payment_account_capability_revocations (
    capability_id          STRING PRIMARY KEY
                               REFERENCES payment_account_capabilities (capability_id),
    revoked_by             STRING NOT NULL,
    reason_code            STRING NOT NULL,
    evidence_hash          BYTES NOT NULL CHECK (length(evidence_hash) = 32),
    revoked_at             TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp()
);

CREATE OR REPLACE FUNCTION public.validate_payment_account_capability_insert()
RETURNS TRIGGER AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM public.accounts
         WHERE account_id = (NEW).account_id AND book_id = (NEW).book_id
    ) THEN
        RAISE EXCEPTION 'authorization capability account does not belong to book';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER payment_account_capability_validate_insert
BEFORE INSERT ON payment_account_capabilities
FOR EACH ROW
EXECUTE FUNCTION public.validate_payment_account_capability_insert();

CREATE OR REPLACE FUNCTION public.reject_authorization_fact_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'authorization grant and revocation facts are append-only';
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER payment_account_capability_no_update
BEFORE UPDATE ON payment_account_capabilities
FOR EACH ROW
EXECUTE FUNCTION public.reject_authorization_fact_mutation();

CREATE TRIGGER payment_account_capability_no_delete
BEFORE DELETE ON payment_account_capabilities
FOR EACH ROW
EXECUTE FUNCTION public.reject_authorization_fact_mutation();

CREATE TRIGGER payment_account_capability_revocation_no_update
BEFORE UPDATE ON payment_account_capability_revocations
FOR EACH ROW
EXECUTE FUNCTION public.reject_authorization_fact_mutation();

CREATE TRIGGER payment_account_capability_revocation_no_delete
BEFORE DELETE ON payment_account_capability_revocations
FOR EACH ROW
EXECUTE FUNCTION public.reject_authorization_fact_mutation();

CREATE ROLE IF NOT EXISTS payment_authorizer NOLOGIN;
GRANT USAGE ON SCHEMA public TO payment_authorizer;
REVOKE ALL ON TABLE payment_account_capabilities,
    payment_account_capability_revocations FROM public;
GRANT SELECT ON TABLE payment_account_capabilities,
    payment_account_capability_revocations TO payment_authorizer;
GRANT SELECT ON TABLE payment_account_capabilities,
    payment_account_capability_revocations TO ledger_reader, ledger_auditor;
GRANT SELECT, INSERT ON TABLE payment_account_capabilities,
    payment_account_capability_revocations TO ledger_admin;

REVOKE EXECUTE ON FUNCTION public.validate_payment_account_capability_insert() FROM public;
REVOKE EXECUTE ON FUNCTION public.reject_authorization_fact_mutation() FROM public;

-- The projection trigger from 008 cannot safely execute under ledger_writer
-- on CockroachDB. The same write is performed below inside the already narrow
-- SECURITY DEFINER finalization boundary and therefore commits atomically with
-- the POSTED journal fact.
DROP TRIGGER IF EXISTS ledger_transaction_project_reference ON ledger_transactions;

CREATE OR REPLACE FUNCTION public.finalize_ledger_transaction(target_transaction_id STRING)
RETURNS STRING AS $$
DECLARE
    target_book_id STRING;
    target_sequence_no INT8;
    target_prev_hash BYTES;
    target_entry_hash BYTES;
    target_status STRING;
    advanced_book_id STRING;
BEGIN
    SELECT book_id, sequence_no, prev_hash, entry_hash, status
      INTO target_book_id, target_sequence_no, target_prev_hash,
           target_entry_hash, target_status
      FROM public.ledger_transactions
     WHERE transaction_id=target_transaction_id
     FOR UPDATE;

    IF target_book_id IS NULL OR target_status <> 'DRAFT' THEN
        RETURN NULL;
    END IF;

    IF (SELECT count(*) FROM public.ledger_lines
         WHERE transaction_id=target_transaction_id) < 2 THEN
        RAISE EXCEPTION 'a posted ledger transaction requires at least two lines';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM public.ledger_lines
         WHERE transaction_id=target_transaction_id
         GROUP BY asset_id
        HAVING sum(CASE WHEN side='DEBIT' THEN amount_atoms ELSE 0 END)
             <> sum(CASE WHEN side='CREDIT' THEN amount_atoms ELSE 0 END)
    ) THEN
        RAISE EXCEPTION 'ledger transaction is not balanced for every asset';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM public.ledger_lines AS line
          JOIN public.accounts AS account ON account.account_id=line.account_id
         WHERE line.transaction_id=target_transaction_id
           AND (line.asset_id <> account.asset_id OR account.book_id <> target_book_id)
    ) THEN
        RAISE EXCEPTION 'ledger line account/book/asset mismatch';
    END IF;

    IF (SELECT min(line_no) FROM public.ledger_lines
         WHERE transaction_id=target_transaction_id) <> 1
       OR (SELECT max(line_no) FROM public.ledger_lines
            WHERE transaction_id=target_transaction_id)
          <> (SELECT count(*) FROM public.ledger_lines
               WHERE transaction_id=target_transaction_id) THEN
        RAISE EXCEPTION 'ledger line numbers must be contiguous from one';
    END IF;

    UPDATE public.books
       SET next_sequence_no=next_sequence_no+1,
           last_entry_hash=target_entry_hash
     WHERE book_id=target_book_id
       AND next_sequence_no=target_sequence_no
       AND last_entry_hash=target_prev_hash
    RETURNING book_id INTO advanced_book_id;
    IF advanced_book_id IS NULL THEN
        RAISE EXCEPTION 'ledger hash-chain compare-and-swap failed';
    END IF;

    UPDATE public.ledger_transactions
       SET status='POSTED', posted_at=transaction_timestamp()
     WHERE transaction_id=target_transaction_id AND status='DRAFT';

    INSERT INTO public.ledger_transaction_references_shadow (
        transaction_id, reference_type, reference_id, source_schema_version
    )
    SELECT transaction_id, 'LEDGER_TRANSACTION', reference_transaction_id,
           schema_version
      FROM public.ledger_transactions
     WHERE transaction_id = target_transaction_id
       AND reference_transaction_id IS NOT NULL
       AND EXISTS (
           SELECT 1 FROM public.reference_migration_control
            WHERE migration_name = 'ledger-reference-v2'
              AND phase IN ('SHADOWING', 'VERIFIED', 'CUTOVER', 'CONTRACTED')
       )
    ON CONFLICT (transaction_id) DO NOTHING;

    INSERT INTO public.account_balances (
        account_id, debit_atoms, credit_atoms, current_balance_atoms,
        last_sequence_no, updated_at
    )
    SELECT line.account_id,
           sum(CASE WHEN line.side='DEBIT' THEN line.amount_atoms ELSE 0 END)::DECIMAL(38,0),
           sum(CASE WHEN line.side='CREDIT' THEN line.amount_atoms ELSE 0 END)::DECIMAL(38,0),
           CASE account.normal_side
             WHEN 'DEBIT' THEN
                 (sum(CASE WHEN line.side='DEBIT' THEN line.amount_atoms ELSE 0 END)
                - sum(CASE WHEN line.side='CREDIT' THEN line.amount_atoms ELSE 0 END))::DECIMAL(38,0)
             ELSE
                 (sum(CASE WHEN line.side='CREDIT' THEN line.amount_atoms ELSE 0 END)
                - sum(CASE WHEN line.side='DEBIT' THEN line.amount_atoms ELSE 0 END))::DECIMAL(38,0)
           END,
           target_sequence_no,
           transaction_timestamp()
      FROM public.ledger_lines AS line
      JOIN public.accounts AS account ON account.account_id=line.account_id
     WHERE line.transaction_id=target_transaction_id
     GROUP BY line.account_id, account.normal_side
    ON CONFLICT (account_id) DO UPDATE
        SET debit_atoms=account_balances.debit_atoms+excluded.debit_atoms,
            credit_atoms=account_balances.credit_atoms+excluded.credit_atoms,
            current_balance_atoms=account_balances.current_balance_atoms
                                  + excluded.current_balance_atoms,
            last_sequence_no=greatest(account_balances.last_sequence_no,
                                      excluded.last_sequence_no),
            updated_at=excluded.updated_at;

    IF EXISTS (
        SELECT 1
          FROM public.account_balances AS balance
          JOIN public.accounts AS account ON account.account_id=balance.account_id
         WHERE account.enforce_spend_limit
           AND balance.current_balance_atoms < -account.credit_limit_atoms
           AND balance.account_id IN (
               SELECT account_id FROM public.ledger_lines
                WHERE transaction_id=target_transaction_id
           )
    ) THEN
        RAISE EXCEPTION 'posting exceeds available balance plus explicit credit';
    END IF;

    RETURN target_transaction_id;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

REVOKE ALL ON FUNCTION public.finalize_ledger_transaction(STRING) FROM public;
GRANT EXECUTE ON FUNCTION public.finalize_ledger_transaction(STRING) TO ledger_writer;
