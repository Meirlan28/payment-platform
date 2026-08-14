-- CockroachDB trigger bodies execute with the statement invoker for nested
-- writes, even when the trigger function is declared SECURITY DEFINER. Keep
-- all privileged finalization work inside one narrow SECURITY DEFINER routine
-- and remove the two nested-write triggers. Runtime writers still have no
-- UPDATE privilege on books, balances, lines, or transaction headers.
DROP TRIGGER IF EXISTS ledger_transaction_validate_post ON ledger_transactions;
DROP TRIGGER IF EXISTS ledger_transaction_apply_balances ON ledger_transactions;

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
