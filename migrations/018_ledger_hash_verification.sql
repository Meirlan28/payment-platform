-- Enforce the ledger-entry/v1 hash inside the database trust boundary. The
-- caller still supplies entry_hash for deterministic retries, but the
-- SECURITY DEFINER finalizer reconstructs every byte from persisted header
-- fields, exact canonical metadata bytes, and ordered lines before any chain
-- head or balance is advanced.

CREATE OR REPLACE FUNCTION public.ledger_hash_uint32(value INT8)
RETURNS BYTES
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT decode(lpad(to_hex(value), 8, '0'), 'hex')
$$;

CREATE OR REPLACE FUNCTION public.ledger_hash_int64(value INT8)
RETURNS BYTES
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT decode(lpad(to_hex(value), 16, '0'), 'hex')
$$;

CREATE OR REPLACE FUNCTION public.ledger_hash_length_prefixed(value BYTES)
RETURNS BYTES
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT public.ledger_hash_uint32(length(value)::INT8) || value
$$;

REVOKE ALL ON FUNCTION public.ledger_hash_uint32(INT8) FROM public;
REVOKE ALL ON FUNCTION public.ledger_hash_int64(INT8) FROM public;
REVOKE ALL ON FUNCTION public.ledger_hash_length_prefixed(BYTES) FROM public;
GRANT EXECUTE ON FUNCTION public.ledger_hash_uint32(INT8),
    public.ledger_hash_int64(INT8),
    public.ledger_hash_length_prefixed(BYTES) TO ledger_auditor, ledger_admin;

-- Existing POSTED rows may legitimately have NULL here. Before this migration
-- is applied, operators must deploy the expanded writer and drain every DRAFT
-- created without canonical bytes. Every INSERT and every finalization after
-- enforcement is fail-closed, so a runtime writer cannot opt into a legacy
-- unverified path.
CREATE OR REPLACE FUNCTION public.enforce_ledger_transaction_insert()
RETURNS TRIGGER AS $$
BEGIN
    IF (NEW).status <> 'DRAFT' OR (NEW).posted_at IS NOT NULL THEN
        RAISE EXCEPTION 'ledger transaction must be inserted as DRAFT';
    END IF;
    IF (NEW).canonical_metadata IS NULL THEN
        RAISE EXCEPTION 'new ledger transaction requires canonical metadata bytes';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE OR REPLACE FUNCTION public.finalize_ledger_transaction(target_transaction_id STRING)
RETURNS STRING AS $$
DECLARE
    target_book_id STRING;
    target_operation_id STRING;
    target_effect_id STRING;
    target_transaction_kind STRING;
    target_reference_transaction_id STRING;
    target_posting_rule_version STRING;
    target_schema_version INT8;
    target_request_hash BYTES;
    target_metadata JSONB;
    target_canonical_metadata BYTES;
    target_sequence_no INT8;
    target_prev_hash BYTES;
    target_entry_hash BYTES;
    target_status STRING;
    target_line_count INT8;
    canonical_hash_input BYTES;
    canonical_line_bytes BYTES;
    calculated_entry_hash BYTES;
    advanced_book_id STRING;
BEGIN
    SELECT book_id, operation_id, effect_id, transaction_kind,
           reference_transaction_id, posting_rule_version, schema_version,
           request_hash, metadata, canonical_metadata, sequence_no, prev_hash,
           entry_hash, status
      INTO target_book_id, target_operation_id, target_effect_id,
           target_transaction_kind, target_reference_transaction_id,
           target_posting_rule_version, target_schema_version,
           target_request_hash, target_metadata, target_canonical_metadata,
           target_sequence_no, target_prev_hash, target_entry_hash,
           target_status
      FROM public.ledger_transactions
     WHERE transaction_id=target_transaction_id
     FOR UPDATE;

    IF target_book_id IS NULL OR target_status <> 'DRAFT' THEN
        RETURN NULL;
    END IF;

    SELECT count(*) INTO target_line_count
      FROM public.ledger_lines
     WHERE transaction_id=target_transaction_id;
    IF target_line_count < 2 THEN
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
            WHERE transaction_id=target_transaction_id) <> target_line_count THEN
        RAISE EXCEPTION 'ledger line numbers must be contiguous from one';
    END IF;

    IF target_canonical_metadata IS NULL THEN
        RAISE EXCEPTION 'ledger finalization requires canonical metadata bytes';
    END IF;
    IF convert_from(target_canonical_metadata, 'UTF8')::JSONB
          IS DISTINCT FROM target_metadata THEN
        RAISE EXCEPTION 'canonical metadata bytes do not represent stored metadata';
    END IF;

    canonical_hash_input :=
        decode('7061796d656e742d706c6174666f726d2f6c65646765722d656e7472792f763100', 'hex')
        || target_prev_hash
        || public.ledger_hash_int64(target_sequence_no)
        || public.ledger_hash_length_prefixed(convert_to(target_transaction_id, 'UTF8'))
        || public.ledger_hash_length_prefixed(convert_to(target_book_id, 'UTF8'))
        || public.ledger_hash_length_prefixed(convert_to(target_operation_id, 'UTF8'))
        || public.ledger_hash_length_prefixed(convert_to(target_effect_id, 'UTF8'))
        || public.ledger_hash_length_prefixed(convert_to(target_transaction_kind, 'UTF8'))
        || public.ledger_hash_length_prefixed(convert_to(target_posting_rule_version, 'UTF8'))
        || public.ledger_hash_int64(target_schema_version);

    IF target_reference_transaction_id IS NULL THEN
        canonical_hash_input := canonical_hash_input || decode('00', 'hex');
    ELSE
        canonical_hash_input := canonical_hash_input
            || decode('01', 'hex')
            || public.ledger_hash_length_prefixed(
                   convert_to(target_reference_transaction_id, 'UTF8'));
    END IF;

    canonical_hash_input := canonical_hash_input
        || target_request_hash
        || public.ledger_hash_length_prefixed(target_canonical_metadata)
        || public.ledger_hash_uint32(target_line_count);

    -- CockroachDB does not implement PL/pgSQL query FOR loops. Encode each
    -- binary line frame as hex, use the aggregate's explicit order, then
    -- decode once. This is byte-for-byte equivalent and cannot inherit an
    -- unspecified physical row order.
    SELECT decode(string_agg(encode(
               public.ledger_hash_int64(line_no)
               || public.ledger_hash_length_prefixed(convert_to(account_id, 'UTF8'))
               || public.ledger_hash_length_prefixed(convert_to(asset_id, 'UTF8'))
               || public.ledger_hash_length_prefixed(convert_to(side, 'UTF8'))
               || public.ledger_hash_length_prefixed(convert_to(memo, 'UTF8'))
               || public.ledger_hash_length_prefixed(
                      convert_to(amount_atoms::STRING, 'UTF8')),
               'hex'), '' ORDER BY line_no), 'hex')
      INTO canonical_line_bytes
      FROM public.ledger_lines
     WHERE transaction_id=target_transaction_id;
    canonical_hash_input := canonical_hash_input || canonical_line_bytes;

    calculated_entry_hash := decode(sha256(canonical_hash_input), 'hex');
    IF calculated_entry_hash IS DISTINCT FROM target_entry_hash THEN
        RAISE EXCEPTION 'ledger entry hash verification failed';
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

REVOKE ALL ON FUNCTION public.enforce_ledger_transaction_insert() FROM public;
REVOKE ALL ON FUNCTION public.finalize_ledger_transaction(STRING) FROM public;
GRANT EXECUTE ON FUNCTION public.finalize_ledger_transaction(STRING) TO ledger_writer;
