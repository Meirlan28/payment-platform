-- Correctness-critical CockroachDB 26.2 schema.
--
-- All monetary values are DECIMAL(38,0) atomic units.  A transaction is
-- first assembled as DRAFT and can have exactly one state transition to POSTED.
-- The transition is the database-side commit point: triggers validate the
-- journal, advance the per-book hash-chain head, and update balances.  Runtime
-- roles cannot UPDATE or DELETE journal lines or mutate a posted transaction.

CREATE TABLE IF NOT EXISTS assets (
    asset_id                 STRING PRIMARY KEY,
    display_code             STRING NOT NULL,
    atomic_scale             INT8 NOT NULL CHECK (atomic_scale BETWEEN 0 AND 18),
    status                   STRING NOT NULL DEFAULT 'ACTIVE'
                             CHECK (status IN ('ACTIVE', 'CLOSED_FOR_NEW_BUSINESS')),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (display_code)
);

CREATE TABLE IF NOT EXISTS books (
    book_id                  STRING PRIMARY KEY,
    legal_entity_id          STRING NOT NULL,
    jurisdiction             STRING NOT NULL,
    next_sequence_no         INT8 NOT NULL DEFAULT 1 CHECK (next_sequence_no > 0),
    last_entry_hash          BYTES NOT NULL CHECK (length(last_entry_hash) = 32),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE IF NOT EXISTS accounts (
    account_id               STRING PRIMARY KEY,
    book_id                  STRING NOT NULL REFERENCES books (book_id),
    asset_id                 STRING NOT NULL REFERENCES assets (asset_id),
    account_type             STRING NOT NULL,
    normal_side              STRING NOT NULL CHECK (normal_side IN ('DEBIT', 'CREDIT')),
    enforce_spend_limit      BOOL NOT NULL DEFAULT false,
    credit_limit_atoms       DECIMAL(38,0) NOT NULL DEFAULT 0 CHECK (credit_limit_atoms >= 0),
    status                   STRING NOT NULL DEFAULT 'ACTIVE'
                             CHECK (status IN ('ACTIVE', 'CLOSED')),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (book_id, account_id)
);

-- This is a projection of the immutable journal, not an independent source of
-- truth.  It is maintained only by the posting trigger.
CREATE TABLE IF NOT EXISTS account_balances (
    account_id               STRING PRIMARY KEY REFERENCES accounts (account_id),
    debit_atoms              DECIMAL(38,0) NOT NULL DEFAULT 0 CHECK (debit_atoms >= 0),
    credit_atoms             DECIMAL(38,0) NOT NULL DEFAULT 0 CHECK (credit_atoms >= 0),
    current_balance_atoms    DECIMAL(38,0) NOT NULL DEFAULT 0,
    last_sequence_no         INT8 NOT NULL DEFAULT 0 CHECK (last_sequence_no >= 0),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE IF NOT EXISTS ledger_transactions (
    transaction_id           STRING PRIMARY KEY,
    book_id                  STRING NOT NULL REFERENCES books (book_id),
    operation_id             STRING NOT NULL,
    effect_id                STRING NOT NULL UNIQUE,
    transaction_kind         STRING NOT NULL,
    reference_transaction_id STRING NULL REFERENCES ledger_transactions (transaction_id),
    posting_rule_version     STRING NOT NULL,
    schema_version           INT8 NOT NULL DEFAULT 1 CHECK (schema_version > 0),
    request_hash             BYTES NOT NULL CHECK (length(request_hash) = 32),
    metadata                 JSONB NOT NULL DEFAULT '{}'::JSONB,
    status                   STRING NOT NULL DEFAULT 'DRAFT'
                             CHECK (status IN ('DRAFT', 'POSTED')),
    sequence_no              INT8 NOT NULL CHECK (sequence_no > 0),
    prev_hash                BYTES NOT NULL CHECK (length(prev_hash) = 32),
    entry_hash               BYTES NOT NULL CHECK (length(entry_hash) = 32),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    posted_at                TIMESTAMPTZ NULL
);

-- Concurrent DRAFT builders may observe the same chain head. Only one can win
-- the books compare-and-swap; uniqueness is required at the POSTED boundary.
CREATE UNIQUE INDEX IF NOT EXISTS ledger_transactions_posted_sequence_uq
    ON ledger_transactions (book_id, sequence_no)
    WHERE status = 'POSTED';

CREATE INDEX IF NOT EXISTS ledger_transactions_operation_idx
    ON ledger_transactions (operation_id);
CREATE INDEX IF NOT EXISTS ledger_transactions_reference_idx
    ON ledger_transactions (reference_transaction_id)
    WHERE reference_transaction_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS ledger_lines (
    transaction_id           STRING NOT NULL REFERENCES ledger_transactions (transaction_id),
    line_no                  INT8 NOT NULL CHECK (line_no > 0),
    account_id               STRING NOT NULL REFERENCES accounts (account_id),
    asset_id                 STRING NOT NULL REFERENCES assets (asset_id),
    side                     STRING NOT NULL CHECK (side IN ('DEBIT', 'CREDIT')),
    amount_atoms             DECIMAL(38,0) NOT NULL CHECK (amount_atoms > 0),
    memo                     STRING NOT NULL DEFAULT '',
    PRIMARY KEY (transaction_id, line_no)
);

CREATE INDEX IF NOT EXISTS ledger_lines_account_idx
    ON ledger_lines (account_id, transaction_id);

CREATE TABLE IF NOT EXISTS payment_operations (
    payment_id               STRING PRIMARY KEY,
    idempotency_scope        STRING NOT NULL,
    idempotency_key          STRING NOT NULL,
    asset_id                 STRING NOT NULL REFERENCES assets (asset_id),
    customer_available_account_id STRING NOT NULL REFERENCES accounts (account_id),
    customer_held_account_id STRING NOT NULL REFERENCES accounts (account_id),
    merchant_account_id      STRING NULL REFERENCES accounts (account_id),
    authority_region         STRING NULL,
    state                    STRING NOT NULL DEFAULT 'CREATED' CHECK (state IN (
                                 'CREATED', 'AUTHORIZED', 'HELD',
                                 'PARTIALLY_CAPTURED', 'CAPTURED', 'SETTLED',
                                 'PARTIALLY_REFUNDED', 'REFUNDED', 'REVERSED',
                                 'DISPUTED', 'CHARGED_BACK', 'FAILED', 'UNKNOWN'
                             )),
    authorized_atoms         DECIMAL(38,0) NOT NULL CHECK (authorized_atoms > 0),
    captured_atoms           DECIMAL(38,0) NOT NULL DEFAULT 0 CHECK (captured_atoms >= 0),
    released_atoms           DECIMAL(38,0) NOT NULL DEFAULT 0 CHECK (released_atoms >= 0),
    refunded_atoms           DECIMAL(38,0) NOT NULL DEFAULT 0 CHECK (refunded_atoms >= 0),
    charged_back_atoms       DECIMAL(38,0) NOT NULL DEFAULT 0 CHECK (charged_back_atoms >= 0),
    fee_atoms                DECIMAL(38,0) NOT NULL DEFAULT 0 CHECK (fee_atoms >= 0),
    tax_atoms                DECIMAL(38,0) NOT NULL DEFAULT 0 CHECK (tax_atoms >= 0),
    cashback_atoms           DECIMAL(38,0) NOT NULL DEFAULT 0 CHECK (cashback_atoms >= 0),
    cashback_rule_atoms      DECIMAL(38,0) NOT NULL DEFAULT 0 CHECK (cashback_rule_atoms >= 0),
    version                  INT8 NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (idempotency_scope, idempotency_key),
    CHECK (captured_atoms + released_atoms <= authorized_atoms),
    CHECK (refunded_atoms + charged_back_atoms <= captured_atoms),
    CHECK (fee_atoms + tax_atoms <= captured_atoms)
    ,CHECK (cashback_atoms <= cashback_rule_atoms)
);

CREATE TABLE IF NOT EXISTS holds (
    hold_id                  STRING PRIMARY KEY,
    payment_id               STRING NOT NULL UNIQUE REFERENCES payment_operations (payment_id),
    authorization_transaction_id STRING NOT NULL UNIQUE REFERENCES ledger_transactions (transaction_id),
    authorization_atoms      DECIMAL(38,0) NOT NULL CHECK (authorization_atoms > 0),
    captured_atoms           DECIMAL(38,0) NOT NULL DEFAULT 0 CHECK (captured_atoms >= 0),
    released_atoms           DECIMAL(38,0) NOT NULL DEFAULT 0 CHECK (released_atoms >= 0),
    state                    STRING NOT NULL DEFAULT 'ACTIVE'
                             CHECK (state IN ('ACTIVE', 'PARTIALLY_CAPTURED', 'CAPTURED', 'RELEASED')),
    version                  INT8 NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    CHECK (captured_atoms + released_atoms <= authorization_atoms)
);

-- Immutable relationship between the payment lifecycle and journal effects.
-- Mutable aggregate counters live on payment_operations/holds; facts live here.
CREATE TABLE IF NOT EXISTS payment_effects (
    payment_effect_id        STRING PRIMARY KEY,
    payment_id               STRING NOT NULL REFERENCES payment_operations (payment_id),
    effect_kind              STRING NOT NULL CHECK (effect_kind IN (
                                 'HOLD', 'CAPTURE', 'RELEASE', 'REVERSAL',
                                 'REFUND', 'CHARGEBACK', 'FEE', 'TAX', 'CASHBACK'
    )),
    amount_atoms             DECIMAL(38,0) NOT NULL CHECK (amount_atoms > 0),
    ledger_transaction_id    STRING NOT NULL REFERENCES ledger_transactions (transaction_id),
    original_transaction_id  STRING NULL REFERENCES ledger_transactions (transaction_id),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (payment_id, payment_effect_id)
);

CREATE INDEX IF NOT EXISTS payment_effects_payment_idx
    ON payment_effects (payment_id, created_at);
CREATE INDEX IF NOT EXISTS payment_effects_ledger_transaction_idx
    ON payment_effects (ledger_transaction_id);

CREATE TABLE IF NOT EXISTS fx_quotes (
    quote_id                 STRING PRIMARY KEY,
    base_asset_id            STRING NOT NULL REFERENCES assets (asset_id),
    quote_asset_id           STRING NOT NULL REFERENCES assets (asset_id),
    rate_numerator           DECIMAL(38,0) NOT NULL CHECK (rate_numerator > 0),
    rate_denominator         DECIMAL(38,0) NOT NULL CHECK (rate_denominator > 0),
    base_amount_atoms        DECIMAL(38,0) NOT NULL CHECK (base_amount_atoms > 0),
    quote_amount_atoms       DECIMAL(38,0) NOT NULL CHECK (quote_amount_atoms > 0),
    rounding_rule            STRING NOT NULL
                             CHECK (rounding_rule IN ('FLOOR', 'CEILING', 'HALF_EVEN')),
    expires_at               TIMESTAMPTZ NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    CHECK (base_asset_id <> quote_asset_id)
);

CREATE TABLE IF NOT EXISTS fx_quote_consumptions (
    quote_id                 STRING PRIMARY KEY REFERENCES fx_quotes (quote_id),
    effect_id                STRING NOT NULL UNIQUE,
    ledger_transaction_id    STRING NOT NULL UNIQUE REFERENCES ledger_transactions (transaction_id),
    consumed_at              TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE IF NOT EXISTS idempotency_records (
    scope                    STRING NOT NULL,
    idempotency_key          STRING NOT NULL,
    request_hash             BYTES NOT NULL CHECK (length(request_hash) = 32),
    state                    STRING NOT NULL CHECK (state IN ('PROCESSING', 'SUCCEEDED', 'FAILED')),
    owner_token              STRING NOT NULL,
    lease_expires_at         TIMESTAMPTZ NOT NULL,
    operation_id             STRING NOT NULL,
    ledger_transaction_id    STRING NULL REFERENCES ledger_transactions (transaction_id),
    response_code            INT8 NULL,
    response_payload         JSONB NULL,
    failure_code             STRING NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (scope, idempotency_key),
    CHECK (
        (state = 'PROCESSING' AND response_payload IS NULL AND failure_code IS NULL)
        OR (state = 'SUCCEEDED' AND response_payload IS NOT NULL AND failure_code IS NULL)
        OR (state = 'FAILED' AND failure_code IS NOT NULL)
    )
);

-- A journal transaction must be born as DRAFT.  This closes the INSERT ...
-- status='POSTED' path that would otherwise bypass the posting triggers.
CREATE OR REPLACE FUNCTION enforce_ledger_transaction_insert()
RETURNS TRIGGER AS $$
BEGIN
    IF (NEW).status <> 'DRAFT' OR (NEW).posted_at IS NOT NULL THEN
        RAISE EXCEPTION 'ledger transaction must be inserted as DRAFT';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER ledger_transaction_insert_is_draft
BEFORE INSERT ON ledger_transactions
FOR EACH ROW
EXECUTE FUNCTION enforce_ledger_transaction_insert();

CREATE OR REPLACE FUNCTION enforce_ledger_line_insert()
RETURNS TRIGGER AS $$
DECLARE
    parent_status STRING;
    parent_book STRING;
    account_book STRING;
    account_asset STRING;
BEGIN
    SELECT status, book_id INTO parent_status, parent_book
      FROM ledger_transactions
     WHERE transaction_id = (NEW).transaction_id;

    IF parent_status IS NULL OR parent_status <> 'DRAFT' THEN
        RAISE EXCEPTION 'ledger lines may only be appended to a DRAFT transaction';
    END IF;

    SELECT book_id, asset_id INTO account_book, account_asset
      FROM accounts
     WHERE account_id = (NEW).account_id;

    IF account_book IS NULL OR account_book <> parent_book THEN
        RAISE EXCEPTION 'ledger line account belongs to a different book';
    END IF;
    IF account_asset <> (NEW).asset_id THEN
        RAISE EXCEPTION 'ledger line asset does not match account asset';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER ledger_line_insert_only_on_draft
BEFORE INSERT ON ledger_lines
FOR EACH ROW
EXECUTE FUNCTION enforce_ledger_line_insert();

CREATE OR REPLACE FUNCTION reject_ledger_line_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'ledger lines are append-only';
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER ledger_line_no_update
BEFORE UPDATE ON ledger_lines
FOR EACH ROW
EXECUTE FUNCTION reject_ledger_line_mutation();

CREATE TRIGGER ledger_line_no_delete
BEFORE DELETE ON ledger_lines
FOR EACH ROW
EXECUTE FUNCTION reject_ledger_line_mutation();

-- Validate the whole staged transaction at the only permitted state change.
-- The UPDATE of books is a compare-and-swap on the per-book audit-chain head.
CREATE OR REPLACE FUNCTION validate_ledger_post()
RETURNS TRIGGER AS $$
DECLARE
    chain_rows INT8 := 0;
BEGIN
    IF (OLD).status <> 'DRAFT' OR (NEW).status <> 'POSTED' THEN
        RAISE EXCEPTION 'only DRAFT to POSTED ledger transition is permitted';
    END IF;

    IF (OLD).transaction_id IS DISTINCT FROM (NEW).transaction_id
       OR (OLD).book_id IS DISTINCT FROM (NEW).book_id
       OR (OLD).operation_id IS DISTINCT FROM (NEW).operation_id
       OR (OLD).effect_id IS DISTINCT FROM (NEW).effect_id
       OR (OLD).transaction_kind IS DISTINCT FROM (NEW).transaction_kind
       OR (OLD).reference_transaction_id IS DISTINCT FROM (NEW).reference_transaction_id
       OR (OLD).posting_rule_version IS DISTINCT FROM (NEW).posting_rule_version
       OR (OLD).schema_version IS DISTINCT FROM (NEW).schema_version
       OR (OLD).request_hash IS DISTINCT FROM (NEW).request_hash
       OR (OLD).metadata IS DISTINCT FROM (NEW).metadata
       OR (OLD).sequence_no IS DISTINCT FROM (NEW).sequence_no
       OR (OLD).prev_hash IS DISTINCT FROM (NEW).prev_hash
       OR (OLD).entry_hash IS DISTINCT FROM (NEW).entry_hash
       OR (OLD).created_at IS DISTINCT FROM (NEW).created_at
       OR (NEW).posted_at IS NULL THEN
        RAISE EXCEPTION 'immutable ledger transaction header was changed while posting';
    END IF;

    IF (SELECT count(*) FROM ledger_lines
         WHERE transaction_id = (NEW).transaction_id) < 2 THEN
        RAISE EXCEPTION 'a posted ledger transaction requires at least two lines';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM ledger_lines
         WHERE transaction_id = (NEW).transaction_id
         GROUP BY asset_id
        HAVING sum(CASE WHEN side = 'DEBIT' THEN amount_atoms ELSE 0 END)
             <> sum(CASE WHEN side = 'CREDIT' THEN amount_atoms ELSE 0 END)
    ) THEN
        RAISE EXCEPTION 'ledger transaction is not balanced for every asset';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM ledger_lines AS line
          JOIN accounts AS account ON account.account_id = line.account_id
         WHERE line.transaction_id = (NEW).transaction_id
           AND (line.asset_id <> account.asset_id OR account.book_id <> (NEW).book_id)
    ) THEN
        RAISE EXCEPTION 'ledger line account/book/asset mismatch';
    END IF;

    IF (SELECT min(line_no) FROM ledger_lines
         WHERE transaction_id = (NEW).transaction_id) <> 1
       OR (SELECT max(line_no) FROM ledger_lines
            WHERE transaction_id = (NEW).transaction_id)
          <> (SELECT count(*) FROM ledger_lines
               WHERE transaction_id = (NEW).transaction_id) THEN
        RAISE EXCEPTION 'ledger line numbers must be contiguous from one';
    END IF;

    UPDATE books
       SET next_sequence_no = next_sequence_no + 1,
           last_entry_hash = (NEW).entry_hash
     WHERE book_id = (NEW).book_id
       AND next_sequence_no = (NEW).sequence_no
       AND last_entry_hash = (NEW).prev_hash
    RETURNING 1 INTO chain_rows;
    IF chain_rows IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'ledger hash-chain compare-and-swap failed';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

CREATE TRIGGER ledger_transaction_validate_post
BEFORE UPDATE ON ledger_transactions
FOR EACH ROW
EXECUTE FUNCTION validate_ledger_post();

-- The materialized balance update is part of the same SQL transaction.  Any
-- spend-limit exception aborts the journal post and the chain-head advance.
CREATE OR REPLACE FUNCTION apply_posted_ledger_balances()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO account_balances (
        account_id,
        debit_atoms,
        credit_atoms,
        current_balance_atoms,
        last_sequence_no,
        updated_at
    )
    SELECT line.account_id,
           sum(CASE WHEN line.side = 'DEBIT' THEN line.amount_atoms ELSE 0 END)::DECIMAL(38,0),
           sum(CASE WHEN line.side = 'CREDIT' THEN line.amount_atoms ELSE 0 END)::DECIMAL(38,0),
           CASE account.normal_side
             WHEN 'DEBIT' THEN
                 (sum(CASE WHEN line.side = 'DEBIT' THEN line.amount_atoms ELSE 0 END)
                - sum(CASE WHEN line.side = 'CREDIT' THEN line.amount_atoms ELSE 0 END))::DECIMAL(38,0)
             ELSE
                 (sum(CASE WHEN line.side = 'CREDIT' THEN line.amount_atoms ELSE 0 END)
                - sum(CASE WHEN line.side = 'DEBIT' THEN line.amount_atoms ELSE 0 END))::DECIMAL(38,0)
           END,
           (NEW).sequence_no,
           transaction_timestamp()
      FROM ledger_lines AS line
      JOIN accounts AS account ON account.account_id = line.account_id
     WHERE line.transaction_id = (NEW).transaction_id
     GROUP BY line.account_id, account.normal_side
    ON CONFLICT (account_id) DO UPDATE
        SET debit_atoms = account_balances.debit_atoms + excluded.debit_atoms,
            credit_atoms = account_balances.credit_atoms + excluded.credit_atoms,
            current_balance_atoms = account_balances.current_balance_atoms
                                  + excluded.current_balance_atoms,
            last_sequence_no = greatest(account_balances.last_sequence_no,
                                        excluded.last_sequence_no),
            updated_at = excluded.updated_at;

    IF EXISTS (
        SELECT 1
          FROM account_balances AS balance
          JOIN accounts AS account ON account.account_id = balance.account_id
         WHERE account.enforce_spend_limit
           AND balance.current_balance_atoms < -account.credit_limit_atoms
           AND balance.account_id IN (
               SELECT account_id FROM ledger_lines
                WHERE transaction_id = (NEW).transaction_id
           )
    ) THEN
        RAISE EXCEPTION 'posting exceeds available balance plus explicit credit';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

CREATE TRIGGER ledger_transaction_apply_balances
AFTER UPDATE ON ledger_transactions
FOR EACH ROW
WHEN ((OLD).status = 'DRAFT' AND (NEW).status = 'POSTED')
EXECUTE FUNCTION apply_posted_ledger_balances();

CREATE OR REPLACE FUNCTION reject_posted_ledger_mutation()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' OR (OLD).status = 'POSTED' THEN
        RAISE EXCEPTION 'posted ledger transactions are immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

-- Alphabetical trigger ordering makes ledger_transaction_reject_immutable run
-- after ledger_transaction_validate_post for the valid DRAFT -> POSTED update.
CREATE TRIGGER ledger_transaction_reject_immutable
BEFORE UPDATE ON ledger_transactions
FOR EACH ROW
WHEN ((OLD).status = 'POSTED')
EXECUTE FUNCTION reject_posted_ledger_mutation();

CREATE TRIGGER ledger_transaction_no_delete
BEFORE DELETE ON ledger_transactions
FOR EACH ROW
EXECUTE FUNCTION reject_posted_ledger_mutation();

CREATE OR REPLACE FUNCTION payment_state_transition_allowed(old_state STRING, new_state STRING)
RETURNS BOOL
LANGUAGE SQL
IMMUTABLE
AS $$
    SELECT old_state = new_state OR CASE old_state
      WHEN 'CREATED' THEN new_state IN ('AUTHORIZED', 'HELD', 'FAILED', 'UNKNOWN')
      WHEN 'AUTHORIZED' THEN new_state IN ('HELD', 'CAPTURED', 'REVERSED', 'FAILED', 'UNKNOWN')
      WHEN 'HELD' THEN new_state IN ('PARTIALLY_CAPTURED', 'CAPTURED', 'REVERSED', 'UNKNOWN')
      WHEN 'PARTIALLY_CAPTURED' THEN new_state IN ('CAPTURED', 'REVERSED', 'UNKNOWN')
      WHEN 'CAPTURED' THEN new_state IN ('SETTLED', 'PARTIALLY_REFUNDED', 'REFUNDED', 'DISPUTED', 'UNKNOWN')
      WHEN 'SETTLED' THEN new_state IN ('PARTIALLY_REFUNDED', 'REFUNDED', 'DISPUTED')
      WHEN 'PARTIALLY_REFUNDED' THEN new_state IN ('REFUNDED', 'DISPUTED')
      WHEN 'DISPUTED' THEN new_state IN ('CHARGED_BACK', 'SETTLED', 'PARTIALLY_REFUNDED', 'REFUNDED')
      WHEN 'UNKNOWN' THEN new_state IN ('AUTHORIZED', 'HELD', 'CAPTURED', 'SETTLED', 'FAILED', 'REVERSED')
      ELSE false
    END
$$;

CREATE OR REPLACE FUNCTION validate_payment_update()
RETURNS TRIGGER AS $$
BEGIN
    IF NOT payment_state_transition_allowed((OLD).state, (NEW).state) THEN
        RAISE EXCEPTION 'invalid payment state transition: % to %', (OLD).state, (NEW).state;
    END IF;
    IF (OLD).payment_id IS DISTINCT FROM (NEW).payment_id
       OR (OLD).idempotency_scope IS DISTINCT FROM (NEW).idempotency_scope
       OR (OLD).idempotency_key IS DISTINCT FROM (NEW).idempotency_key
       OR (OLD).asset_id IS DISTINCT FROM (NEW).asset_id
       OR (OLD).customer_available_account_id IS DISTINCT FROM (NEW).customer_available_account_id
       OR (OLD).customer_held_account_id IS DISTINCT FROM (NEW).customer_held_account_id
       OR (OLD).merchant_account_id IS DISTINCT FROM (NEW).merchant_account_id
       OR (OLD).authority_region IS DISTINCT FROM (NEW).authority_region
       OR (OLD).authorized_atoms IS DISTINCT FROM (NEW).authorized_atoms
       OR (NEW).captured_atoms < (OLD).captured_atoms
       OR (NEW).released_atoms < (OLD).released_atoms
       OR (NEW).refunded_atoms < (OLD).refunded_atoms
       OR (NEW).charged_back_atoms < (OLD).charged_back_atoms
       OR (NEW).fee_atoms < (OLD).fee_atoms
       OR (NEW).tax_atoms < (OLD).tax_atoms
       OR (NEW).cashback_atoms < (OLD).cashback_atoms
       OR (OLD).cashback_rule_atoms IS DISTINCT FROM (NEW).cashback_rule_atoms
       OR (NEW).version <> (OLD).version + 1 THEN
        RAISE EXCEPTION 'payment identity/counters are immutable or monotonic';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER payment_validate_update
BEFORE UPDATE ON payment_operations
FOR EACH ROW
EXECUTE FUNCTION validate_payment_update();

CREATE OR REPLACE FUNCTION validate_hold_update()
RETURNS TRIGGER AS $$
BEGIN
    IF (OLD).hold_id IS DISTINCT FROM (NEW).hold_id
       OR (OLD).payment_id IS DISTINCT FROM (NEW).payment_id
       OR (OLD).authorization_transaction_id IS DISTINCT FROM (NEW).authorization_transaction_id
       OR (OLD).authorization_atoms IS DISTINCT FROM (NEW).authorization_atoms
       OR (NEW).captured_atoms < (OLD).captured_atoms
       OR (NEW).released_atoms < (OLD).released_atoms
       OR (NEW).version <> (OLD).version + 1 THEN
        RAISE EXCEPTION 'hold identity/counters are immutable or monotonic';
    END IF;
    IF (OLD).state = 'CAPTURED' OR (OLD).state = 'RELEASED' THEN
        RAISE EXCEPTION 'terminal hold cannot be changed';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER hold_validate_update
BEFORE UPDATE ON holds
FOR EACH ROW
EXECUTE FUNCTION validate_hold_update();

CREATE OR REPLACE FUNCTION reject_row_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'row is immutable';
END;
$$ LANGUAGE PLpgSQL;

CREATE TRIGGER fx_quote_no_update
BEFORE UPDATE ON fx_quotes
FOR EACH ROW
EXECUTE FUNCTION reject_row_mutation();
CREATE TRIGGER fx_quote_no_delete
BEFORE DELETE ON fx_quotes
FOR EACH ROW
EXECUTE FUNCTION reject_row_mutation();
CREATE TRIGGER fx_consumption_no_update
BEFORE UPDATE ON fx_quote_consumptions
FOR EACH ROW
EXECUTE FUNCTION reject_row_mutation();
CREATE TRIGGER fx_consumption_no_delete
BEFORE DELETE ON fx_quote_consumptions
FOR EACH ROW
EXECUTE FUNCTION reject_row_mutation();
CREATE TRIGGER payment_effect_no_update
BEFORE UPDATE ON payment_effects
FOR EACH ROW
EXECUTE FUNCTION reject_row_mutation();
CREATE TRIGGER payment_effect_no_delete
BEFORE DELETE ON payment_effects
FOR EACH ROW
EXECUTE FUNCTION reject_row_mutation();

-- Runtime roles deliberately receive no DELETE privilege on financial tables
-- and no direct UPDATE privilege on ledger lines, books, or balances.
CREATE ROLE IF NOT EXISTS ledger_admin NOLOGIN;
CREATE ROLE IF NOT EXISTS ledger_writer NOLOGIN;
CREATE ROLE IF NOT EXISTS ledger_reader NOLOGIN;
CREATE ROLE IF NOT EXISTS ledger_auditor NOLOGIN;

REVOKE CREATE ON SCHEMA public FROM public;
GRANT USAGE ON SCHEMA public TO ledger_admin, ledger_writer, ledger_reader, ledger_auditor;

REVOKE ALL ON TABLE assets, books, accounts, account_balances,
    ledger_transactions, ledger_lines, payment_operations, holds, fx_quotes,
    payment_effects, fx_quote_consumptions, idempotency_records
    FROM public;

GRANT ALL ON TABLE assets, books, accounts, account_balances,
    ledger_transactions, ledger_lines, payment_operations, holds, fx_quotes,
    payment_effects, fx_quote_consumptions, idempotency_records
    TO ledger_admin;

GRANT SELECT ON TABLE assets, books, accounts, account_balances,
    ledger_transactions, ledger_lines, payment_operations, holds, fx_quotes,
    payment_effects, fx_quote_consumptions, idempotency_records
    TO ledger_reader, ledger_writer;

GRANT INSERT, UPDATE ON TABLE ledger_transactions TO ledger_writer;
GRANT INSERT ON TABLE ledger_lines, payment_effects, fx_quotes, fx_quote_consumptions
    TO ledger_writer;
GRANT INSERT, UPDATE ON TABLE payment_operations, holds, idempotency_records
    TO ledger_writer;

GRANT SELECT ON TABLE assets, books, accounts, account_balances,
    ledger_transactions, ledger_lines, payment_operations, holds, fx_quotes,
    payment_effects, fx_quote_consumptions TO ledger_auditor;

REVOKE EXECUTE ON FUNCTION enforce_ledger_transaction_insert() FROM public;
REVOKE EXECUTE ON FUNCTION enforce_ledger_line_insert() FROM public;
REVOKE EXECUTE ON FUNCTION reject_ledger_line_mutation() FROM public;
REVOKE EXECUTE ON FUNCTION validate_ledger_post() FROM public;
REVOKE EXECUTE ON FUNCTION apply_posted_ledger_balances() FROM public;
REVOKE EXECUTE ON FUNCTION reject_posted_ledger_mutation() FROM public;
REVOKE EXECUTE ON FUNCTION validate_payment_update() FROM public;
REVOKE EXECUTE ON FUNCTION validate_hold_update() FROM public;
REVOKE EXECUTE ON FUNCTION reject_row_mutation() FROM public;
