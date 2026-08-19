-- Peer-to-peer transfers as a first-class ledger operation.
--
-- A payment is payer → merchant, and merchant accounts are replicated into
-- every book, so a payment never leaves one book. A transfer is customer →
-- customer, and customers are deliberately sharded across books to avoid a
-- global hot journal, so two arbitrary parties usually sit in different books.
--
-- A ledger transaction cannot span books: enforce_ledger_line_insert requires
-- every line's account to belong to the transaction's book, and each book
-- carries its own hash chain. That restriction is not incidental — it is what
-- makes each book independently balanced and independently verifiable — so a
-- transfer must not weaken it.
--
-- The model used here is the one real multi-ledger systems use: each book gets
-- an inter-book settlement account ("due to / due from"), and a cross-book
-- transfer becomes two balanced transactions, one per book:
--
--     book A:  DEBIT payer.available X   CREDIT settlement.A X
--     book B:  DEBIT settlement.B   X   CREDIT payee.available X
--
-- Each book balances on its own. Across books the settlement accounts net to
-- zero for every asset, which is a new invariant this migration makes
-- checkable. Both legs commit in one SERIALIZABLE database transaction, so a
-- transfer is atomic — there is no saga, no compensation and no window in
-- which one side moved and the other did not.
--
-- A same-book transfer is the degenerate case of the same operation: one
-- transaction, DEBIT payer / CREDIT payee, no settlement account involved.

-- ---------------------------------------------------------------------------
-- Capabilities
-- ---------------------------------------------------------------------------

-- Transferring is a distinct authority from authorizing a payment. A principal
-- allowed to move money between customers is not thereby allowed to authorize
-- merchant payments, and vice versa.
ALTER TABLE payment_account_capabilities DROP CONSTRAINT IF EXISTS check_permission;
ALTER TABLE payment_account_capabilities ADD CONSTRAINT check_permission CHECK (
    permission IN (
        'AUTHORIZE_PAYER_AVAILABLE',
        'AUTHORIZE_PAYER_HELD',
        'AUTHORIZE_MERCHANT',
        'CAPTURE_FEE',
        'CAPTURE_TAX',
        'CAPTURE_CASHBACK_EXPENSE',
        'REFUND_MERCHANT_DEBIT',
        'CHARGEBACK_MERCHANT_RESERVE',
        -- Debit a customer's available account as the sender of a transfer.
        'TRANSFER_DEBIT_AVAILABLE',
        -- Credit a customer's available account as the recipient. Held
        -- separately from the debit permission so a compromised sender-side
        -- credential cannot conjure a credit into an account of its choosing.
        'TRANSFER_CREDIT_AVAILABLE'
    )
);

-- ---------------------------------------------------------------------------
-- Inter-book settlement accounts
-- ---------------------------------------------------------------------------

-- One settlement account per (book, asset). It is an ordinary ledger account —
-- it has no special posting rules — but it is registered here so the zero-sum
-- invariant below knows exactly which accounts to add up, rather than
-- inferring membership from a naming convention.
CREATE TABLE IF NOT EXISTS interbook_settlement_accounts (
    book_id    STRING NOT NULL REFERENCES books (book_id),
    asset_id   STRING NOT NULL REFERENCES assets (asset_id),
    account_id STRING NOT NULL REFERENCES accounts (account_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (book_id, asset_id),
    UNIQUE (account_id)
);

-- The invariant that replaces the one a cross-book transfer would otherwise
-- break: every atom that left one book through settlement arrived in another
-- through settlement, so the settlement accounts net to zero for each asset.
--
-- A non-zero residual here is the transfer equivalent of a ledger imbalance
-- and is treated with the same seriousness.
CREATE OR REPLACE VIEW interbook_settlement_residual AS
SELECT settlement.asset_id,
       coalesce(sum(balance.current_balance_atoms), 0) AS residual_atoms,
       count(*) AS settlement_accounts
  FROM interbook_settlement_accounts AS settlement
  LEFT JOIN account_balances AS balance
         ON balance.account_id = settlement.account_id
 GROUP BY settlement.asset_id;

-- ---------------------------------------------------------------------------
-- Transfers
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS transfer_operations (
    transfer_id           STRING PRIMARY KEY,
    -- Idempotency is scoped, exactly as it is for payments: the same key from
    -- two different callers is two different transfers.
    idempotency_scope     STRING NOT NULL,
    idempotency_key       STRING NOT NULL,
    request_hash          BYTES NOT NULL CHECK (length(request_hash) = 32),
    asset_id              STRING NOT NULL REFERENCES assets (asset_id),
    payer_account_id      STRING NOT NULL REFERENCES accounts (account_id),
    payee_account_id      STRING NOT NULL REFERENCES accounts (account_id),
    payer_book_id         STRING NOT NULL REFERENCES books (book_id),
    payee_book_id         STRING NOT NULL REFERENCES books (book_id),
    -- The region whose escrow rights are spent. Both parties must be homed in
    -- it: moving value across regions is the signed rights-transfer protocol's
    -- job, not this one's.
    authority_region      STRING NOT NULL,
    amount_atoms          DECIMAL(38,0) NOT NULL CHECK (amount_atoms > 0),
    -- A transfer is atomic and final the moment it commits. There is no
    -- authorize/capture window, because there is no merchant deciding later
    -- whether to take the money.
    state                 STRING NOT NULL DEFAULT 'SETTLED'
                          CHECK (state IN ('SETTLED', 'REVERSED')),
    -- A reversal is a new transfer in the opposite direction that points at
    -- the original. The original is never edited.
    reference_transfer_id STRING NULL REFERENCES transfer_operations (transfer_id),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (idempotency_scope, idempotency_key),
    -- Paying yourself would net to nothing while still consuming escrow
    -- rights on one side and granting them on the other.
    CONSTRAINT check_distinct_parties CHECK (payer_account_id <> payee_account_id)
);

CREATE INDEX IF NOT EXISTS transfer_operations_payer_idx
    ON transfer_operations (payer_account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS transfer_operations_payee_idx
    ON transfer_operations (payee_account_id, created_at DESC);

-- The legs. A same-book transfer has exactly one row with leg='SINGLE'; a
-- cross-book transfer has exactly two, 'PAYER' and 'PAYEE'.
CREATE TABLE IF NOT EXISTS transfer_effects (
    transfer_effect_id    STRING PRIMARY KEY,
    transfer_id           STRING NOT NULL REFERENCES transfer_operations (transfer_id),
    leg                   STRING NOT NULL CHECK (leg IN ('SINGLE', 'PAYER', 'PAYEE')),
    book_id               STRING NOT NULL REFERENCES books (book_id),
    ledger_transaction_id STRING NOT NULL REFERENCES ledger_transactions (transaction_id),
    amount_atoms          DECIMAL(38,0) NOT NULL CHECK (amount_atoms > 0),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (transfer_id, leg),
    UNIQUE (ledger_transaction_id)
);

-- Transfers and their legs are financial receipts: append-only, like every
-- other record of something that happened.
CREATE OR REPLACE FUNCTION reject_transfer_record_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'transfer legs are immutable';
END;
$$ LANGUAGE PLpgSQL;

DROP TRIGGER IF EXISTS transfer_effects_immutable ON transfer_effects;
CREATE TRIGGER transfer_effects_immutable
BEFORE UPDATE OR DELETE ON transfer_effects
FOR EACH ROW EXECUTE FUNCTION public.reject_transfer_record_mutation();

-- ---------------------------------------------------------------------------
-- Escrow movement bound to a posted transfer
-- ---------------------------------------------------------------------------

-- apply_payment_escrow_effect refuses any effect it cannot link to exactly one
-- posted payment effect. Transfers need the same discipline against their own
-- evidence: an escrow movement is permitted only when a posted transfer leg
-- proves that the corresponding value actually moved, in the right direction,
-- for the right account and the right amount.
--
-- SPEND is paired with a DEBIT of the account and RETURN with a CREDIT, and in
-- both cases the transaction must not also move the account the other way —
-- otherwise a self-cancelling pair of lines could justify a one-way change to
-- spending rights.
CREATE OR REPLACE FUNCTION public.apply_transfer_escrow_effect(
    target_effect_id STRING,
    target_effect_kind STRING,
    target_transfer_id STRING,
    target_account_id STRING,
    target_asset_id STRING,
    target_region STRING,
    target_amount DECIMAL
)
RETURNS BOOL AS $$
DECLARE
    linked_effects INT8;
    inserted_effect_id STRING;
    changed_account_id STRING;
    stored_effect_kind STRING;
    stored_account_id STRING;
    stored_asset_id STRING;
    stored_region STRING;
    stored_amount DECIMAL;
    effect_hash BYTES;
BEGIN
    IF target_effect_kind NOT IN ('SPEND', 'RETURN')
       OR target_effect_id IS NULL OR pg_catalog.length(target_effect_id) NOT BETWEEN 1 AND 512
       OR target_transfer_id IS NULL OR pg_catalog.length(target_transfer_id) = 0
       OR target_account_id IS NULL OR pg_catalog.length(target_account_id) = 0
       OR target_asset_id IS NULL OR pg_catalog.length(target_asset_id) = 0
       OR target_region IS NULL OR pg_catalog.length(target_region) = 0
       OR target_amount IS NULL OR target_amount <= 0
       OR target_amount <> pg_catalog.trunc(target_amount) THEN
        RAISE EXCEPTION 'invalid transfer escrow effect request';
    END IF;

    -- The receipt table is shared with payments, so the hash must be over this
    -- effect's own fields; a transfer effect can never collide with a payment
    -- effect that happens to name the same account and amount.
    effect_hash := pg_catalog.decode(pg_catalog.sha256(
        pg_catalog.convert_to('payment-platform/transfer-escrow-effect/v1', 'UTF8')
        || pg_catalog.convert_to(target_effect_kind, 'UTF8')
        || pg_catalog.convert_to(target_effect_id, 'UTF8')
        || pg_catalog.convert_to(target_transfer_id, 'UTF8')
        || pg_catalog.convert_to(target_account_id, 'UTF8')
        || pg_catalog.convert_to(target_asset_id, 'UTF8')
        || pg_catalog.convert_to(target_region, 'UTF8')
        || pg_catalog.convert_to(target_amount::STRING, 'UTF8')), 'hex');

    stored_effect_kind := NULL;
    SELECT effect_kind, account_id, asset_id, region, amount
      INTO stored_effect_kind, stored_account_id, stored_asset_id,
           stored_region, stored_amount
      FROM public.escrow_effect_receipts
     WHERE effect_id = target_effect_id;
    IF stored_effect_kind IS NOT NULL THEN
        IF stored_effect_kind IS DISTINCT FROM target_effect_kind
           OR stored_account_id IS DISTINCT FROM target_account_id
           OR stored_asset_id IS DISTINCT FROM target_asset_id
           OR stored_region IS DISTINCT FROM target_region
           OR stored_amount IS DISTINCT FROM target_amount THEN
            RAISE EXCEPTION 'escrow effect conflict';
        END IF;
        RETURN false;
    END IF;

    -- The proof. Exactly one posted leg of this transfer must move this
    -- account by this amount in the direction the effect claims.
    SELECT pg_catalog.count(*) INTO linked_effects
      FROM public.transfer_effects AS leg
      JOIN public.transfer_operations AS transfer
        ON transfer.transfer_id = leg.transfer_id
      JOIN public.ledger_transactions AS transaction
        ON transaction.transaction_id = leg.ledger_transaction_id
       AND transaction.status = 'POSTED'
     WHERE leg.transfer_id = target_transfer_id
       AND transfer.asset_id = target_asset_id
       AND transfer.authority_region = target_region
       AND leg.amount_atoms = target_amount
       AND (
           (target_effect_kind = 'SPEND'
            AND transfer.payer_account_id = target_account_id
            AND (SELECT coalesce(pg_catalog.sum(line.amount_atoms), 0)
                   FROM public.ledger_lines AS line
                  WHERE line.transaction_id = transaction.transaction_id
                    AND line.account_id = target_account_id
                    AND line.asset_id = target_asset_id
                    AND line.side = 'DEBIT') = target_amount
            AND NOT EXISTS (
                SELECT 1 FROM public.ledger_lines AS line
                 WHERE line.transaction_id = transaction.transaction_id
                   AND line.account_id = target_account_id
                   AND line.asset_id = target_asset_id
                   AND line.side = 'CREDIT'))
        OR (target_effect_kind = 'RETURN'
            AND transfer.payee_account_id = target_account_id
            AND (SELECT coalesce(pg_catalog.sum(line.amount_atoms), 0)
                   FROM public.ledger_lines AS line
                  WHERE line.transaction_id = transaction.transaction_id
                    AND line.account_id = target_account_id
                    AND line.asset_id = target_asset_id
                    AND line.side = 'CREDIT') = target_amount
            AND NOT EXISTS (
                SELECT 1 FROM public.ledger_lines AS line
                 WHERE line.transaction_id = transaction.transaction_id
                   AND line.account_id = target_account_id
                   AND line.asset_id = target_asset_id
                   AND line.side = 'DEBIT'))
       );
    IF linked_effects <> 1 THEN
        RAISE EXCEPTION 'transfer escrow effect is not linked to one exact posted transfer leg';
    END IF;

    INSERT INTO public.escrow_effect_receipts
        (effect_id, effect_kind, account_id, asset_id, region, amount, request_hash)
    VALUES (target_effect_id, target_effect_kind, target_account_id,
            target_asset_id, target_region, target_amount, effect_hash)
    ON CONFLICT (effect_id) DO NOTHING
    RETURNING effect_id INTO inserted_effect_id;
    IF inserted_effect_id IS NULL THEN
        RETURN false;
    END IF;

    changed_account_id := NULL;
    IF target_effect_kind = 'SPEND' THEN
        UPDATE public.escrow_regional_rights
           SET available = available - target_amount,
               version = version + 1,
               updated_at = pg_catalog.transaction_timestamp()
         WHERE account_id = target_account_id
           AND asset_id = target_asset_id
           AND region = target_region
           AND available >= target_amount
        RETURNING account_id INTO changed_account_id;
        IF changed_account_id IS NULL THEN
            RAISE EXCEPTION 'escrow insufficient rights';
        END IF;

        changed_account_id := NULL;
        UPDATE public.escrow_authorities
           SET total_authority = total_authority - target_amount,
               version = version + 1
         WHERE account_id = target_account_id
           AND asset_id = target_asset_id
           AND total_authority >= target_amount
        RETURNING account_id INTO changed_account_id;
        IF changed_account_id IS NULL THEN
            RAISE EXCEPTION 'escrow authority inconsistent';
        END IF;
    ELSE
        UPDATE public.escrow_regional_rights
           SET available = available + target_amount,
               version = version + 1,
               updated_at = pg_catalog.transaction_timestamp()
         WHERE account_id = target_account_id
           AND asset_id = target_asset_id
           AND region = target_region
        RETURNING account_id INTO changed_account_id;
        IF changed_account_id IS NULL THEN
            RAISE EXCEPTION 'escrow regional authority is missing';
        END IF;

        changed_account_id := NULL;
        UPDATE public.escrow_authorities
           SET total_authority = total_authority + target_amount,
               version = version + 1
         WHERE account_id = target_account_id
           AND asset_id = target_asset_id
        RETURNING account_id INTO changed_account_id;
        IF changed_account_id IS NULL THEN
            RAISE EXCEPTION 'escrow authority is missing';
        END IF;
    END IF;
    RETURN true;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

-- ---------------------------------------------------------------------------
-- Least privilege
-- ---------------------------------------------------------------------------

-- The transfer runtime may move value between customer accounts and nothing
-- else. It cannot create accounts, cannot create money, and cannot touch the
-- payment lifecycle — three separate credential classes, as elsewhere.
CREATE ROLE IF NOT EXISTS transfer_runtime NOLOGIN;
GRANT USAGE ON SCHEMA public TO transfer_runtime;

REVOKE ALL ON TABLE transfer_operations, transfer_effects,
    interbook_settlement_accounts FROM public;
REVOKE EXECUTE ON FUNCTION public.apply_transfer_escrow_effect(
    STRING, STRING, STRING, STRING, STRING, STRING, DECIMAL) FROM public;
REVOKE EXECUTE ON FUNCTION public.reject_transfer_record_mutation() FROM public;

GRANT SELECT ON TABLE assets, books, accounts, account_balances,
    payment_account_capabilities, payment_account_capability_revocations,
    interbook_settlement_accounts TO transfer_runtime;
GRANT INSERT ON TABLE ledger_transactions, ledger_lines TO transfer_runtime;
GRANT EXECUTE ON FUNCTION public.finalize_ledger_transaction(STRING)
    TO transfer_runtime;
-- Escrow is moved only through the linkage-checked function, never by a direct
-- UPDATE: the runtime has no privilege to change spending rights on its own.
GRANT SELECT ON TABLE escrow_authorities, escrow_regional_rights TO transfer_runtime;
GRANT EXECUTE ON FUNCTION public.apply_transfer_escrow_effect(
    STRING, STRING, STRING, STRING, STRING, STRING, DECIMAL) TO transfer_runtime;
GRANT SELECT, INSERT ON TABLE transfer_operations, transfer_effects TO transfer_runtime;
GRANT INSERT ON TABLE outbox_messages TO transfer_runtime;

-- Provisioning owns the creation of settlement accounts, because it is what
-- creates books and accounts in the first place.
GRANT SELECT, INSERT ON TABLE interbook_settlement_accounts TO account_provisioner;

GRANT SELECT ON TABLE transfer_operations, transfer_effects,
    interbook_settlement_accounts TO ledger_reader;
GRANT ALL ON TABLE transfer_operations, transfer_effects,
    interbook_settlement_accounts TO ledger_admin;
