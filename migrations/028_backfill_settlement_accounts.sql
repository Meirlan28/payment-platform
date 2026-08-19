-- Backfill inter-book settlement accounts for books that already exist.
--
-- Migration 027 made provisioning create a settlement account with every book,
-- which covers books opened from now on. Books that already existed have none,
-- and a transfer into one of them would be refused for a reason the customer
-- cannot act on and did not cause.
--
-- Relying on the next customer to be provisioned into such a book is not a
-- backfill: a book that stops receiving new customers would stay unreachable
-- indefinitely, and which books those are is not knowable in advance.
--
-- The account is created directly rather than through the ledger service
-- because an account is an ordinary row — it carries no journal entry and does
-- not touch a book's hash chain, so there is nothing here that could make the
-- chain disagree with itself.

INSERT INTO accounts (
    account_id, book_id, asset_id, account_type, normal_side,
    enforce_spend_limit, credit_limit_atoms
)
SELECT DISTINCT
    'settlement_' || account.book_id || '_' || account.asset_id,
    account.book_id,
    account.asset_id,
    'INTERBOOK_SETTLEMENT',
    'CREDIT',
    -- Deliberately not spend-limited: a settlement account records a position
    -- against peer books and is expected to be negative in whichever book has
    -- sent more than it has received.
    false,
    0
  FROM accounts AS account
 WHERE account.account_type <> 'INTERBOOK_SETTLEMENT'
ON CONFLICT (account_id) DO NOTHING;

INSERT INTO account_balances (account_id)
SELECT account_id FROM accounts WHERE account_type = 'INTERBOOK_SETTLEMENT'
ON CONFLICT (account_id) DO NOTHING;

INSERT INTO interbook_settlement_accounts (book_id, asset_id, account_id)
SELECT book_id, asset_id, account_id
  FROM accounts WHERE account_type = 'INTERBOOK_SETTLEMENT'
ON CONFLICT (book_id, asset_id) DO NOTHING;

-- Transfer permissions are deliberately NOT backfilled here.
--
-- The obvious shortcut is to copy every AUTHORIZE_PAYER_AVAILABLE grant into a
-- pair of transfer grants for the same principal. That would work, and it
-- would quietly hand transfer authority to the payment principal — which is
-- precisely the widening that keeping the two credential classes disjoint
-- exists to prevent.
--
-- A capability names a principal, and which principal should hold transfer
-- authority for a cell is a deployment decision this file cannot see. It is
-- therefore made explicitly, by provisioning for new wallets and by an
-- operator-run grant for existing ones, where it is recorded against a named
-- principal rather than inferred.
