-- Expand phase for database-side ledger hash verification. Existing rows stay
-- readable and verifiable with the v1 Go auditor; new writers populate the
-- exact UTF-8 bytes which they used as the metadata component of entry_hash.
-- Enforcement is intentionally a later migration so CockroachDB observes the
-- new descriptor before compiling the replacement trigger/finalizer.

ALTER TABLE ledger_transactions
    ADD COLUMN IF NOT EXISTS canonical_metadata BYTES NULL;

COMMENT ON COLUMN ledger_transactions.canonical_metadata IS
    'Exact UTF-8 JSON bytes hashed by ledger-entry/v1; NULL only on rows created before hash-verification enforcement';
