-- Contract assertion for the capture link introduced by migration 014. The
-- statement-by-statement schema migrator executes ADD COLUMN, backfill and
-- constraint creation as separate implicit CockroachDB transactions. Repeating
-- these validations is idempotent and makes an incomplete legacy 014 fail
-- closed before later binaries are admitted.

ALTER TABLE cashback_repair_manifests
    ALTER COLUMN capture_transaction_id SET NOT NULL;

ALTER TABLE cashback_repair_manifests
    VALIDATE CONSTRAINT cashback_repair_capture_fk;

COMMENT ON COLUMN cashback_repair_manifests.capture_transaction_id IS
    'Immutable capture authority whose per-capture counters bound correction value';
