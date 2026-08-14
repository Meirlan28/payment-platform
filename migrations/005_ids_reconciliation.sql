CREATE TABLE IF NOT EXISTS id_issuers (
    issuer_prefix STRING PRIMARY KEY,
    incarnation INT8 NOT NULL CHECK (incarnation > 0),
    next_counter INT8 NOT NULL DEFAULT 1 CHECK (next_counter > 0),
    retired BOOL NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Prefixes are allocated by deployment control-plane and are never reused.
INSERT INTO id_issuers (issuer_prefix, incarnation)
VALUES
    ('pay-a', 1),
    ('pay-b', 1),
    ('pay-c', 1),
    ('ledger', 1),
    ('transfer', 1),
    ('event', 1)
ON CONFLICT (issuer_prefix) DO NOTHING;

CREATE TABLE IF NOT EXISTS reconciliation_runs (
    run_id STRING PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ NULL,
    status STRING NOT NULL CHECK (status IN ('RUNNING', 'PASSED', 'FAILED')),
    verified_book_watermarks JSONB NOT NULL DEFAULT '{}'::JSONB,
    violations JSONB NOT NULL DEFAULT '[]'::JSONB
);

CREATE TABLE IF NOT EXISTS reconciliation_breaks (
    break_id STRING PRIMARY KEY,
    run_id STRING NOT NULL REFERENCES reconciliation_runs (run_id),
    category STRING NOT NULL,
    effect_id STRING NULL,
    asset_id STRING NULL,
    amount_atoms DECIMAL(38,0) NULL,
    details JSONB NOT NULL,
    status STRING NOT NULL DEFAULT 'OPEN'
        CHECK (status IN ('OPEN', 'EXPECTED_LAG', 'CORRECTION_POSTED', 'RESOLVED')),
    correction_transaction_id STRING NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS reconciliation_breaks_open_idx
    ON reconciliation_breaks (category, created_at)
    WHERE status IN ('OPEN', 'EXPECTED_LAG');

CREATE TABLE IF NOT EXISTS cashback_repair_manifests (
    repair_id STRING PRIMARY KEY,
    original_payment_id STRING NOT NULL,
    original_transaction_id STRING NOT NULL,
    posting_rule_version STRING NOT NULL,
    asset_id STRING NOT NULL,
    expected_atoms DECIMAL(38,0) NOT NULL CHECK (expected_atoms >= 0),
    actual_atoms DECIMAL(38,0) NOT NULL CHECK (actual_atoms >= 0),
    excess_atoms DECIMAL(38,0) NOT NULL CHECK (excess_atoms > 0),
    correction_effect_id STRING NOT NULL UNIQUE,
    correction_transaction_id STRING NULL UNIQUE,
    status STRING NOT NULL DEFAULT 'PLANNED'
        CHECK (status IN ('PLANNED', 'POSTED', 'WAIVED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (actual_atoms = expected_atoms + excess_atoms)
);
