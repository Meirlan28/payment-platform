-- Durable distributed-protocol state.  All identifiers are supplied by the
-- application; none of the correctness protocols depend on wall-clock order.

CREATE TABLE IF NOT EXISTS escrow_authorities (
    account_id       STRING NOT NULL,
    asset_id         STRING NOT NULL,
    total_authority  DECIMAL(38,0) NOT NULL CHECK (total_authority >= 0),
    unallocated      DECIMAL(38,0) NOT NULL CHECK (unallocated >= 0),
    version          INT8 NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, asset_id),
    CHECK (unallocated <= total_authority)
);

CREATE TABLE IF NOT EXISTS escrow_regional_rights (
    account_id  STRING NOT NULL,
    asset_id    STRING NOT NULL,
    region      STRING NOT NULL,
    available   DECIMAL(38,0) NOT NULL CHECK (available >= 0),
    version     INT8 NOT NULL DEFAULT 0 CHECK (version >= 0),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, asset_id, region),
    FOREIGN KEY (account_id, asset_id)
        REFERENCES escrow_authorities (account_id, asset_id)
);

CREATE TABLE IF NOT EXISTS escrow_transfers (
    transfer_id        STRING PRIMARY KEY,
    account_id         STRING NOT NULL,
    asset_id           STRING NOT NULL,
    source_region      STRING NOT NULL,
    destination_region STRING NOT NULL,
    amount              DECIMAL(38,0) NOT NULL CHECK (amount > 0),
    source_epoch        INT8 NOT NULL CHECK (source_epoch >= 0),
    key_id              STRING NOT NULL,
    certificate_payload BYTES NOT NULL,
    certificate_sig     BYTES NOT NULL,
    status              STRING NOT NULL DEFAULT 'IN_TRANSIT'
                        CHECK (status IN ('IN_TRANSIT', 'ACKNOWLEDGED')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged_at     TIMESTAMPTZ NULL,
    CHECK (source_region <> destination_region),
    UNIQUE (account_id, asset_id, source_region, source_epoch)
);

CREATE INDEX IF NOT EXISTS escrow_transfers_pending_idx
    ON escrow_transfers (source_region, destination_region, created_at)
    WHERE status = 'IN_TRANSIT';

-- This row and the destination rights update are committed in one database
-- transaction.  Its primary key is the exactly-once economic-effect guard.
CREATE TABLE IF NOT EXISTS escrow_consumed_certificates (
    transfer_id        STRING PRIMARY KEY,
    account_id         STRING NOT NULL,
    asset_id           STRING NOT NULL,
    source_region      STRING NOT NULL,
    destination_region STRING NOT NULL,
    amount              DECIMAL(38,0) NOT NULL CHECK (amount > 0),
    payload_hash        BYTES NOT NULL,
    consumed_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS outbox_messages (
    event_id              STRING PRIMARY KEY,
    topic                 STRING NOT NULL,
    message_key           BYTES NOT NULL,
    payload               BYTES NOT NULL,
    headers               JSONB NOT NULL DEFAULT '{}'::JSONB,
    aggregate_id          STRING NOT NULL,
    aggregate_version     INT8 NOT NULL CHECK (aggregate_version >= 0),
    parent_transaction_id STRING NULL REFERENCES ledger_transactions (transaction_id),
    status                STRING NOT NULL DEFAULT 'PENDING'
                          CHECK (status IN ('PENDING', 'PUBLISHING', 'PUBLISHED', 'POISON')),
    attempts              INT8 NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_by             STRING NULL,
    locked_until          TIMESTAMPTZ NULL,
    last_error            STRING NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at          TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS outbox_claim_idx
    ON outbox_messages (available_at, created_at)
    WHERE status IN ('PENDING', 'PUBLISHING');

CREATE TABLE IF NOT EXISTS transport_inbox_messages (
    consumer_name STRING NOT NULL,
    message_id    STRING NOT NULL,
    payload_hash  BYTES NOT NULL,
    status        STRING NOT NULL DEFAULT 'PROCESSING'
                  CHECK (status IN ('PROCESSING', 'FAILED', 'APPLIED', 'POISON')),
    attempts      INT8 NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error    STRING NULL,
    result        BYTES NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_at    TIMESTAMPTZ NULL,
    PRIMARY KEY (consumer_name, message_id)
);

CREATE TABLE IF NOT EXISTS saga_instances (
    saga_id       STRING PRIMARY KEY,
    saga_type     STRING NOT NULL,
    definition    STRING NOT NULL,
    status        STRING NOT NULL
                  CHECK (status IN ('RUNNING', 'COMPENSATING', 'COMPLETED', 'COMPENSATED', 'FAILED')),
    input         BYTES NOT NULL,
    result        BYTES NULL,
    current_step  INT8 NOT NULL DEFAULT 0 CHECK (current_step >= 0),
    version       INT8 NOT NULL DEFAULT 0 CHECK (version >= 0),
    last_error    STRING NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS saga_steps (
    saga_id       STRING NOT NULL REFERENCES saga_instances (saga_id),
    ordinal       INT8 NOT NULL CHECK (ordinal >= 0),
    step_name     STRING NOT NULL,
    effect_id     STRING NOT NULL,
    status        STRING NOT NULL
                  CHECK (status IN ('PENDING', 'WAITING', 'COMPLETED', 'FAILED', 'COMPENSATED', 'COMPENSATION_FAILED')),
    attempts      INT8 NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    output        BYTES NULL,
    last_error    STRING NULL,
    completed_at  TIMESTAMPTZ NULL,
    compensated_at TIMESTAMPTZ NULL,
    PRIMARY KEY (saga_id, ordinal),
    UNIQUE (effect_id)
);

CREATE TABLE IF NOT EXISTS external_attempts (
    operation_id       STRING PRIMARY KEY,
    rail               STRING NOT NULL,
    provider_reference STRING NOT NULL UNIQUE,
    request_hash       BYTES NOT NULL,
    request_payload    BYTES NOT NULL,
    status             STRING NOT NULL
                       CHECK (status IN ('IN_FLIGHT', 'UNKNOWN', 'SUCCEEDED', 'FAILED')),
    attempt_token      STRING NOT NULL,
    attempts           INT8 NOT NULL DEFAULT 1 CHECK (attempts > 0),
    response_payload   BYTES NULL,
    provider_code      STRING NULL,
    last_error         STRING NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at        TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS external_attempts_unknown_idx
    ON external_attempts (rail, updated_at)
    WHERE status IN ('IN_FLIGHT', 'UNKNOWN');

-- Roles are created by 001_core.sql.  Runtime identities receive no DELETE on
-- protocol history/deduplication rows.
REVOKE ALL ON TABLE escrow_authorities, escrow_regional_rights,
    escrow_transfers, escrow_consumed_certificates, outbox_messages,
    transport_inbox_messages, saga_instances, saga_steps, external_attempts
    FROM public;

GRANT ALL ON TABLE escrow_authorities, escrow_regional_rights,
    escrow_transfers, escrow_consumed_certificates, outbox_messages,
    transport_inbox_messages, saga_instances, saga_steps, external_attempts
    TO ledger_admin;

GRANT SELECT, INSERT, UPDATE ON TABLE escrow_authorities,
    escrow_regional_rights, escrow_transfers, escrow_consumed_certificates,
    outbox_messages, transport_inbox_messages, saga_instances, saga_steps,
    external_attempts TO ledger_writer;

GRANT SELECT ON TABLE escrow_authorities, escrow_regional_rights,
    escrow_transfers, escrow_consumed_certificates, outbox_messages,
    transport_inbox_messages, saga_instances, saga_steps, external_attempts
    TO ledger_reader, ledger_auditor;
