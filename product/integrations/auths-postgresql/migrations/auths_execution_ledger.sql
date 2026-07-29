BEGIN;

CREATE SCHEMA IF NOT EXISTS auths_internal;

CREATE TABLE IF NOT EXISTS auths_internal.auths_execution_ledger (
    action_digest text PRIMARY KEY
        CHECK (action_digest ~ '^[0-9a-f]{64}$'),
    claim_id text UNIQUE NOT NULL,
    profile text NOT NULL,
    relation_oid oid NOT NULL,
    tenant_commitment text NOT NULL
        CHECK (tenant_commitment ~ '^[0-9a-f]{64}$'),
    row_set_digest text NOT NULL
        CHECK (row_set_digest ~ '^[0-9a-f]{64}$'),
    before_state_digest text NOT NULL
        CHECK (before_state_digest ~ '^[0-9a-f]{64}$'),
    after_state_digest text NOT NULL
        CHECK (after_state_digest ~ '^[0-9a-f]{64}$'),
    affected_rows integer
        CHECK (affected_rows IS NULL OR affected_rows >= 0),
    result_commitment text
        CHECK (result_commitment IS NULL OR result_commitment ~ '^[0-9a-f]{64}$'),
    transaction_started_at timestamptz NOT NULL,
    committed_at timestamptz,
    receipt_digest text
        CHECK (receipt_digest IS NULL OR receipt_digest ~ '^[0-9a-f]{64}$')
);

REVOKE ALL ON SCHEMA auths_internal FROM PUBLIC;
REVOKE ALL ON auths_internal.auths_execution_ledger FROM PUBLIC;
GRANT USAGE ON SCHEMA auths_internal TO auths_executor;
GRANT SELECT, INSERT, UPDATE ON auths_internal.auths_execution_ledger TO auths_executor;

COMMENT ON TABLE auths_internal.auths_execution_ledger IS
    'Append-only Auths execution evidence committed atomically with bounded updates';

COMMIT;
