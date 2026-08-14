CREATE TABLE auths_sandbox_meta (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    schema_version INTEGER NOT NULL CHECK (schema_version = 2),
    contract_id TEXT NOT NULL CHECK (contract_id = 'auths.sandbox.shared-state/2')
);

INSERT INTO auths_sandbox_meta (singleton, schema_version, contract_id)
VALUES (TRUE, 2, 'auths.sandbox.shared-state/2');

CREATE TABLE auths_sandbox_uses (
    authority_digest BYTEA PRIMARY KEY CHECK (octet_length(authority_digest) = 32),
    uses BIGINT NOT NULL CHECK (uses > 0)
);

CREATE TABLE auths_sandbox_pending (
    reference TEXT PRIMARY KEY CHECK (octet_length(reference) = 43),
    profile TEXT NOT NULL CHECK (octet_length(profile) BETWEEN 1 AND 128),
    authority_digest BYTEA NOT NULL CHECK (octet_length(authority_digest) = 32),
    action_bytes BYTEA NOT NULL CHECK (octet_length(action_bytes) BETWEEN 1 AND 1048576),
    created_at BIGINT NOT NULL CHECK (created_at >= 0)
);

CREATE TABLE auths_sandbox_receipts (
    receipt_id TEXT PRIMARY KEY CHECK (octet_length(receipt_id) = 64),
    profile TEXT NOT NULL CHECK (octet_length(profile) BETWEEN 1 AND 128),
    completed_at BIGINT NOT NULL CHECK (completed_at >= 0),
    receipt_bytes BYTEA NOT NULL CHECK (octet_length(receipt_bytes) BETWEEN 1 AND 1048576),
    value_bytes BYTEA NOT NULL CHECK (octet_length(value_bytes) BETWEEN 1 AND 1048576)
);

CREATE TABLE auths_sandbox_recovery (
    reference TEXT PRIMARY KEY CHECK (octet_length(reference) = 43),
    receipt_id TEXT NOT NULL REFERENCES auths_sandbox_receipts(receipt_id)
);
