CREATE TABLE auths_lifecycle_store_meta (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    schema_version INTEGER NOT NULL CHECK (schema_version = 4),
    contract_id TEXT NOT NULL CHECK (
        contract_id = 'auths.lifecycle.transactional-store/4'
    )
);

INSERT INTO auths_lifecycle_store_meta (singleton, schema_version, contract_id)
VALUES (TRUE, 4, 'auths.lifecycle.transactional-store/4');

CREATE TABLE auths_lifecycle_records (
    workflow_id TEXT PRIMARY KEY CHECK (
        octet_length(workflow_id) BETWEEN 1 AND 256
    ),
    revision BIGINT NOT NULL CHECK (revision >= 1),
    lifecycle_state SMALLINT NOT NULL CHECK (
        lifecycle_state BETWEEN 0 AND 8
    ),
    record_bytes BYTEA NOT NULL CHECK (
        octet_length(record_bytes) BETWEEN 1 AND 262144
    ),
    record_sha256 BYTEA NOT NULL CHECK (
        octet_length(record_sha256) = 32
    )
);

CREATE TABLE auths_recovery_references (
    recovery_reference_digest BYTEA PRIMARY KEY CHECK (
        octet_length(recovery_reference_digest) = 32
    ),
    workflow_id TEXT UNIQUE NOT NULL CHECK (
        octet_length(workflow_id) BETWEEN 1 AND 256
    ),
    profile_id TEXT NOT NULL CHECK (
        octet_length(profile_id) BETWEEN 1 AND 256
    )
);

CREATE INDEX auths_recovery_profile_workflow
ON auths_recovery_references (profile_id, workflow_id);

CREATE TABLE auths_recovery_leases (
    workflow_id TEXT PRIMARY KEY CHECK (
        octet_length(workflow_id) BETWEEN 1 AND 256
    ),
    profile_id TEXT NOT NULL CHECK (
        octet_length(profile_id) BETWEEN 1 AND 256
    ),
    expected_revision BIGINT NOT NULL CHECK (expected_revision >= 1),
    expires_at BIGINT NOT NULL CHECK (expires_at >= 0),
    lease_digest BYTEA NOT NULL CHECK (octet_length(lease_digest) = 32)
);

CREATE TABLE auths_gateway_attempts (
    attempt_key BYTEA PRIMARY KEY CHECK (octet_length(attempt_key) = 32),
    record_bytes BYTEA NOT NULL CHECK (
        octet_length(record_bytes) BETWEEN 1 AND 131072
    ),
    record_sha256 BYTEA NOT NULL CHECK (octet_length(record_sha256) = 32)
);
