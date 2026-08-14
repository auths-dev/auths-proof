CREATE TABLE auths_lifecycle_store_meta (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    schema_version INTEGER NOT NULL CHECK (schema_version = 2),
    contract_id TEXT NOT NULL CHECK (
        contract_id = 'auths.lifecycle.transactional-store/2'
    )
);

INSERT INTO auths_lifecycle_store_meta (singleton, schema_version, contract_id)
VALUES (TRUE, 2, 'auths.lifecycle.transactional-store/2');

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
