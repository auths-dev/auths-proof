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
GRANT USAGE ON SCHEMA auths_internal TO auths_audit;
GRANT SELECT ON auths_internal.auths_execution_ledger TO auths_audit;

CREATE OR REPLACE FUNCTION auths_internal.auths_prepare_execution(
    p_action_digest text,
    p_claim_id text,
    p_profile text,
    p_relation_oid oid,
    p_tenant_commitment text,
    p_row_set_digest text,
    p_before_state_digest text,
    p_after_state_digest text,
    p_transaction_started_at bigint
) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, auths_internal
AS $auths$
BEGIN
    INSERT INTO auths_internal.auths_execution_ledger (
        action_digest, claim_id, profile, relation_oid, tenant_commitment,
        row_set_digest, before_state_digest, after_state_digest,
        transaction_started_at
    ) VALUES (
        p_action_digest, p_claim_id, p_profile, p_relation_oid,
        p_tenant_commitment, p_row_set_digest, p_before_state_digest,
        p_after_state_digest, to_timestamp(p_transaction_started_at)
    );
    RETURN true;
END
$auths$;

CREATE OR REPLACE FUNCTION auths_internal.auths_finalize_execution(
    p_action_digest text,
    p_claim_id text,
    p_profile text,
    p_relation_oid oid,
    p_tenant_commitment text,
    p_row_set_digest text,
    p_before_state_digest text,
    p_after_state_digest text,
    p_affected_rows integer,
    p_result_commitment text,
    p_committed_at bigint
) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, auths_internal
AS $auths$
DECLARE
    changed integer;
BEGIN
    UPDATE auths_internal.auths_execution_ledger AS ledger
       SET affected_rows = p_affected_rows,
           result_commitment = p_result_commitment,
           committed_at = to_timestamp(p_committed_at),
           receipt_digest = p_result_commitment
     WHERE ledger.action_digest = p_action_digest
       AND ledger.claim_id = p_claim_id
       AND ledger.profile = p_profile
       AND ledger.relation_oid = p_relation_oid
       AND ledger.tenant_commitment = p_tenant_commitment
       AND ledger.row_set_digest = p_row_set_digest
       AND ledger.before_state_digest = p_before_state_digest
       AND ledger.after_state_digest = p_after_state_digest
       AND ledger.committed_at IS NULL;
    GET DIAGNOSTICS changed = ROW_COUNT;
    RETURN changed = 1;
END
$auths$;

CREATE OR REPLACE FUNCTION auths_internal.auths_read_execution(p_claim_id text)
RETURNS TABLE (
    action_digest text,
    claim_id text,
    profile text,
    relation_oid bigint,
    tenant_commitment text,
    row_set_digest text,
    before_state_digest text,
    after_state_digest text,
    affected_rows integer,
    result_commitment text,
    transaction_started_at bigint,
    committed_at bigint,
    receipt_digest text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, auths_internal
AS $auths$
    SELECT ledger.action_digest,
           ledger.claim_id,
           ledger.profile,
           ledger.relation_oid::bigint,
           ledger.tenant_commitment,
           ledger.row_set_digest,
           ledger.before_state_digest,
           ledger.after_state_digest,
           ledger.affected_rows,
           ledger.result_commitment,
           EXTRACT(EPOCH FROM ledger.transaction_started_at)::bigint,
           EXTRACT(EPOCH FROM ledger.committed_at)::bigint,
           ledger.receipt_digest
      FROM auths_internal.auths_execution_ledger AS ledger
     WHERE ledger.claim_id = p_claim_id
       AND ledger.committed_at IS NOT NULL
$auths$;

REVOKE ALL ON FUNCTION auths_internal.auths_prepare_execution(
    text, text, text, oid, text, text, text, text, bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION auths_internal.auths_finalize_execution(
    text, text, text, oid, text, text, text, text, integer, text, bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION auths_internal.auths_read_execution(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auths_internal.auths_prepare_execution(
    text, text, text, oid, text, text, text, text, bigint
) TO auths_executor;
GRANT EXECUTE ON FUNCTION auths_internal.auths_finalize_execution(
    text, text, text, oid, text, text, text, text, integer, text, bigint
) TO auths_executor;
GRANT EXECUTE ON FUNCTION auths_internal.auths_read_execution(text) TO auths_executor;

COMMENT ON TABLE auths_internal.auths_execution_ledger IS
    'Append-only Auths execution evidence committed atomically with bounded updates';

COMMIT;
