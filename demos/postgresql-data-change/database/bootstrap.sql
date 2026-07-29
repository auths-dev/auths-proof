\set ON_ERROR_STOP on

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auths_owner') THEN
        CREATE ROLE auths_owner NOLOGIN
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auths_executor') THEN
        CREATE ROLE auths_executor NOLOGIN
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
    END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS app AUTHORIZATION auths_owner;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = 'app' AND t.typname = 'review_status'
    ) THEN
        CREATE TYPE app.review_status AS ENUM ('pending', 'reviewed');
        ALTER TYPE app.review_status OWNER TO auths_owner;
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS app.demo_accounts (
    account_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    display_name text NOT NULL,
    email text NOT NULL,
    review_status app.review_status NOT NULL DEFAULT 'pending',
    row_version bigint NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE app.demo_accounts OWNER TO auths_owner;
ALTER TABLE app.demo_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.demo_accounts FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auths_tenant_isolation ON app.demo_accounts;
CREATE POLICY auths_tenant_isolation ON app.demo_accounts
    AS RESTRICTIVE
    FOR ALL
    TO auths_executor
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT CONNECT ON DATABASE auths_demo TO auths_executor;
GRANT USAGE ON SCHEMA app TO auths_executor;
GRANT SELECT (account_id, tenant_id, review_status, row_version)
    ON app.demo_accounts TO auths_executor;
GRANT UPDATE (review_status, row_version)
    ON app.demo_accounts TO auths_executor;

INSERT INTO app.demo_accounts
    (account_id, tenant_id, display_name, email, review_status, row_version)
VALUES
    ('00000000-0000-0000-0000-000000000001', 'tenant-demo', 'Ada North', 'ada@example.invalid', 'pending', 1),
    ('00000000-0000-0000-0000-000000000002', 'tenant-demo', 'Lin South', 'lin@example.invalid', 'pending', 2),
    ('00000000-0000-0000-0000-000000000003', 'tenant-demo', 'Sam West', 'sam@example.invalid', 'pending', 3)
ON CONFLICT (account_id) DO NOTHING;

COMMIT;
