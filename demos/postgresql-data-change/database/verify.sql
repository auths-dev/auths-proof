\set ON_ERROR_STOP on

SELECT c.oid,
       c.relrowsecurity,
       c.relforcerowsecurity,
       pg_get_userbyid(c.relowner) AS owner,
       current_setting('server_version') AS server_version
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'app' AND c.relname = 'demo_accounts';

SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
FROM pg_catalog.pg_roles
WHERE rolname IN ('auths_owner', 'auths_executor')
ORDER BY rolname;

SELECT polname, polpermissive, polcmd,
       pg_get_expr(polqual, polrelid) AS using_expression,
       pg_get_expr(polwithcheck, polrelid) AS check_expression
FROM pg_catalog.pg_policy
WHERE polrelid = 'app.demo_accounts'::regclass
ORDER BY polname;
