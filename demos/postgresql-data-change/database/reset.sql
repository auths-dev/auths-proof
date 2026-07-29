\set ON_ERROR_STOP on

BEGIN;
SET LOCAL ROLE auths_owner;

UPDATE app.demo_accounts
SET review_status = 'pending',
    row_version = CASE account_id
        WHEN '00000000-0000-0000-0000-000000000001'::uuid THEN 1
        WHEN '00000000-0000-0000-0000-000000000002'::uuid THEN 2
        WHEN '00000000-0000-0000-0000-000000000003'::uuid THEN 3
        ELSE row_version
    END,
    updated_at = clock_timestamp()
WHERE tenant_id = 'tenant-demo'
  AND account_id IN (
      '00000000-0000-0000-0000-000000000001'::uuid,
      '00000000-0000-0000-0000-000000000002'::uuid,
      '00000000-0000-0000-0000-000000000003'::uuid
  );

DELETE FROM auths_internal.auths_execution_ledger;
COMMIT;
