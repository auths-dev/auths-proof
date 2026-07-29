# Fail-closed debugging

- `verifier-configuration-mismatch`: compare the full required and executed
  objects shown in the decision receipt. Re-issue authorization after an
  intentional policy change.
- `plan-artifact-mismatch`: quarantine the artifact store. Do not re-plan or
  substitute a file under the existing action.
- `state-serial-mismatch`: another operation advanced state. Reconcile the
  provider effect, then create a new saved plan and proof.
- `dependency-not-pinned`: regenerate the provider lock through the protected
  deployment process and issue a new action.
- `already-claimed`: inspect the durable claim stage and receipts. Never delete
  the claim merely to retry.
- `execution-outcome-unknown`: use state/provider read-back. The executor's
  reconciliation path is read-only and does not submit the plan again.
- `/readyz` unavailable: verify the absolute binary and working-directory
  paths, file ownership, pinned version, and provider lock. Readiness does not
  request mutation credentials.

Receipt and log inspection must search for provider token material, raw saved
plan bytes, backend configuration, and `TF_VAR_*` values. Any match is a
security incident, not a debugging convenience.

## Executable local diagnostics

From `demos/opentofu-plan`:

```sh
docker compose up --build -d
npm ci
npx playwright install chromium
npm run check
npm run test:live-contract
npm run test:live-recovery
npm run test:e2e
```

The live contract covers every repository-owned denial and a concurrent claim
race. The recovery contract injects `before-apply` and
`after-apply-unreconciled`, recreates the API with the same volume, and proves
fresh state/provider reconciliation without a second apply. The browser test
uses `http://localhost:4174`, including inline JSON and the designed receipt
route.

If restart reconciliation reports `execution-outcome-unknown`, verify that
`sandbox/local/main.tf` still configures both `path` and `workspace_dir` below
`/data/auths-opentofu`. Keeping only the default state path durable silently
loses non-default workspace state when the container is replaced.
