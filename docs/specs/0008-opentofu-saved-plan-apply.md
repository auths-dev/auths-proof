# 0008: Auths for OpenTofu saved-plan application

Status: Implemented
Target: MVP plus public end-to-end demonstration  
Profile: `auths.opentofu.saved-plan-apply/1`  
Product package: `product/integrations/auths-opentofu`  
Demo: `demos/opentofu-plan`

## 1. Decision

Build one vertical OpenTofu product package that allows an untrusted agent to propose infrastructure configuration without receiving backend or provider credentials.

The protected planner creates a saved OpenTofu plan in an isolated workspace. Auths authorizes application of that exact plan artifact to one exact backend, workspace, and state lineage. The protected executor claims the action and applies the saved plan once.

The first profile is intentionally narrower than “run OpenTofu”:

- one root module;
- one initialized workspace;
- one saved plan;
- an explicit resource-type and action allowlist;
- no destroy, replacement, import, moved-resource manipulation, provisioners, or arbitrary hooks; and
- no agent-selected CLI flags or environment variables at execution time.

## 2. Product claim

An OpenTofu plan can preview changes, and a saved plan can later be applied. Auths binds authority to:

- the opaque saved-plan bytes;
- a sanitized semantic projection of the plan;
- configuration, variable, module, and provider-lock digests;
- backend and workspace identity;
- state lineage and serial;
- allowed resource actions;
- required verifier configuration; and
- a short authorization lifetime.

The agent cannot swap the plan, backend, workspace, provider, variables, or execution configuration after authorization.

## 3. Goals

The MVP must:

1. keep planning and applying behind a protected boundary;
2. represent one saved-plan application as a canonical Auths action;
3. prevent plan-file substitution and plan-summary confusion;
4. detect state or workspace drift before apply;
5. claim before acquiring mutation credentials;
6. apply by exact saved-plan path, never by implicit re-planning;
7. distinguish apply acceptance from provider-side postconditions;
8. keep sensitive plan material out of public receipts;
9. expose required and executed verifier configuration; and
10. prove the workflow in a real sandbox demonstration.

## 4. Non-goals

The MVP does not:

- run arbitrary OpenTofu subcommands;
- accept an agent-created plan as trusted evidence;
- expose saved plans or raw `tofu show -json` output publicly;
- support destroy plans;
- permit delete-and-create replacements;
- run local, remote, or file provisioners;
- execute external data sources or unpinned modules;
- change backend configuration;
- rotate credentials;
- guarantee provider success; or
- authorize every effect a provider plugin might perform.

## 5. Trust and credential model

### Untrusted

- agent-generated HCL;
- user-supplied variables;
- human-readable plan text;
- browser state;
- plan summaries not derived by the protected planner;
- remote module content not pinned by digest; and
- provider responses until checked by the protected runtime.

### Trusted for the MVP

- Auths core;
- the OpenTofu vertical package;
- protected planner and executor images;
- pinned OpenTofu binary and provider checksums;
- configured backend identity;
- claim and receipt stores;
- provider sandbox; and
- required verifier configuration.

Planning credentials and mutation credentials should be separated where the provider supports it. The agent receives neither. Mutation credentials become available only after a successful claim.

## 6. Vertical package

```text
product/integrations/auths-opentofu/
  Cargo.toml
  src/
    lib.rs
    action.rs
    bundle.rs
    canonical.rs
    planner.rs
    plan_projection.rs
    profile.rs
    executor.rs
    observe.rs
    receipts.rs
    errors.rs
  tests/
    fixtures/
    conformance/
```

All OpenTofu, HCL, plan, backend, workspace, provider, and resource-change concepts remain in this package. Core crates remain provider-neutral. The demo consumes this package without becoming an alternative implementation.

## 7. Proposed configuration bundle

The agent submits a bounded source bundle:

```text
OpenTofuSourceBundleV1 {
  root_module_files
  variable_values
  dependency_lock_file
  module_manifest
  requested_workspace
}
```

The protected planner:

1. rejects paths outside the root and all symlinks;
2. applies hard file-count, byte, expression-depth, and archive limits;
3. rejects forbidden blocks and functions;
4. verifies module and provider pins;
5. writes the bundle into a fresh isolated directory;
6. initializes against configured backend metadata;
7. selects the configured workspace;
8. creates a saved plan with non-interactive, pinned flags;
9. renders the plan’s machine-readable projection; and
10. stores the sensitive plan artifact in protected storage.

The source bundle is not the executable action. The resulting saved plan is.

## 8. Canonical action

```text
OpenTofuSavedPlanApplyV1 {
  profile
  executor_audience
  opentofu_version
  platform
  backend_identity
  workspace
  state_lineage
  state_serial
  state_digest
  configuration_bundle_digest
  variable_commitment
  dependency_lock_digest
  module_manifest_digest
  opaque_plan_digest
  plan_projection_digest
  plan_handle
  permitted_change_summary
  required_configuration
  planned_at
  expires_at
  nonce
}
```

`plan_handle` is an opaque, single-tenant reference to protected storage. It is not a path and cannot be supplied directly to OpenTofu. The executor resolves it only after verification and claim, then verifies `opaque_plan_digest` before use.

The canonical action must never contain provider credentials, sensitive variable values, raw plan bytes, or unredacted plan output.

## 9. Sanitized plan projection

The protected planner derives:

```text
SavedPlanProjectionV1 {
  format_version
  terraform_version
  prior_state_lineage
  prior_state_serial
  resource_changes[]
  output_change_commitments[]
  checks[]
  provider_configuration_commitments[]
}

ResourceChangeV1 {
  address
  provider_source
  resource_type
  resource_name
  actions
  before_commitment
  after_commitment
  sensitive_paths
  replacement_paths
}
```

The projection is canonicalized by the Auths package, not by hashing pretty-printed CLI text.

Sensitive values are replaced by typed commitments that preserve structural comparison without disclosure. Unknown-after-apply values remain explicitly unknown; they must not be serialized as null or omitted.

## 10. MVP restrictions

The verifier denies a plan containing:

- `delete`;
- replacement (`delete` plus `create`);
- more than the configured number of resource changes;
- a resource type or provider outside the allowlist;
- a provider configuration not committed by the action;
- an ephemeral input variable that would have to be supplied again at apply time;
- a provisioner;
- an external executable data source;
- an unpinned remote module;
- an override file;
- backend change;
- an unexpected sensitive output;
- failed or unknown policy checks that configuration requires to be known; or
- a projected cost or cardinality outside configured bounds.

The initial demonstration should permit one low-cost, reversible resource update. The product profile remains provider-neutral, but the demo configuration is provider-specific and narrow.

## 11. Required and executed configuration

```text
OpenTofuVerifierConfigurationV1 {
  profile
  canonicalization_version
  allowed_opentofu_versions
  allowed_backend_identities
  allowed_workspaces
  allowed_provider_sources
  allowed_resource_types
  allowed_actions
  maximum_resource_changes
  maximum_plan_age_seconds
  maximum_authorization_lifetime_seconds
  allow_sensitive_outputs
  allow_destroy
  allow_replacement
  receipt_schema_version
}
```

The decision returns both `required_configuration` and `executed_configuration`. Canonical inequality produces `verifier-configuration-mismatch` before claim or credential access.

A mandatory unit test changes only `maximum_resource_changes` after proof issuance and asserts denial while showing both configurations.

## 12. State freshness

Before authorization, evidence commits to:

- backend identity;
- workspace;
- state lineage;
- state serial;
- canonical state digest;
- current lock status;
- provider and module locks;
- planning time; and
- planner build identity.

Immediately before apply, the executor rechecks backend, workspace, lineage, serial, and plan digest. If state has advanced, the action is stale even if OpenTofu might independently reject it.

Refreshing or re-planning creates a new action requiring new authorization. The executor must never silently replace an authorized saved plan with a fresh plan.

## 13. Claim and execution

```text
verify proof and evidence
  -> claim action digest
  -> resolve protected plan handle
  -> verify plan digest
  -> acquire backend/provider credentials
  -> recheck state identity
  -> run `tofu apply <saved-plan>`
  -> observe state and provider postconditions
  -> write linked receipts
```

The executor invokes a pinned binary with a fixed argument vector and a scrubbed environment. It does not use a shell. It sets explicit timeouts, working directory, plugin cache, data directory, input-disabled mode, and automation mode.

The execution directory is fresh and cannot contain agent-controlled startup files, CLI configuration, credentials helpers, binaries, plugins, or hooks.

## 14. Provider and backend credentials

Credentials must be:

- scoped to the configured sandbox or workspace;
- short-lived where supported;
- acquired only after claim;
- passed without command-line exposure;
- unavailable to the agent and frontend; and
- scrubbed before logs and receipts are recorded.

OpenTofu backend and plan files can contain sensitive information. They remain encrypted in protected storage and are deleted according to an explicit retention policy after reconciliation no longer requires them.

## 15. Outcomes and reconciliation

Separate:

1. `authorized`;
2. `apply_started`;
3. `state_committed`;
4. `postconditions_observed`; and
5. `converged` or `failed`.

If the process exits or connectivity fails after apply starts, the action becomes `outcome_unknown`. Reconciliation reads:

- backend lineage and serial;
- state resources and commitments;
- provider-side object identity;
- OpenTofu operation records when available; and
- the protected execution log digest.

It must not re-run the saved plan until reconciliation proves it was not applied and the original state preconditions still hold. A new state serial normally requires a new plan and authorization.

## 16. Receipts

### Decision receipt

Action digest, proof identity, required/executed configuration, state evidence digest and age, plan projection digest, verdict, stable code, and stage.

### Claim receipt

Action digest, claim ID, claimant audience, transition, and replay outcome.

### Apply receipt

Pinned tool build, opaque plan digest, backend/workspace commitments, start/end time, sanitized exit classification, resulting state lineage/serial/digest, and protected log digest.

### Observation receipt

Provider object commitments, asserted postconditions, observed values safe for disclosure, and final state.

No receipt contains raw plan bytes, backend configuration, credentials, or sensitive values.

## 17. Stable codes

- `malformed-source-bundle`
- `unsupported-profile`
- `forbidden-opentofu-feature`
- `dependency-not-pinned`
- `plan-failed`
- `plan-artifact-mismatch`
- `plan-projection-mismatch`
- `verifier-configuration-mismatch`
- `evidence-stale`
- `backend-identity-mismatch`
- `workspace-mismatch`
- `state-lineage-mismatch`
- `state-serial-mismatch`
- `change-outside-profile`
- `destroy-denied`
- `replacement-denied`
- `already-claimed`
- `credential-unavailable`
- `apply-failed`
- `postcondition-failed`
- `execution-outcome-unknown`

## 18. End-to-end demo

### Real effect

The demo applies a saved plan that changes one safe, dedicated sandbox resource with a publicly observable, non-secret value. The exact provider may be selected at implementation time, but it must support:

- isolated credentials;
- negligible cost;
- deterministic reset;
- provider-side read-back; and
- a visible postcondition.

A Cloudflare test-zone TXT record or a dedicated object in a sandbox cloud account are acceptable. A fake provider or local-only file is not sufficient for the primary success path.

### UI

One screen shows:

- proposed configuration diff;
- sanitized saved-plan changes;
- state lineage and serial;
- authorization verdict;
- required/executed configuration parity;
- claim and apply status;
- provider-side observed value; and
- linked receipts.

Controls and results remain adjacent. Experiments include exact plan, swapped plan artifact, changed workspace, stale state, added delete, changed provider lock, verifier configuration mismatch, and replay.

The UI clearly states that the agent has neither backend nor provider credentials and shows a real failed credential probe as bounded evidence, without printing secret names or values.

### Frontend delivery contract

The frontend is a required part of the implementation, not optional follow-up work. A backend-only implementation, API explorer, static mockup, or page that never reaches the native planner/executor does not satisfy this specification.

Follow the established GitHub and Radicle demo interaction model:

- one primary workbench places selectable experiments beside the current verdict and apply result;
- selecting an experiment immediately updates the exact plan facts and predicted decision;
- executing it calls the deployed native backend and renders its returned stable code, configuration commitments, claim state, provider effect, and receipt links;
- loading, unavailable, denied, indeterminate, authorized, applied, reconciled, and replay states are visibly distinct;
- the successful path performs the real sandbox apply, while every denied path proves that no provider mutation occurred; and
- desktop and mobile layouts keep the control that caused a result adjacent to that result.

### Receipt interface contract

Receipts must be understandable without navigating away from the experiment
that produced them:

- after every attempted execution, the primary workbench exposes the complete,
  pretty-printed machine-readable receipt inline beneath the live result;
- the inline JSON is loaded from the real receipt API and is not reconstructed
  from frontend state;
- the workbench’s receipt link opens a dedicated
  `/receipts/{session-or-workflow-id}` page, not the raw JSON API response;
- the dedicated page summarizes the decision, stable code, action and evidence
  commitments, required/executed configuration relationship, credential or
  provider boundary, and observed effect before offering the complete raw JSON;
- missing, expired, malformed, or unverifiable receipt identifiers render an
  explicit fail-closed receipt page; and
- browser tests cover both the inline viewer and the dedicated receipt route.

Browser-level end-to-end tests must start from the rendered page and exercise readiness, exact apply, at least one material denial, replay, provider read-back, and receipt inspection through the same public API routes used in production. Static DOM assertions and backend-only integration tests are necessary but insufficient.

Completion requires a publicly reachable frontend URL and a publicly reachable native API deployment. Opening `index.html` through `file://`, serving only on localhost, committing Vercel/Fly configuration without deploying it, or deploying a frontend whose API is unavailable does not satisfy this specification. Before handoff, test the public Vercel URL against the public Fly deployment and record the tested URLs and release identifiers.

### Design and deployment

Use the `auths-proof-site` design language and concise explanatory copy. Deploy the frontend on Vercel and the native planner/executor on Fly.io or an equivalently isolated runtime. Store plan artifacts and claims durably. Document API origins, health checks, provider sandbox reset, secret injection, retention, and rollback.

The deployed demo exposes stable public URLs and reports whether it is using live provider evidence or deterministic fixtures.

## 19. Testing

### Unit and conformance

- source-bundle path and size limits;
- canonical action and projection vectors;
- sensitive-value redaction and commitments;
- required/executed configuration mismatch;
- changed plan byte;
- changed workspace, backend, lineage, serial, lock file, module, or variable commitment;
- unknown and sensitive plan values;
- forbidden action and feature matrix;
- browser/native verifier parity;
- concurrent claim races and replay.

### Integration

- protected planning against a real backend;
- exact saved-plan apply;
- state advancement between plan and apply;
- corrupted protected artifact;
- expired provider credential;
- provider partial failure;
- process termination before and after state commit;
- reconciliation from resulting state;
- secret scans over artifacts, logs, receipts, and frontend bundles.

### CI

- package dependency boundaries;
- pinned OpenTofu and provider checksums;
- no native executor dependency in WASM artifacts;
- deterministic fixtures;
- prohibited credential patterns;
- sandbox contract tests separated from offline conformance tests; and
- workspace Rust edition, resolver, MSRV, lint, audit, and dependency checks.

### Completion evidence checklist

The following work is required before this specification may be marked
implemented. A fixture backend may establish pure authorization and HTTP
contract behavior, but it does not satisfy any item that requires OpenTofu,
provider state, process interruption, restart, or public browser execution.

- [x] Commit versioned, byte-stable policy, action, saved-plan projection,
  evidence, decision, execution, observation, denial, and replay fixtures.
  Programmatically constructed test values alone are not the canonical fixture
  corpus.
- [ ] Run the protected planner against the pinned OpenTofu binary, provider
  lock, initialized workspace, real backend state, and live sandbox provider.
  Capture the exact saved-plan artifact and derive the authorization from that
  artifact and fresh state. The local-provider contract now proves the complete
  planner and saved-artifact machinery, but it does not close this external
  provider gate.
- [ ] Apply that exact saved plan once and prove the real provider object and
  backend state changed to the authorized postcondition. A fixture serial
  increment or an `opentofu_called` test flag is not provider evidence. The
  local-provider contract proves an exact provider effect and read-back, but
  the primary Cloudflare or equivalent external-provider path remains to be
  exercised.
- [x] Exercise every material denial through the native enforcement boundary:
  changed source configuration, one changed plan byte, workspace/backend
  change, provider-lock change, state drift, unavailable state lock, destructive
  change beyond policy, expired plan/evidence, and required/executed
  configuration mismatch. Each denial must prove that credentials were not
  released and `tofu apply` was not entered.
- [x] Fault-inject an apply failure before any provider effect and verify the
  claim, artifact, state, and receipts remain consistent.
- [x] Fault-inject a provider partial effect or otherwise ambiguous apply
  outcome, terminate the executor both before and after possible state commit,
  restart with the durable claim/artifact/receipt stores, and reconcile from a
  fresh backend and provider observation without issuing a second apply.
- [x] Prove replay after committed and reconciled outcomes returns the durable
  prior result and never invokes OpenTofu again.
- [x] Run browser-driven end-to-end tests against the local live service. The
  browser must create a fresh session and exercise readiness, exact apply,
  material denial, replay, provider read-back, inline receipt JSON, the designed
  receipt route, and fail-closed invalid receipt identifiers. Reading HTML or
  JavaScript files and asserting that selectors or request strings exist is not
  browser-level coverage.
- [ ] Deploy the native live-mode service and frontend, then repeat the same
  browser flow through the public frontend and public API. A `fly.toml`,
  `vercel.json`, configured hostname, fixture-mode deployment, DNS record, or
  HTTP 404 is not deployment evidence.
- [ ] Record redacted release evidence containing the tested frontend and API
  URLs, source revision, Fly image reference or equivalent native release,
  Vercel deployment identifier, OpenTofu version, provider-lock digest,
  provider/backend observation commitments, region, and test timestamp.
- [ ] Map the live sandbox, fault/restart, browser, deployment, canonical
  fixture, and secret-scan evidence into `compliance.toml`. A green compliance
  job is insufficient if it points only to fixture-backed tests.
- [ ] Pass formatting, architecture, workspace tests, clippy, MSRV, dependency
  policy, secret scanning, compliance, and the complete authoritative CI suite
  on the exact revision whose release evidence was recorded.

## 20. Acceptance criteria

1. The agent proposes configuration without backend or provider credentials.
2. The protected planner creates the saved plan and semantic projection.
3. Auths commits to both without exposing sensitive contents.
4. Only the exact plan can be applied.
5. Any workspace, state, provider, variable, module, plan, or configuration change denies.
6. Claim precedes credential acquisition.
7. Destroy, replacement, and forbidden features are rejected.
8. Ambiguous execution reconciles without blind replay.
9. Receipts distinguish authorization, state commit, and provider observation.
10. Browser and native verdicts match.
11. The public demo performs and displays a real sandbox effect.
12. Core crates remain independent of OpenTofu.
13. The deployed frontend completes exact, denial, replay, provider-observation, and receipt flows against the deployed native backend.
14. Browser-level end-to-end tests fail if frontend/backend wiring, CORS, readiness, interaction, or result rendering breaks.
15. Canonical policy, action, projection, evidence, and receipt fixtures are committed and byte-stable.
16. Live failure, interruption, restart, ambiguous-outcome reconciliation, and replay tests pass without duplicate provider effects.
17. Redacted release evidence identifies and proves the exact public frontend, native release, provider/backend observation, and source revision tested.
18. Complete compliance claims and authoritative CI pass for that revision.

## 21. Milestone 5 shared-lifecycle cutover contract

The Milestone 5 source cutover replaces the production claim machine in this
vertical with the shared bounded-policy and durable-lifecycle kernels. It does
not move OpenTofu, saved-plan, backend, provider, state, artifact, credential,
observation, reconciliation, or receipt semantics into shared code.

The closed identities for this semantic version are:

| Concept | Identifier |
| --- | --- |
| profile | `auths.opentofu.saved-plan-apply/1` |
| policy type | `auths.opentofu.saved-plan-policy/1` |
| evaluator semantic | `auths.opentofu.saved-plan-apply.evaluate/1` |
| implementation | `auths-opentofu/shared-lifecycle-production/1` |
| configuration semantic | `auths.opentofu.verifier-configuration/1` |
| evidence schema | `auths.opentofu.saved-plan-state-evidence/1` |
| evidence source | `opentofu-backend-state-and-lock-read/1` |
| state schema | `auths.opentofu.backend-state-snapshot/1` |
| reservation intent | `auths.opentofu.backend-workspace-exclusive-intent/1` |
| reservation algebra | `auths.opentofu.backend-workspace-state-exclusive/1` |
| obligation schema | `auths.opentofu.verified-saved-plan-command/1` |
| provider contract | `auths.opentofu.fixed-argv-saved-plan-apply/1` |
| domain | `opentofu` |

One authorized action projects to one exclusive reservation over the canonical
tuple:

```text
(
  executor audience,
  backend identity,
  workspace,
  state lineage,
  prior state serial
)
```

The scope intentionally excludes the plan digest. Two different plans created
from the same backend/workspace state must contend for the same reservation;
giving each plan a separate scope would permit both to pass capacity checks
against one prior state. The exact action, opaque plan, projection,
configuration, dependency locks, module manifest, variables, and evidence
remain committed separately by the policy input and verified command.

The lifecycle workflow and execution identities are derived
domain-separately from the exact action and policy commitments. Credential
acquisition requires the durable execution authorization produced after
decision persistence, reservation, and execution-intent persistence. The
gateway receives only a sealed domain command containing that authorization;
it never receives an unsealed action plus a boolean or claim flag.

The durable progression is:

```text
decision
  -> reservation
  -> execution intent
  -> provider attempt
  -> provider call entry
  -> committed | failed | outcome unknown
  -> reconciliation observation
  -> reconciled committed | reconciled not committed
```

Artifact resolution and digest verification remain domain-local and occur
after reservation but before credentials. State freshness is rechecked after
credential acquisition and before the provider-call entry. A definite
pre-effect error releases the reservation and records failure. Any ambiguous
error after the apply attempt begins records `outcome_unknown` and retains the
reservation until reconciliation reaches a terminal conclusion.

Reconciliation authority is a separate sealed command derived only from a
durable `outcome_unknown` record. It may read backend state, provider object
identity, and protected operation evidence, but it cannot submit the saved
plan. Recovery after process restart loads the shared lifecycle record,
constructs reconciliation authority, and observes the provider without
reissuing `tofu apply`.

Public claim, apply, and observation receipts remain OpenTofu projections of
the shared lifecycle and provider evidence. Their unchanged versioned bytes
remain differential oracles. The obsolete prelaunch claim-store format is
rejected at startup; this cutover adds no legacy reader, dual write, migration,
or compatibility shim.

The cutover is accepted only when:

1. all unchanged decision classes, stable codes, stages, verified command
   commitments, and receipt bytes match the frozen reference fixtures;
2. a changed action, plan, backend, workspace, state lineage, state serial,
   configuration, or evidence cannot resume another workflow;
3. concurrent plans from the same prior backend/workspace state permit at most
   one provider effect;
4. denial and artifact mismatch occur before credential release and provider
   invocation;
5. crash-before-effect, crash-after-possible-commit, restart, reconciliation,
   replay, and corrupt or obsolete state tests pass;
6. reconciliation never invokes the apply boundary;
7. provider behavior, protected artifact handling, credentials, observation,
   and canonical public receipts remain in the OpenTofu vertical; and
8. the old production claim orchestration is removed after the shared path and
   retained test-only oracle prove exact conformance.

## 22. Deferred work

- destroy and replacement profiles;
- multiple workspaces or root modules;
- speculative remote runs;
- policy integrations;
- cost-estimation standards;
- drift remediation;
- import and moved resources;
- provider-specific semantic profiles;
- HCP/OpenTofu remote execution integrations; and
- reusable infrastructure-plan abstractions extracted after another engine validates them.
