# v1.0 Launch Readiness — Independent Assessment

## Verdict

The codebase is not ready to be represented as a credible v1.0 release. The principal blocker is not polish: the stock `auths-node` executable used by the production Kubernetes manifests rejects every production configuration, so the shipped reference deployment cannot start. Effectful HTTP requests can also return a timeout while their blocking operation continues detached, with no client-known recovery handle and no admission bound. The intended absent-budget semantic change is correct in the kernel but is not an atomic cutover: clean `HEAD` retains the old result in supported TypeScript/Python MCP and formal paths, and the compliance run fails 16 tests; concurrent uncommitted Lean work does not yet close that cross-language failure. The authoritative and release gates also stop on stale error-lifecycle metadata, before reaching the two intentionally red gates. Adversarial conformance exists but is not invoked by the aggregate compliance or release path, so a deliberately corrupted expected result passes `cargo xtask conformance`. Finally, the advertised OTLP configuration is parsed but does not cause the node to export OTLP or report telemetry readiness. Four blockers and two major findings must close before v1.0; no minor findings are being used to dilute that conclusion.

## Summary table

| ID | Title | Severity | Area | Est. effort | Depends on |
|----|-------|----------|------|-------------|------------|
| LR-001 | Ship a production assembly in the stock `auths-node` image | blocker | production runtime | 5 days | LR-002 |
| LR-002 | Make deadlines effect-safe and bound blocking admission | blocker | runtime/effect recovery | 6–8 days | — |
| LR-003 | Complete the absent-budget cutover atomically across SDKs and Lean | blocker | semantics/bindings/formal | 3 days | — |
| LR-004 | Synchronize active error lifecycle metadata with the registry | blocker | release metadata | 0.5 day | — |
| LR-005 | Put adversarial conformance on the aggregate release path | major | compliance | 1 day | — |
| LR-006 | Make configured OTLP export real and observable | major | operations | 4–6 days | LR-001 |

## Baseline

The command baseline was taken from `dev-cleanup` at `ac5b968` (`core: make terminal budget coverage the kernel's own answer (UNSIGNED)`) after reading `AGENTS.md`, the ratified API contract, commits `bbeb654..HEAD`, and both prior API audits. While this document was being written, `HEAD` advanced to `f82cb08` (`formal: run the 31 ungated Kani harnesses and fix what they proved (UNSIGNED)`). Its complete commit message and diff were reviewed: it closes Kani gate/harness weaknesses in lifecycle, bounded policy, and Stripe but does not close any of LR-001 through LR-006; the intentionally red formal command should nevertheless be rebuilt before its digest is used. Concurrent uncommitted formal-vector/Lean edits are visible in the shared working tree but are not treated as completed or verified work in this assessment. The separately supplied launch-readiness investigation list was deliberately not read. No shipping source was changed by this assessment; two temporary negative controls were restored/deleted after execution.

The aggregate gates currently stop on an unexpected lifecycle-registry mismatch:

```text
$ ./target/debug/xtask ci authoritative
architecture policy and dependency snapshots passed
binding semantics passed: 103 files, 14 patterns, 13 declared allowances (0 temporary)
xtask: active error lifecycle metadata does not exactly cover the Rust registry
exit=1

$ ./target/debug/xtask release-check
architecture policy and dependency snapshots passed
binding semantics passed: 103 files, 14 patterns, 13 declared allowances (0 temporary)
xtask: active error lifecycle metadata does not exactly cover the Rust registry
exit=1
```

The two red gates explicitly anticipated by the launch brief are still red and were not treated as newly discovered defects:

```text
$ ./target/debug/xtask semantic-freeze
xtask: semantic freeze drifted; assign new semantic identities or versions, then run `cargo xtask semantic-freeze --update`
exit=1

$ ./target/debug/xtask formal
xtask: production translation source closure drifted; run `cargo xtask formal qualify aeneas --update` (computed digest e15edc03ddaf02c2318cc02de20925ea3ad1b71a876c06447ece0fd3e193722c)
exit=1
```

The permitted direct Lean build succeeds; its three `sorry` warnings are in the vendored Aeneas standard library and are not raised as launch findings:

```text
$ cd formal && lake build
⚠ [3077/3200] Replayed Aeneas.Std.Slice
warning: Aeneas/Std/Slice.lean:363:4: declaration uses `sorry`
warning: Aeneas/Std/Slice.lean:586:8: declaration uses `sorry`
⚠ [3156/3200] Replayed Aeneas.Std.StringIter
warning: Aeneas/Std/StringIter.lean:12:4: declaration uses `sorry`
warning: Aeneas/Std/StringIter.lean:15:4: declaration uses `sorry`
Build completed successfully (3284 jobs).
```

The full compliance run gets through the Rust/product corpus and then fails in the TypeScript SDK with the cross-language absent-budget drift described in LR-003. These are the verbatim milestones and terminal summary retained from that run:

```text
compliance inventory covers 68 declared product surfaces
specification, registry, and result-code registries are synchronized
516 golden vector files are byte-stable
target V1 canonical corpus conformance passed
exchange transport conformance passed
product MCP and Iroh conformance passed
product fixtures are stable
Stripe profile boundary passed (6 families, 11 profiles)
bounded-domain boundary passed (7 domains, 11 required scenarios)
Auths Lab matrix: 504 nominal points, 396 baseline-compatible points
1..87
# tests 94
# suites 0
# pass 78
# fail 16
# cancelled 0
# skipped 0
# todo 0
# duration_ms 3591.035083
xtask: npm test failed with exit status: 1
```

## Findings

### LR-001 — Ship a production assembly in the stock `auths-node` image

- **Severity:** blocker
- **Area:** Production runtime and reference deployment
- **Estimated effort:** 5 engineering days
- **Depends on:** LR-002
- **Files:** `product/runtime/auths-node/Cargo.toml:10-39`; `product/runtime/auths-node/src/lib.rs:3-14`; `product/runtime/auths-node/src/main.rs:55-120`; `product/runtime/auths-node/src/config.rs:16-88`; `product/runtime/auths-node/src/profiles.rs:158-338`; `product/runtime/auths-node/src/production.rs` (new); `product/runtime/auths-node/tests/production_assembly.rs` (new); `product/integrations/auths-opentofu/src/service.rs:82-125`; `product/integrations/auths-postgresql/src/service.rs:75-115`; `product/integrations/auths-github/src/service.rs:57-135`; `product/stores/auths-stores/src/lib.rs:7-12`; `product/integrations/auths-custody-aws-kms/src/lib.rs:164-328`; `product/integrations/auths-custody-pkcs11/src/lib.rs:165-308`; `demos/open-production-reference/Dockerfile:1-10`; `demos/open-production-reference/config/production.example.toml:1-36`; `demos/open-production-reference/deploy/kubernetes/base/config-map.yaml:6-35`; `demos/open-production-reference/deploy/kubernetes/base/deployment.yaml:36-63`; `demos/open-production-reference/tests/production-smoke.sh` (new); `demos/open-production-reference/README.md:7-13`

**What is true today**

The executable loads the configuration and immediately rejects it when `sandbox_providers = false`; only the sandbox branch constructs a runtime, using a fixture seed and `PostgresSandboxStore` (`product/runtime/auths-node/src/main.rs:64-98`). The production port traits and `ClosedProfileRegistry` exist (`product/runtime/auths-node/src/profiles.rs:158-338`), but repository-wide searches found no implementations of the five production port traits and no construction of `ClosedProfileRegistry`. Meanwhile, the production Kubernetes configuration sets production mode and disables sandbox providers, and its Deployment runs the stock image (`demos/open-production-reference/deploy/kubernetes/base/config-map.yaml:6-35`; `demos/open-production-reference/deploy/kubernetes/base/deployment.yaml:36-63`).

```rust
// product/runtime/auths-node/src/main.rs:64-70
let config = NodeConfig::from_path(Path::new(&config_path))?;
if !config.sandbox_providers() {
    if command.as_deref() == Some("doctor") {
        println!("{}", serde_json::to_string_pretty(&config.doctor(false))?);
    }
    return Err("production ports must be assembled with the auths-node library".into());
}
```

**Why this blocks launch**

The primary deployment artifact cannot start in the configuration it ships. A README instruction that operators must assemble the library themselves (`demos/open-production-reference/README.md:7-13`) does not make the supplied image or manifest a runnable production reference. This blocks deployment validation, production end-to-end evidence, operational qualification, and any honest claim that the three ratified integrations are available through the node.

**Evidence**

The exact production doctor invocation reports the configured surface and then refuses assembly:

```text
$ ./target/debug/auths-node demos/open-production-reference/config/production.example.toml doctor
{
  "ready": false,
  "sections": [
    {"name":"Configuration","status":"PASS","detail":"contract 1 / auths.open-production/1"},
    {"name":"Lifecycle DB","status":"FAIL","detail":"TLS / auths.lifecycle.postgresql/3"},
    {"name":"Custody","status":"PASS","detail":"aws-kms-p256-v1"},
    {"name":"Profiles","status":"PASS","detail":"auths.opentofu.saved-plan-apply/1 / auths.postgresql.bounded-update/1 / auths.github.issue-address/1"}
  ]
}
auths-node: production ports must be assembled with the auths-node library
exit=1
```

The failure is unconditional for production configurations at `product/runtime/auths-node/src/main.rs:64-70`. The Dockerfile compiles that executable into the runtime image (`demos/open-production-reference/Dockerfile:1-10`), rather than a separate operator-provided binary.

The production port/registry construction search returned no implementations or call sites:

```text
$ rg -n 'impl (AuthorityPort|ExactProfilePort|WorkflowPort|ReceiptPort|ReadinessPort)|ClosedProfileRegistry::(new|with_profile)' --glob '*.rs' .
(no output)

$ rg -n 'impl .*AwsKmsApi|impl .*Pkcs11Api' product/integrations/auths-custody-aws-kms/src/lib.rs product/integrations/auths-custody-pkcs11/src/lib.rs
product/integrations/auths-custody-aws-kms/src/lib.rs:406:    impl AwsKmsApi for FakeKms {
product/integrations/auths-custody-pkcs11/src/lib.rs:415:    impl Pkcs11Api for FakeToken {
```

**Required end state**

One supported, stock production image constructs the kernel authority, PostgreSQL lifecycle store, configured custody implementation, durable workflow/receipt stores, and the three closed qualified profile services. `doctor` probes the exact assembled dependencies, the server becomes ready only when required dependencies are usable, and the checked-in Kubernetes base plus AWS overlay can run that same image without source customization.

**How to implement**

1. Add an `auths-node` production assembly module implementing `AuthorityPort`, `ExactProfilePort`, `WorkflowPort`, `ReceiptPort`, and `ReadinessPort`, then construct `ClosedProfileRegistry` from it.
2. Adapt the already-qualified `SavedPlanService`, `BoundedUpdateService`, and `GitHubIssueWorkflowService` rather than duplicating profile logic.
3. Use `auths_stores::PostgresLifecycleStore` for production lifecycle state. Supply concrete, non-test `AwsKmsApi` and `Pkcs11Api` clients to the existing custody adapters; expose the currently private custody configuration through bounded typed getters rather than reparsing TOML.
4. Wire the production branch in `main.rs` and make missing dependencies fail closed with section-specific doctor output.
5. Add a production assembly integration test using test doubles plus one containerized PostgreSQL path. Add `tests/production-smoke.sh` to build the stock image, apply the checked-in Kubernetes base/selected custody overlay to a disposable cluster with bounded test providers, wait for `/ready`, and exercise all three profiles.
6. Complete LR-002’s idempotency/recovery interface before freezing this assembly’s public request contract.

**Blast radius**

This touches the highest-risk composition seam: custody, lifecycle durability, profile providers, recovery, receipts, readiness, packaging, and deployment configuration. Keep the existing sandbox branch for local fixtures, make production adapters narrow wrappers around qualified services, and do not allow production configuration to fall back to sandbox providers. If the production request schema changes under LR-002, assign the next `auths.product.open-production-contract` version before regenerating the semantic freeze (`release/semantic-freeze.json:851-874`).

**How to verify it worked**

```text
cargo test -p auths-node
cargo test -p auths-node --test production_assembly
cargo xtask production-contract
demos/open-production-reference/tests/production-smoke.sh
cargo xtask ci compliance
```

Acceptance requires a healthy production `doctor`, `/ready`, and one create/delegate/verify plus execute/status/receipt flow for each enabled profile through the stock image. It must also include a negative test proving production configuration cannot instantiate sandbox custody, stores, or providers.

**Rollback**

Keep production assembly behind the existing explicit production mode while sandbox mode remains unchanged. If an individual qualified profile fails qualification, disable only that profile in the closed registry; do not ship a production mode that silently substitutes fixtures. A release containing no runnable production assembly is not an acceptable fallback for v1.0.

### LR-002 — Make deadlines effect-safe and bound blocking admission

- **Severity:** blocker
- **Area:** HTTP runtime, effect recovery, and resource admission
- **Estimated effort:** 6–8 engineering days
- **Depends on:** —
- **Files:** `product/runtime/auths-node/src/api.rs:102-145`; `product/runtime/auths-node/src/api.rs:250-385`; `product/runtime/auths-node/src/config.rs:16-30`; `product/runtime/auths-node/src/config.rs:174-217`; `product/runtime/auths-node/src/config.rs:262-405`; `product/runtime/auths-node/src/kernel.rs:428-545`; `product/runtime/auths-node/src/profiles.rs:158-338`; `product/runtime/auths-node/tests/effect_deadlines.rs` (new); `product/runtime/auths-production-client/src/lib.rs:250-387`; `product/runtime/auths-production-client/src/lib.rs:474-595`; `product/fixtures/v1/production-client/contract-v1.json:1`; `product/fixtures/v1/production-client/manifest.json:1`; `bindings/typescript/src/production-client.ts:153-162`; `bindings/typescript/src/production-client.ts:252-335`; `bindings/python/python/auths/_production_client.py:248-303`; `bindings/python/python/auths/_production_client.py:338-372`; `demos/open-production-reference/config/local.toml:1-34`; `demos/open-production-reference/config/production.example.toml:1-36`; `demos/open-production-reference/deploy/kubernetes/base/config-map.yaml:6-35`

**What is true today**

The router applies a blanket `TimeoutLayer` to all routes but no concurrency or queue limit (`product/runtime/auths-node/src/api.rs:102-145`). Every runtime call, including effectful execution and recovery, is put into `tokio::task::spawn_blocking` (`product/runtime/auths-node/src/api.rs:250-385`). Dropping the awaiting future at the HTTP deadline does not cancel that blocking closure. The Rust production client recognizes that a post-transmission transport failure can mean an unknown effect (`product/runtime/auths-production-client/src/lib.rs:480-585`), but TypeScript and Python still synthesize narrower transport results (`bindings/typescript/src/production-client.ts:252-301`; `bindings/python/python/auths/_production_client.py:248-303`). The server currently mints the recovery reference after processing, so a lost response cannot communicate it to the client (`product/runtime/auths-node/src/kernel.rs:428-545`).

```rust
// product/runtime/auths-node/src/api.rs:138-143,376-385
.layer(TimeoutLayer::with_status_code(
    StatusCode::REQUEST_TIMEOUT,
    config.request_timeout(),
))

async fn call_runtime<T>(
    call: impl FnOnce() -> Result<T, RuntimeFailure> + Send + 'static,
) -> Result<T, RuntimeFailure>
where
    T: Send + 'static,
{
    tokio::task::spawn_blocking(call)
        .await
        .unwrap_or(Err(RuntimeFailure::Unavailable))
}
```

**Why this blocks launch**

A caller can receive HTTP 408, retry, and cause or collide with an effect that is still executing. With no client-known operation key, the caller cannot reliably reconcile the first attempt if its response is lost. Unbounded `spawn_blocking` admission also lets a request burst occupy an unbounded blocking queue, defeating the advertised timeout as a resource bound. For money, infrastructure, database, and GitHub mutations, this is an effect-safety and recovery-contract failure rather than a generic availability issue.

**Evidence**

A temporary integration test used a `NodeRuntime` whose `handle` slept for 250 ms and then set an atomic flag. The router deadline was 100 ms. These are the verbatim retained failure lines:

```text
$ cargo test -p auths-node --test launch_readiness_tmp -- --nocapture
running 1 test
effectful work continued after the server returned its timeout response
timeout_status=408 Request Timeout completed_after_timeout=true
error: test failed, to rerun pass `-p auths-node --test launch_readiness_tmp`
```

The material test source was:

```rust
struct SlowRuntime(Arc<AtomicBool>);

impl NodeRuntime for SlowRuntime {
    fn handle(&self, _: ProductionRequest) -> Result<ProductionResponse, RuntimeFailure> {
        std::thread::sleep(Duration::from_millis(250));
        self.0.store(true, Ordering::Release);
        completed_response()
    }
    // The remaining trait methods returned bounded typed test failures.
}

#[tokio::test]
async fn timed_out_effectful_work_must_not_continue_detached() {
    let completed = Arc::new(AtomicBool::new(false));
    let mut config = test_config();
    config.request_timeout_ms = 100;
    let router = app(&config, Arc::new(SlowRuntime(Arc::clone(&completed))), accepting());
    let response = router.oneshot(valid_execute_request()).await.unwrap();
    let timeout_status = response.status();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let completed_after_timeout = completed.load(Ordering::Acquire);
    println!("timeout_status={timeout_status} completed_after_timeout={completed_after_timeout}");
    assert!(
        !completed_after_timeout,
        "effectful work continued after the server returned its timeout response"
    );
}
```

The throwaway test file was deleted after execution. The result follows directly from the timeout wrapping `spawn_blocking` at `product/runtime/auths-node/src/api.rs:138-143` and `product/runtime/auths-node/src/api.rs:376-385`.

**Required end state**

Before any provider entry, each effectful request has a client-generated opaque operation key mapped durably to a recovery record. Replays with the same key are idempotent. If a deadline or connection loss happens after transmission, every supported SDK returns outcome-unknown/reconcile with the already-known recovery handle. The server never emits a bare timeout that suggests an effectful request stopped. Blocking admission has explicit maximum in-flight and queue bounds, overload behavior is typed and fail-closed, and non-effectful read deadlines remain conventional and bounded.

**How to implement**

1. Add a client-generated operation key/recovery handle to `ProductionRequest` before transmission; this is the clean pre-1.0 point for that protocol change.
2. Persist an accepted/recoverable record before entering the provider, pass cancellation/deadline context only to adapters that can honor it, and otherwise let the durable workflow own completion.
3. Split blanket router timeout behavior: retain short timeouts for health/read-only routes, but have effectful routes return a protocol response tied to the durable handle.
4. Add `maximum_in_flight_requests` and a bounded wait/queue policy to `NodeConfig`, acquire a permit before `spawn_blocking`, and reject overload before effects begin.
5. Bring Rust, TypeScript, and Python transport classifiers to one decision table.
6. Add tests for lost response, deadline before/after durable admission, same-key replay, overload, process restart, and status reconciliation.

**Blast radius**

This changes the pre-1.0 production wire request, SDK behavior, runtime traits, configuration, persistence, and provider adapters. It should not change proof semantics. Assign a new `auths.product.open-production-contract` version and, if installed SDK surface changes, `auths.product.public-sdk-contract` (currently recorded at `release/semantic-freeze.json:851-918`). The largest migration risk is accidental duplicate execution, so do not implement the handle only as an in-memory cache.

**How to verify it worked**

```text
cargo test -p auths-node --test effect_deadlines
cargo test -p auths-node --test production_assembly
cargo test -p auths-production-client
npm test --prefix bindings/typescript
pytest -q bindings/python/tests
cargo xtask ci compliance
```

The negative control above must pass with `completed_after_timeout=false` only when the provider was never durably admitted; the admitted case must instead return a client-known handle and converge through status lookup. A load test must prove the configured in-flight/queue maximum is never exceeded.

**Rollback**

Because this is a correctness contract, do not feature-flag the unsafe behavior in production. A short-lived compatibility decoder may accept the old request only in sandbox mode. Production rollout can gate provider execution on the durable-admission capability and remain not-ready until its backing store is available.

### LR-003 — Complete the absent-budget cutover atomically across SDKs and Lean

- **Severity:** blocker
- **Area:** Core semantics, MCP bindings, generated vectors, and formal model
- **Estimated effort:** 3 engineering days
- **Depends on:** —
- **Files:** `core/crates/auths-model/src/lib.rs:927-946`; `core/crates/auths-authority/src/lib.rs:330-345`; `product/profiles/auths-profile-mcp/src/lib.rs:234-251`; `product/profiles/auths-profile-mcp/src/lib.rs:354-370`; `bindings/wasm/auths-proof-wasm/examples/generate-node-vectors.rs:194-250`; `bindings/typescript/test/integration/profiles/mcp.test.js:219-248`; `bindings/python/tests/test_mcp_workflow.py:319-337`; `formal/Auths/VectorExport.lean:142`; `formal/Auths/Rich/Semantics.lean:28`; `formal/Auths/Rich/Theorems.lean:138`

**What is true today**

The Rust kernel now answers the intended rule: when a parent has a ceiling and the request supplies no computed budget, coverage is false (`core/crates/auths-model/src/lib.rs:927-946`), and authority verification delegates that decision to the kernel (`core/crates/auths-authority/src/lib.rs:330-345`). MCP canonicalization supplies no requested budget (`product/profiles/auths-profile-mcp/src/lib.rs:234-251`; `product/profiles/auths-profile-mcp/src/lib.rs:354-370`), but the Node-vector generator still creates budgeted MCP trust anchors and grants (`bindings/wasm/auths-proof-wasm/examples/generate-node-vectors.rs:194-250`). TypeScript and Python MCP tests also construct budgeted delegations and expect authorization (`bindings/typescript/test/integration/profiles/mcp.test.js:219-248`; `bindings/python/tests/test_mcp_workflow.py:319-337`). At clean `f82cb08`, Lean's exported vector, semantics, and proof retain the old true outcome (`f82cb08:formal/Auths/VectorExport.lean:142-146`; `f82cb08:formal/Auths/Rich/Semantics.lean:28-35`; `f82cb08:formal/Auths/Rich/Theorems.lean:138-146`). Concurrent uncommitted changes now alter those formal files, but they have not removed the still-failing SDK/generator half of this blocker and were not part of the retained green `lake build`.

```rust
// core/crates/auths-model/src/lib.rs:938-945
match (ceiling, requested) {
    (None, _) => true,
    (Some(_), None) => false,
    (Some(ceiling), Some(requested)) => ceiling.covers(requested),
}

// bindings/wasm/auths-proof-wasm/examples/generate-node-vectors.rs:205-208
Some(auths_model::BudgetCeiling::new(
    auths_model::BudgetAlgebraId::parse("numeric-ceiling-v1")?,
    20,
)),
```

**Why this blocks launch**

The kernel change is the correct safety direction, but releasing midway through the cutover makes supported language paths disagree about authorization. The compliance suite already fails 16 tests, including outcome changes from `authorized`/`indeterminate` to `denied` and error changes to `budget-ceiling-exceeded`. Formal artifacts then document a rule the executable kernel no longer implements. This is not one of the two red gates intentionally allowed by the launch brief.

**Evidence**

Representative verbatim TypeScript assertion excerpts from the compliance run are:

```text
# Subtest: inspection exposes copied bounded evidence and no capability
Expected values to be strictly equal:
+ actual - expected
+ 'denied'
- 'authorized'
# Subtest: MCP authorization preserves indeterminate as a value
+ 'denied'
- 'indeterminate'
# Subtest: MCP authorization preserves denial as a value
+ 'budget-ceiling-exceeded'
- 'invalid-signature'
# pass 78
# fail 16
xtask: npm test failed with exit status: 1
```

Commit `ac5b968` itself records that `formal/Auths/VectorExport.lean:142` still expects the old result. The source mismatch explains the failures without weakening the new kernel rule.

**Required end state**

MCP is explicitly budgetless from trust-anchor and grant construction through all supported SDK fixtures: it supplies no parent ceiling and no delegated budget. Budget-bearing profiles derive an explicit requested budget before asking the kernel; they do not rely on absent-budget inheritance. Lean returns false for `(some ceiling, no requested budget)` and proves the executable rule. Generated vectors, TypeScript, Python, Rust, and formal refinement tests all agree.

**How to implement**

1. Remove budgets from MCP trust anchors/grants and delegation helpers in the vector generator and language tests.
2. Regenerate binding vectors and checked-in diffs.
3. Review and complete the in-progress uncommitted Lean/vector edits, ensure the three assessed locations implement the terminal kernel rule, and prove the changed branch.
4. Audit every qualified money/bounded profile for explicit requested-budget derivation, but preserve generic core testkit cases that deliberately exercise budget coverage.
5. Do not restore the former fallback or special-case MCP in the kernel.
6. Once all semantic edits are complete, assign the next `auths.core.protocol` version and update the freeze once, not piecemeal (`release/semantic-freeze.json:72-90`).

**Blast radius**

The deliberate behavior change affects any caller that issued a parent budget ceiling but omitted the requested computed budget. That is a protocol-level semantic change, while the MCP fixture cleanup removes an incoherent feature from a profile that cannot compute the budget. Explicitly version it, regenerate every binding corpus, and call it out in migration notes. The principal risk is hiding a real money-profile omission by deleting its ceiling; those profiles must instead calculate the request budget.

**How to verify it worked**

```text
cargo test -p auths-model
cargo test -p auths-authority
cargo test -p auths-formal-refinement
npm test --prefix bindings/typescript
pytest -q bindings/python/tests/test_mcp_workflow.py
cd formal && lake build
cargo xtask ci compliance
```

Add one shared vector for each of `(ceiling, no request) => denied`, `(ceiling, covered request) => allowed`, `(ceiling, excessive request) => denied`, and `(no ceiling, no request) => allowed`, and require all supported bindings plus Lean refinement to consume it.

**Rollback**

Do not roll back by weakening the kernel. If the cross-language cutover cannot land atomically, hold the release or temporarily remove the affected profile from the supported surface. A semantic compatibility mode that authorizes an absent request budget would reintroduce the v1 safety ambiguity.

### LR-004 — Synchronize active error lifecycle metadata with the registry

- **Severity:** blocker
- **Area:** Release evolution policy
- **Estimated effort:** 0.5 engineering day
- **Depends on:** —
- **Files:** `release/evolution-lifecycle-v1.json:1-65`; `docs/product/COMPATIBILITY_AND_SUPPORT.md:1-87`; `release/semantic-freeze.json:1015-1037`

**What is true today**

The Rust registry contains 48 active codes while the lifecycle metadata contains 45. The evolution-policy implementation requires exact set equality (`xtask/src/evolution_policy.rs:285-315`), so both authoritative CI and release-check stop immediately. The missing codes are the three new core authorization/principal results.

```rust
// xtask/src/evolution_policy.rs:312-315
if registered != active || lifecycle.len() != registry.errors.len() {
    return Err(
        "active error lifecycle metadata does not exactly cover the Rust registry".to_owned(),
    );
}
```

**Why this blocks launch**

This blocks the authoritative and release gates and leaves public compatibility metadata incomplete for errors that supported callers can receive. It is mechanically small, but it is a blocker because no v1.0 candidate should bypass the repository's own evolution contract.

**Evidence**

```text
$ comm -13 /tmp/auths-lifecycle-codes.txt /tmp/auths-registry-codes.txt
core.authorization-denied
core.authorization-indeterminate
core.unauthenticated-principal

$ wc -l /tmp/auths-lifecycle-codes.txt /tmp/auths-registry-codes.txt
45 /tmp/auths-lifecycle-codes.txt
48 /tmp/auths-registry-codes.txt
93 total
```

The gate output is reproduced in the Baseline section. Updating the generated support document alone cannot fix this: the update path validates lifecycle data before writing it (`xtask/src/evolution_policy.rs:194-229`).

**Required end state**

All 48 active registry codes have active lifecycle entries, with `final_version` and replacement fields unset where appropriate, and the generated compatibility/support table reflects them. The authoritative and release gates advance past evolution policy without an exception or allowance.

**How to implement**

1. Add sorted active entries for `core.authorization-denied`, `core.authorization-indeterminate`, and `core.unauthenticated-principal` to `release/evolution-lifecycle-v1.json`.
2. Run the supported evolution-policy update to regenerate `docs/product/COMPATIBILITY_AND_SUPPORT.md`.
3. Review the public descriptions and migration meaning.
4. Assign the next `auths.release.evolution-contract` version, then update semantic freeze in the final versioning batch (`release/semantic-freeze.json:1015-1037`).

**Blast radius**

Low implementation risk, but the metadata is a public compatibility promise. The entries must describe active v1 codes rather than marking them deprecated or aliasing semantically distinct denied, indeterminate, and unauthenticated outcomes.

**How to verify it worked**

```text
cargo xtask evolution-policy
cargo xtask ci authoritative
cargo xtask release-check
```

The latter two may then stop only at a separately known gate; they must no longer mention lifecycle coverage.

**Rollback**

There is no runtime feature flag. If the three codes are not actually part of v1, remove them atomically from the public Rust registry and every consumer instead of leaving an incomplete lifecycle set. The current mixed state must not ship.

### LR-005 — Put adversarial conformance on the aggregate release path

- **Severity:** major
- **Area:** Compliance and release gating
- **Estimated effort:** 1 engineering day
- **Depends on:** —
- **Files:** `xtask/src/checks.rs:73-87`; `xtask/src/compliance.rs:5-20`; `xtask/src/compliance.rs:502-539`; `xtask/src/conformance.rs:5-190`

**What is true today**

There is an `adversarial-conformance` command and it correctly detects mismatched expected outcomes, but neither the `ci_compliance` aggregate in `xtask/src/checks.rs:73-87` nor the standalone compliance composition in `xtask/src/compliance.rs:5-20` invokes it. `release-check` delegates to aggregate CI (`xtask/src/release.rs:138-159`). Consequently, negative corpus expectations can drift while the positive `conformance` command remains green.

```rust
// xtask/src/checks.rs:73-87
pub(crate) fn ci_compliance() -> Result<(), String> {
    let compliance_inventory = compliance_inventory()?;
    abi()?;
    exchange_conformance()?;
    product_conformance()?;
    product_fixtures(false)?;
    stripe_profiles()?;
    bounded_domains()?;
    matrix()?;
    bindings_conformance()?;
    package_check()?;
    wasm()?;
    live_demo()?;
    write_compliance_report(&compliance_inventory)
}
```

**Why this blocks launch**

The adversarial corpus is evidence that failures are classified correctly at hostile boundaries, not just that canonical successes work. An opt-in command provides no release assurance if a release engineer can run every documented aggregate gate without executing it. This is major rather than blocker because the checker itself works and the fix is narrowly in gate composition.

**Evidence**

As a controlled negative test, the first manifest case's expected code at `core/conformance/v1/manifest.json:9` was temporarily changed from `verifier-configuration-mismatch` to `invalid-signature`:

The following are the verbatim result fields from that run (the long manifest digest is omitted, not abbreviated):

```text
$ ./target/debug/xtask conformance
target V1 canonical corpus conformance passed
exit=0

$ ./target/debug/xtask adversarial-conformance --case context/raw-key-chain/configuration-bitflip/full-verifier
{
 "schema":"auths-proof-conformance-result/v1",
 "cases":1,"passed":0,"failed":1,
 "coverage":{"context_fields":"1/14","principal_methods":"0/7","common_contract":"0/7"},
 "executions":[{"case":"context/raw-key-chain/configuration-bitflip/full-verifier","boundary":"full-verifier","expected_code":"invalid-signature","actual_code":"verifier-configuration-mismatch","passed":false}]
}
xtask: 1 of 1 adversarial conformance cases failed
exit=1
```

After restoring the manifest, the same targeted command reported one case passed, zero failed, with expected and actual both `verifier-configuration-mismatch`. The mutation left no source diff.

**Required end state**

`cargo xtask ci compliance`, the standalone compliance command, authoritative CI, and `release-check` all execute the full adversarial corpus and fail on any case mismatch. Their report clearly identifies case, boundary, expected code, and actual code. One checked regression test proves aggregate composition cannot silently drop this gate.

**How to implement**

1. Invoke `adversarial_conformance(Vec::new())` from both aggregate composition points, adjacent to target/corpus conformance.
2. Preserve the targeted subcommand for diagnosis.
3. Add a gate-composition test or CI negative control that mutates a temporary copy/fixture manifest rather than the canonical corpus, then asserts aggregate compliance fails.
4. If aggregate reports enumerate constituent checks, record adversarial conformance explicitly there as well.

**Blast radius**

Runtime behavior is unchanged. CI duration increases by the adversarial corpus runtime, and previously hidden expectation drift may become newly visible. Because `xtask/src/checks.rs` is covered by release metadata, include any resulting `auths.release.public-surface` freeze change in the final semantic-version batch rather than accepting an unexplained drift (`release/semantic-freeze.json:1040-1135`).

**How to verify it worked**

```text
cargo xtask adversarial-conformance
cargo xtask ci compliance
cargo xtask release-check
```

Repeat the controlled one-case mismatch against a temporary corpus and require all aggregate paths to fail. Restore it and require all paths to pass.

**Rollback**

Do not feature-flag a release gate off. If corpus runtime is temporarily excessive, shard it deterministically while requiring all shards for release. Keep the targeted command for local iteration, not as a substitute for aggregate execution.

### LR-006 — Make configured OTLP export real and observable

- **Severity:** major
- **Area:** Operations telemetry and readiness
- **Estimated effort:** 4–6 engineering days
- **Depends on:** LR-001
- **Files:** `product/runtime/auths-node/Cargo.toml:10-39`; `product/runtime/auths-node/src/config.rs:16-30`; `product/runtime/auths-node/src/config.rs:73-78`; `product/runtime/auths-node/src/config.rs:174-217`; `product/runtime/auths-node/src/config.rs:262-405`; `product/runtime/auths-node/src/api.rs:71-78`; `product/runtime/auths-node/src/api.rs:102-113`; `product/runtime/auths-node/src/api.rs:289-325`; `product/runtime/auths-node/src/main.rs:55-120`; `product/runtime/auths-node/src/shutdown.rs:10-18`; `product/runtime/auths-node/tests/otlp_export.rs` (new); `product/operations/auths-operations-otel/Cargo.toml:10-14`; `product/operations/auths-operations-otel/src/lib.rs:52-168`; `demos/open-production-reference/config/local.toml:20-22`; `demos/open-production-reference/config/production.example.toml:22-24`; `demos/open-production-reference/deploy/kubernetes/base/config-map.yaml:6-35`; `demos/open-production-reference/compose/otel/collector.yaml:1-25`; `demos/open-production-reference/README.md:40-50`

**What is true today**

The node parses and validates an OTLP endpoint and service name (`product/runtime/auths-node/src/config.rs:73-78`) but has no public getters or runtime consumer for them. `AppState` contains only a `PrometheusProjection`, and every recorded operation goes only to it (`product/runtime/auths-node/src/api.rs:102-113`; `product/runtime/auths-node/src/api.rs:289-325`). The operations crate contains a bounded in-memory `BoundedOtlpExporter` and `CombinedSink` abstraction (`product/operations/auths-operations-otel/src/lib.rs:52-168`), but no node path instantiates a network exporter. Doctor's summary hard-codes the telemetry family and has no telemetry health section (`product/runtime/auths-node/src/config.rs:346-405`). The demo collector accepts OTLP, but also scrapes Prometheus; node events reach only the latter (`demos/open-production-reference/compose/otel/collector.yaml:1-25`).

```rust
// product/runtime/auths-node/src/api.rs:71-78,318-325
struct AppState {
    runtime: Arc<dyn NodeRuntime>,
    release: Arc<str>,
    semantic_id: Arc<str>,
    accepting: Arc<AtomicBool>,
    metrics: Arc<PrometheusProjection>,
}

state.metrics.record(&OperationalEventV2::runtime(
    None,
    operation_stage,
    outcome,
    reason,
    elapsed,
));
```

**Why this blocks launch**

The reference documentation claims privacy-safe OTLP operations export (`demos/open-production-reference/README.md:40-50`), while the configuration has no effect. Operators can believe forensic events are leaving the process when they are not. Prometheus aggregate metrics reduce this from blocker to major, but they do not provide the bounded event evidence or exporter health implied by the operations contract.

**Evidence**

Repository-wide searches for the OTLP endpoint and service-name fields found only parsing, validation, and configuration tests; no runtime getter or exporter construction. `record_operation` ends with `state.metrics.record(...)` at `product/runtime/auths-node/src/api.rs:289-325`. The production doctor evidence in LR-001 contains only Configuration, Lifecycle DB, Custody, and Profiles—no Telemetry section—despite OTLP being mandatory configuration.

```text
$ rg -n 'otlp_endpoint|service_name' product/runtime/auths-node/src product/operations/auths-operations-otel/src demos/open-production-reference/compose/otel/collector.yaml
product/runtime/auths-node/src/api.rs:537:otlp_endpoint = "http://otel:4317"
product/runtime/auths-node/src/api.rs:538:service_name = "auths-node"
product/runtime/auths-node/src/config.rs:76:    otlp_endpoint: String,
product/runtime/auths-node/src/config.rs:77:    service_name: String,
product/runtime/auths-node/src/config.rs:198:        if !self.telemetry.otlp_endpoint.starts_with("http://")
product/runtime/auths-node/src/config.rs:199:            && !self.telemetry.otlp_endpoint.starts_with("https://")
product/runtime/auths-node/src/config.rs:203:        if !valid_label(&self.telemetry.service_name, 96) {
product/runtime/auths-node/src/config.rs:471:otlp_endpoint = "http://otel:4317"
product/runtime/auths-node/src/config.rs:472:service_name = "auths-node"

$ rg -n 'BoundedOtlpExporter|CombinedSink' product/runtime/auths-node/src
(no output)
```

**Required end state**

When OTLP is configured, the node sends the bounded `OperationalEventV2` stream to that endpoint while retaining the Prometheus projection. Queue capacity, batching/flush timing, and backpressure policy are explicit configuration with bounded memory. Export success, failures, and dropped-event counts are observable. Readiness follows a ratified policy: recommended `DropNewest` degradation does not stop authorization but is prominently unhealthy/degraded, while a configured blocking/fail-closed assurance mode affects readiness. Shutdown performs a bounded final flush. Doctor probes exporter configuration/connectivity and reports Telemetry separately.

**How to implement**

1. Expose validated telemetry getters in `NodeConfig`.
2. Add a real OTLP transport around the existing bounded exporter, instantiate `CombinedSink` in production assembly, and store an `Arc<dyn EventSink>` in `AppState` while preserving `/metrics`.
3. Add a bounded export worker with explicit capacity, retry/backoff, flush interval, counters, and shutdown deadline; never place secrets or unbounded labels in events.
4. Extend doctor/readiness and the Kubernetes/local configuration with the selected failure policy.
5. Add a collector-backed integration test proving one known event arrives, plus unavailable-collector, full-queue, restart, and shutdown tests.

**Blast radius**

This adds a network task, dependency, shutdown work, and operational behavior. A blocking exporter must never stall the authorization path accidentally. Default to bounded non-blocking behavior unless the operator explicitly selects fail-closed assurance. If the operations event/export contract changes, assign the next `auths.product.operations` version before the final freeze update (`release/semantic-freeze.json:877-896`).

**How to verify it worked**

```text
cargo test -p auths-operations-otel
cargo test -p auths-node --test otlp_export
cargo xtask production-contract
docker compose -f demos/open-production-reference/compose/compose.yaml up --build --wait
demos/open-production-reference/tests/compose-smoke.sh
docker compose -f demos/open-production-reference/compose/compose.yaml exec auths-1 auths-node /etc/auths/local.toml doctor
```

The test must observe a known bounded event at the collector, force a full queue and verify the selected policy/counter, take the collector down and verify readiness semantics, then prove shutdown completes within the configured drain bound.

**Rollback**

The exporter transport may be disabled only by an explicit telemetry mode, with doctor and readiness accurately reporting that state; configuration must never claim OTLP while silently emitting only Prometheus. If transport causes instability, switch to bounded `DropNewest`, preserve failure/drop counters, and keep authorization isolated while repairing export.

## Recommended execution order

1. **LR-004 first:** unblock authoritative/release execution so subsequent work receives full gate feedback.
2. **LR-003 second:** finish the already-started semantic cutover atomically and restore cross-language/formal agreement without weakening the kernel.
3. **LR-002 third:** ratify and implement the pre-transmission operation key, durable recovery, effect-safe deadline behavior, and bounded admission; this defines production runtime interfaces.
4. **LR-001 fourth:** assemble production ports and qualified services against LR-002's final interfaces, then qualify the stock image and Kubernetes reference.
5. **LR-006 fifth:** attach real OTLP export to the production assembly and exercise it with the reference collector.
6. **LR-005 in parallel with LR-001/LR-006:** wire the already-working adversarial checker into aggregates and add the negative control.
7. **Version/freeze only after semantic work settles:** assign every affected identity once, update semantic freeze, qualify the formal source closure, then run compliance, authoritative CI, and release-check from a clean tree.

## Disagreements with the prior audit

1. The prior main audit correctly identified client/server transport ambiguity and a bare server timeout, then proposed surfacing a recovery reference (`docs/target-state/v1-api-review-findings.md:319-350`). That is necessary but not sufficient: a server-random reference carried only in the lost response cannot help the caller. The temporary runtime test proves the server can return 408 while an effect continues. LR-002 therefore requires a client-known operation key/recovery handle established before transmission and durable admission before effects.
2. The prior audit correctly classified absent-budget inheritance as a blocker and prescribed one kernel answer (`docs/target-state/v1-api-review-findings.md:394-405`). Commit `ac5b968` implements that kernel answer, so this assessment does not reopen the decision. It finds new cutover collateral: supported MCP SDK fixtures and Lean still encode the old result, and current compliance fails 16 tests. The blocker remains open until the atomic cross-language/formal cutover is complete.
3. The earlier `auths-node` kernel-rebuild concern was materially addressed by `d82d57f`; it is not repeated here. LR-001 is narrower and newly evidenced: the stock production executable and the checked-in Kubernetes production configuration are mutually incompatible even though the library now has a closed runtime abstraction.

## Areas examined that the prior audit did not cover

- The exact executable built into the open-production Docker image and its compatibility with the Kubernetes base/AWS production configuration.
- Runtime cancellation semantics of Tower deadlines around `spawn_blocking`, demonstrated through a throwaway effect-continuation test.
- Blocking admission bounds and the absence of a client-known pre-transmission recovery key.
- Aggregate-gate composition under a controlled adversarial-corpus mutation.
- Exact error-registry versus evolution-lifecycle set equality.
- End-to-end consumption of OTLP configuration, event sinks, collector wiring, doctor output, and shutdown/readiness policy.

## Unresolved

- A real production end-to-end run cannot be performed until LR-001 supplies a production assembly; that missing evidence is itself part of the blocker rather than a reason to infer readiness.
- The full compliance command did not reach Python and later stages because TypeScript failed first. After LR-003, rerun it from the beginning and retain the complete report.
- `cargo xtask formal` remains intentionally red until the Aeneas source-closure digest is qualified. The retained `lake build` was green before the concurrent uncommitted formal edits; settle those edits, then run `cd formal && lake build` and `cargo test -p auths-formal-refinement` before updating the closure.
- Sustained production qualification, independent review, and the 30-day assurance window remain non-code release evidence outside this code-readiness assessment (`release/assurance/open-production-candidate-1/summary.md:3-15`).
- Provider sandbox credentials and a production-grade custody/lifecycle environment were not available. No claim of real AWS KMS, PKCS#11, GitHub, PostgreSQL mutation, or OpenTofu apply qualification is made here.

## Coverage statement

This assessment read the repository instructions and required abstraction plan, the ratified v1 API contract, every commit from `bbeb654` through current `HEAD`, and both prior main/bindings API audits before testing. It examined the core budget decision, authority use, MCP canonicalization, generated binding vectors, supported TypeScript/Python MCP paths, Lean semantics, evolution policy, compliance/release composition, adversarial corpus behavior, production client transport classification, node routing/runtime/configuration/profiles/kernel, qualified integration service seams, stores/custody exports, open-production Docker/Kubernetes/collector assets, telemetry sinks, and semantic-freeze ownership. It ran the authoritative, release, semantic-freeze, formal, Lean, compliance, production-doctor, detached-effect, and adversarial-mutation checks described above. It deliberately did not read `docs/prompts/LAUNCH_READINESS_INVESTIGATIONS.md`, did not treat the anticipated semantic-freeze/formal closure failures as findings, did not exhaustively re-audit unrelated crates or duplicate previously accepted API findings, and did not claim supply-chain, performance, fuzz-duration, or live-provider evidence that was not run. The temporary corpus mutation was restored and the temporary Rust integration test was deleted; this document is the only assessment artifact added by this work.
