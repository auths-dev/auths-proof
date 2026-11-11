# AP078 implementation and evidence record

Contract: [AP-SPEC-078](../specs/0078-residual-state-ownership.md).
Baseline: `e40bfdd32e3812ef349bb2db84faada443cb1938` (merged PR #217).
Branch: `codex/residual-state-ownership`.

## Acceptance boundary

The source audit and implementation are bounded to the owners below. Static
cross-review is not a successful dynamic reproduction, and a generated artifact
constructor is not the complete test suite. Final hosted results and the exact
accepted head belong in the implementation PR's acceptance attestation; recording
those results must not itself change the source revision under test.

No merge, production qualification, global state-machine audit, physical
power-loss guarantee or authorization bypass is claimed by this record.

## Requirement map

Paths below are relative to the repository root.

| Gates | Authoritative owner and regression owner |
| --- | --- |
| S1/S2 | Gateway `src/bin/auths-gateway.rs`: serving and protected endpoint-directory claims, inode-owned cleanup and overdue-drain process termination. Binary tests plus `tests/socket_paths.rs`, with retained operator/process drain tests. |
| Q1/Q2 | `bindings/python-adapters/sqlite/python/auths_sqlite/__init__.py`: retained worker cohort and shared close drain; immutable admission snapshot. `tests/test_sqlite_store.py` uses real commit and worker-entry barriers, cancellation, mutation, failure and reopen. |
| T1 | `bindings/typescript/src/internal/signing.ts`: original deadline and nondecreasing observations through signature acceptance. `test/helpers/signing-deadline-contract.mjs` is consumed by source and installed-package runners. |
| E1 | `exchange/crates/auths-proof-exchange-framing/src/lib.rs`: preflight versus admitted unavailable state. `interruption_tests.rs` controls partial headers/bodies, writes, response waits and shutdown deadlines. |
| E2 | Memory and HTTPS exchange adapters: claimed submission before delivery, unavailable after interruption. Memory tests retain a delivered request; HTTPS `delivery_tests.rs` uses an actual trusted local TLS peer and holds its response after reading the exact canonical request. |
| E3 | `exchange/adapters/auths-iroh`: raw frame/finish ownership; interruption tests use actual local channels, malformed frames, abandoned receive/finish, and an observed peer STOP distinguished from a clean acknowledgement. Existing proof-Iroh conformance remains. |
| K1 | `product/integrations/auths-git-signing/src/custody.rs`: private staged publication and explicit uncertain acknowledgement. Existing unit owner now covers injected failures, actual subprocess termination at publication boundaries, concurrent creators, and a fresh reader after caller-observed success and termination. |
| P1 | `product/stores/auths-stores/src/lifecycle.rs`: usable/unavailable snapshot under the existing mutex. Fault matrix continues through same-instance read/replay/unrelated mutation before validated reopen. |
| B1 | Northstar `src/server.ts`: bounded body admission precedes synchronous current-state transition. `tests/state-ownership.mjs` holds real request bodies to order redemption, firewall and reset histories. |
| U1 | REST demo `web/app.js`: view/operation identity and captured execution context. Existing `tests/web-smoke.mjs` now controls preparation/execution/finally completion orders. |
| V1 | Incident control-room `src/app.ts`: viewer and refresh generations, immediate protected-view clearing and stale login/refresh failure handling. `tests/viewer-scope-contract.mjs` consumes the generated shipped controller, and is called by browser smoke and hosted compliance. |

## Integration and topology

Distinct gateway daemons must use separate protected endpoint parent directories.
The fixed directory claim deliberately serializes differently spelled leaves,
including case aliases, without introducing filesystem collation assumptions.
Multi-daemon test topologies use each installation's own endpoint parents.
Administrative state operations use a separate lock and remain available while
serving. A shutdown deadline reports incomplete work and exits while ownership
is retained; it does not publish a false quiescent state.

Northstar remains a single-process demo server. No new production provider
executor or incident-agent ledger is introduced. The Google refresh rotation
hypothesis, scheduling-only reconciliation leases and asynchronous AWS physical
deletion are dispositioned in AP078 rather than promoted into unproved defects.

The hosted compliance workflow builds Northstar and the control-room through
their maintained TypeScript/build entry points, checks the committed browser
mirror, and executes the new held-request and viewer-generation contracts.
Existing Python, TypeScript package, native workspace, exchange and records-demo
checks retain their coverage. No new duplicate full CI workflow is introduced.

## Static review and generation

Three implementing agents reviewed disjoint areas and cross-reviewed neighboring
changes. Before the first push this caught overdue shutdown ownership, filename
aliases, initially absent sockets in unsafe parents, mutable reservation buffers,
stale OAuth errors, a peer STOP misclassified as acknowledgement, and regression
test synchronization/termination gaps. Tests distinguish these concrete schedules
from authorization and provider-effect claims that the evidence does not support.

Required artifact generation includes the architecture snapshot, reviewed
semantic/source identities, proof-coverage measurements where source coordinates
change, gateway closure/CLI/interface fixtures, and the shipped browser mirror.
Only maintained constructors may update canonical artifacts. Full hosted
verification remains pending until the PR attestation records its final result.

## Collected first-cohort repair

The initial published head `7f2c6bba` passed both SDK package workflows, all 26
Python jobs, Git signing on Linux/macOS and both live signing checks, TLS
PostgreSQL qualification, gateway isolation, SDK recipes, recipe qualification
and the Google demo. Repository preflight stopped on the serving function's
lint length limit; dependent wrapper failures were not separate findings.
The remaining fast proof feedback job was cancelled once the failed revision
could no longer qualify.

The source-free operator simulation and Stripe/Airtable installed/assessment
jobs exposed old multi-daemon launchers sharing one socket parent. Their repair
uses protected per-host parents and passes operator review sockets explicitly,
independently of application endpoint paths. Current assessment consumers and
runbooks follow that topology; historical assessment evidence is unchanged.

The collected repair additionally fixes a redundant test import and makes the
framing fixture visible to its sibling regression module. Preflight now asks
Cargo to keep checking independent targets after a failure, preserving its
failure status while collecting a more complete diagnostic batch.

Bounded repair verification passed workspace/all-target/all-feature Clippy,
the gateway binary's 16 tests and socket-path suite's 18 tests, nine demo-layout
Python units, five held-request Northstar tests, five REST browser tests, and
the viewer contract including actual public-SDK/WASM withdrawal evidence with
network/provider calls forbidden. The source-free Linux root/UID simulations
still require their hosted container jobs; these macOS checks are not substitutes.
Final completed-head verification remains required.

The touched demo launchers additionally delegate all socket recovery/cleanup to
the native owner and wait for a bounded child readiness event rather than a
pathname. Their final 15 Python units cover ready/refused/partial-line children
and preserve existing live and stale socket inodes; retained stdout handles are
closed during restart and cleanup.
