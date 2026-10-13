# AP-SPEC-067: Robust Stripe demo through the general gateway

- **Status:** Proposed. Source audit completed 13 October 2026; no new demo or
  protected qualification is claimed by this document.
- **Depends on:** [AP-SPEC-063](0063-generalized-gateway.md),
  [AP-SPEC-066](0066-production-gateway-polish-and-recipe-qualification.md),
  [ADR 0012](../adr/0012-declarative-credential-isolated-gateway-boundary.md),
  [ADR 0013](../adr/0013-recipe-capabilities-and-sum-budget.md), and the
  [domain boundary plan](../target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md).
- **Companion:** [Airtable demo](0068-airtable-general-gateway-demo.md).
- **Scope:** One maintained platform-account Stripe test-refund demo using
  the shipping general gateway, a data-only recipe and installed public SDKs.
  Provider-specific references and qualification orchestration remain test or
  release code. No Stripe executor is added to the gateway or core.
- **Normative language:** MUST, MUST NOT and SHOULD define requirements.

## 1. Decision

Build the new Stripe demonstration around the general gateway interface.
The application authors and submits proof and canonical action bytes. It never
receives a provider credential and never constructs or sends a Stripe write.
The operator approves the exact recipe and installation; the gateway verifies,
claims, leases, constructs the closed request and records the outcome.

The first maintained effect is a platform-account test refund, without paid
Connect onboarding. Qualifying this effect does not qualify payments,
subscriptions, Connect transfers, payouts or Issuing. Production custody means
the deployment uses its production secret-store and persistence boundaries;
the provider experiment remains explicitly Stripe **test mode**.

The work MUST NOT extend the old profile-specific demo services into a second
production execution path. Existing pure evaluators, fixtures and tests may
inform a reviewed oracle. Each reused behavior needs an explicit comparison
with the recipe; similar operation names do not establish equivalence.

## 2. Audited starting point and actual gaps

The requested `demos/stripe-*` checkout was audited at `393edc52`.
PR [#206](https://github.com/auths-dev/auths-proof/pull/206) was independently
checked on 13 October at candidate `096579ad5d41ac34cfd4a424ab64eed6cf14f9ea`,
and subsequently merged as `f68f8b17` under the owner's explicit instruction. Its release-only machinery is an implementation baseline, not a
completed protected run. Links to old evidence below identify historical
observations; they do not certify the new demo or the present deployment.

| Existing surface | What the inspected source/evidence actually establishes | Required treatment |
| --- | --- | --- |
| `stripe-refund` | `src/app.rs` invokes the Stripe vertical and owns its reservation/receipt path. `src/main.rs` loads dotenv; `src/stripe.rs` holds fixture and mutation keys. Its browser test covers denial, success and replay, not the complete production wall. | Replace the maintained application execution path with an installed SDK client of the general gateway. Compare exact requests, authority, limits and receipt meaning before reusing fixtures. |
| `stripe-payment-collect` | Its July evidence records real test API effects, independent retrieval, restart replay and lost-response reconciliation, including a public browser run. | Retain this as historical vertical evidence. It is not evidence for the new refund recipe, AWS custody or its recovery behavior. |
| `stripe-payment-authorize`, `stripe-payment-capture`, `stripe-payment-cancel`, `stripe-payment-mandate`, `stripe-subscription-create`, `stripe-subscription-modify` | July records describe real local test effects and various replay/recovery checks, but also standard test keys and missing provider-side least-privilege or deployment evidence. | Preserve useful reference cases; do not label their coupled services qualified gateway demos. Each later effect needs its own reviewed recipe and evidence. |
| `stripe-subscription-cancel` | `src/lib.rs::cancel` selects fixed records and constant counters. The September correction in its July evidence explicitly says the route verifies no proof and calls neither Stripe nor the cancellation service. A separate provider experiment does not repair that route. | Remove live/production enforcement claims from this presentation. A future live cancellation demo must derive decisions and counters from the actual gateway journey. |
| `stripe-connect-transfer`, `stripe-payout` | Their routes select fixed records with constant credential/provider counts. July records also identify missing connected destinations or payout capability/balance. | Mark as reference simulations or retire their misleading live presentation. Do not treat journal persistence or rendered counters as measured effects. They are outside this first demo. |
| `stripe-purchase-authorization` | The local service has a synthetic `DemoEnvironment` and synthesized webhook evidence for experiments; real Issuing prerequisites were absent in its evidence record. | Keep synthetic service tests distinct from authentic webhook/provider evidence. This spec grants no Issuing claim. |
| `stripe-payment-common` | Demo HTTP helpers retain environment-loaded keys and profile-specific adapter calls. | Do not make them the new app's provider transport or a shipping dependency. |

Relevant records are the per-demo `docs/release-evidence-2026-07-30.md`
files, [refund implementation](../../demos/stripe-refund/src/app.rs),
[refund credential adapter](../../demos/stripe-refund/src/stripe.rs),
[refund browser test](../../demos/stripe-refund/tests/browser-e2e.py), and
[subscription-cancel correction](../../demos/stripe-subscription-cancel/docs/release-evidence-2026-07-30.md).
Not every existing demo is fake; not every recorded live experiment traverses
the demo's enforcement path. Both distinctions must survive the cutover.

The PR #206 development report at
`qualification/simulation/evidence/stripe-platform-live-2026-10-07/report.json`
records an installed-wheel/native-socket live test-mode refund at `20837b56`.
It explicitly excludes production PostgreSQL/AWS custody, complete qualification
coverage, independent lease/entry counters and Connect scope. Its simulation
signature MUST NOT be substituted for a protected qualification attestation.

## 3. Architecture and execution contract

```text
Operator: approve recipe/trust -> install custody and gateway -> diagnose/rotate
Application: installed SDK -> proof + exact action -> general gateway socket
Gateway: verify -> durable claim/budget -> credential lease -> closed Stripe POST
Gateway observation + independent reviewer read -> bounded evidence/audit bundle
```

1. The maintained demo SHOULD live under `demos/stripe-gateway/`. It MUST have
   one execution implementation, using the public gateway client. A web backend
   may relay proof/action bytes; it MUST NOT call a Stripe vertical executor.
2. The application uses installed Python and TypeScript packages, outside the
   source checkout. It MUST NOT import Rust internals, sibling source packages,
   private binding APIs or testkit trust in the protected mode.
3. All Stripe URL, method, body mapping, API version, credential guards,
   idempotency and observation rules reside in the approved data-only recipe.
   Requests MUST NOT accept caller-chosen URLs, headers, tokens or HTTP bodies.
4. The profile/action binds the recipe digest, namespace, logical operation,
   exact PaymentIntent, amount and currency. The first recipe is the reviewed
   `stripe-platform-refund-v1`, API `2025-03-31.basil`, with a 50% basis bound.
   A changed contract requires regenerated review and qualification.
5. Durable admission, spend accounting, outcomes and recovery use the shipping
   gateway. No app-local counter, lock or receipt may stand in for gateway state.
6. Operator/setup, application and gateway processes have separate authority.
   The fixture key is setup-only; the application receives neither it nor the
   restricted runtime key, AWS credentials, signing keys or administrative socket.
7. Development rehearsal and protected qualification use the same application
   interface and recipe semantics. Development file custody is clearly labeled;
   it cannot satisfy the protected production target.

The retained PR #206 `qualification/reference/stripe_platform.py`, reviewed
family manifest and source-owned corpus SHOULD be reused after integration.
They MUST NOT be imported into the gateway runtime. The old refund vertical's
aggregate reservation and reconciliation rules are not automatically properties
of this recipe.

## 4. Operator and user experience

Provide a clean Docker-local HTTP workbench and a guided CLI backed by the same
SDK submission path. Setup must require no Rust checkout or local compiler.
Show adjacent authority, exact proposed refund, recipe digest and current result.
Controls select closed experiments: exact boundary, boundary plus one, changed
action, wrong currency, replay, race, restart and response loss.

Display verification, entry, recorded response and observed effect separately.
An `unknown` outcome retains authority consumption and offers only permitted
observation; it MUST NOT show a retry-refund button. Show canonical gateway
result/audit data and a dedicated receipt/evidence page. A frontend projection
must identify unsigned display data and may not invent a signed receipt.

Setup performs a bounded prerequisite check and reports a missing credential,
wrong account/mode, unavailable gateway, failed custody/doctor row, stale
qualification or exhausted budget before offering a live submission. Secrets
must not appear in UI, arguments, logs, artifacts or support bundles.
Fresh-install instructions must distinguish operator installation from app
submission. The packaged example includes diagnosis and run-owned cleanup.

## 5. Required proof and evidence matrix

All applicable AP-SPEC-066 wall scenarios remain mandatory. Each row below
needs a case ID, independently derived expectation, actual observation,
candidate/tuple binding and publication digest; a prose checklist is insufficient.

| Experiment | Required observation |
| --- | --- |
| Exact request/oracle | Independent source oracle agrees with native verification and the ordered form body, version/idempotency headers, PaymentIntent binding and observation subject. Expectations are fixed before candidate execution. |
| Authority rejection | Forged/altered proofs, wrong recipe/trust/operation, expired authority, grant overflow and configuration drift enter no write; refusals before custody have zero leases. |
| Provider-read guard | For a 2,000-minor-unit USD payment, 1,000 is admitted; 1,001 and a currency mismatch are refused before write after the measured guard lease/read. Do not falsely require zero leases for these post-lease checks. |
| Budgets | Distinct operations exercise inclusive count and sum limits, one-unit overflow and concurrent final capacity without editing or resetting durable state. |
| Replay/race | Original proof and fresh-challenge replay, two independent gateway processes and restart preserve one logical write entry. Record observation-only leases separately from write entries. |
| Crash/response loss | Kill before entry, after entry and before result recording using actual process/transport faults. A lost refund response with no retained locator remains `unknown`; an old vertical's search reconciliation must not resolve it. |
| Read-back | A fresh independent GET verifies returned refund ID, selected payment, exact amount and action echo. Do not require a nonexistent Refund `livemode` field; establish test mode from the bound payment/account guards. |
| Scope and restrictions | Both restricted runtime keys address the reviewed test platform; account/mode guards and denied customer/payout reads are measured. The platform recipe sends no `Stripe-Account` header and claims no connected-account isolation. |
| Idempotency | A separately accounted reference-only duplicate of an already confirmed run-owned request returns the same refund within the declared window. It is not a gateway retry or proof of indefinite/global exactly-once behavior. |
| Rotation/drift | Two genuine distinct restricted keys work for the same allowed scope. Measure generation, commitment, external-version and store-kind drift; install the successor, test two-host behavior and retirement. Duplicating one key under two names is not rotation. |
| Isolation | Actual app UID/container cannot read keys/state, acquire AWS authority, reach admin controls or call the provider with a token. Socket-only app submission succeeds. |
| Installed clients/redaction | Both installed language consumers complete the ordinary qualified journey without source/token access. Scan actual log, trace, metric, support and final evidence bytes against all live canaries. |
| Lifecycle | Partial preparation, stage failure and lost setup responses leave a recoverable run-owned journal. Cleanup retires only this run's AWS/journal resources and refunds remaining disposable test payment capacity as defined by the reference. Stripe retains payment/refund records; do not claim deletion. |

[Stripe's API v1 idempotency documentation](https://docs.stripe.com/api/idempotent_requests)
allows key pruning after at least 24 hours. The declared 86,400-second window
must be tested and its limits stated; Auths replay protection remains necessary.
Provider availability, real-money settlement and unrelated actors remain outside
the claim. Formal kernel/refinement checks support the bound native mechanisms;
they do not prove Stripe behavior or substitute for live observations.

## 6. Protected live qualification

Use AP-SPEC-066's existing artifacts and verifier, not a new demo attestation
format. The full retained run MUST use PostgreSQL/TLS, synchronized production
clock, actual AWS web identity, `aws-secrets-manager-v1` with pinned versions,
separate administrative/read identities and the exact Linux release candidate.
No static AWS key, plaintext production credential or optional qualification
policy is a fallback.

The following are unresolved prerequisites, verified 13 October 2026:

- `gateway-custody-live` has one required-reviewer rule but no deployment branch
  policy. The workflow requires exactly the reviewed `main` deployment policy
  before reading provider credentials.
- Its secret-name inventory contains only `STRIPE_TEST_KEY`. The existing
  workflow also needs setup-only `STRIPE_QUALIFICATION_SETUP_KEY` and genuinely
  distinct `STRIPE_QUALIFICATION_NEXT_RUNTIME_KEY`. Names and prefixes alone do
  not establish permissions or rotation eligibility.
- PR #206 was merged to main as `f68f8b17` on 13 October under explicit owner
  authorization. This resolves the prerequisite source landing; engineering
  landing is not Epic 5 acceptance or protected-run evidence. Privileged runs
  remain manual/main-only with existing reviewer protection.
- The checked-in root revocation list has `next_update` on 8 October 2026 at
  03:01:16 UTC. Refresh it through the offline-root procedure with a higher
  sequence and current bounds; do not backdate, extend a stale list or sign
  future lists in bulk. Check both purpose certificates and pinned root too.

Execute the retained sequence: clean candidate/offline differential evidence;
reviewed resource/action expansion; finite purpose-separated commissioning
permit; production installation/tuple comparison; commissioning corpus;
independent first qualification; ordinary required-gate live corpus; confirmed
cleanup; independent final signing and gateway verification. Commissioning
must prove ordinary applications still refuse before the first qualification.

The protected signer rebuilds its own tools and independently reconstructs the
full reviewed family/pool before using its key. Final evidence binds source,
binary/semantic closure, recipe/profile/contract/corpus, production tuple,
workflow run and attempt, measured counters and sanitized resources. Use the
reviewed Stripe maximum 30-day validity, current revocation data and signed
index; first commissioning qualification remains separately bounded.

Stripe completion contributes one family to the two-provider launch gate.
Stable launch readiness remains derived by `release-check`; Airtable's current
attestation and the separate human boundary review are also required.

## 7. Delivery and acceptance

1. Build/package the general-gateway application and web/CLI journeys; cut the
   maintained entry point over directly. Label remaining vertical demos as
   reference/simulation examples and correct constant-counter live claims.
2. Add the independent request comparison and adverse-case matrix. Let hosted
   CI verify architecture, fixtures, compliance, native/formal boundaries,
   installed SDKs and browser behavior on the exact candidate.
3. Run a source-free packaged operator rehearsal; fix and rerun its defects.
   Record binary/package digests and which live operations were excluded.
4. Complete the protected live sequence and publish current signed evidence.
   Separately install the actual GitHub release and repeat its maintained demo
   journey; CI artifacts alone are not proof of release-download usability.

Report three acceptance states independently: **gateway demo implemented**
(real packaged API/UI journey and adverse cases), **development live evidence**
(actual test-provider effect under the declared development tuple), and
**protected recipe qualified** (complete protected wall and current signed
artifacts). None implies another. An operator simulation is never an independent
human trial. No new real-money, Connect or other Stripe-family claim is implied.

## 8. Implementation status

The current branch adds `demos/stripe-gateway/`: public SDK authoring/submission,
a separate operator and actor, two gateway processes with shared durable state,
CLI and HTTP workbench, native audit export, a counting platform-provider double,
shipping-binary live test-mode setup/cleanup and a source-free Docker handoff.
The new hosted workflow runs installed Python/TypeScript clients and a real
browser. Verification is pending; no protected run, production qualification,
provider rotation or GitHub release installation is claimed. Old vertical
examples remain references, with the maintained entry point moved to this demo.
