# 12 — Mechanism and profile conformance

**Status:** implemented
**Milestones:** B — contract inventory; D — framework publication decision; F — conformance ecosystem
**Design dependencies:** inventory uses [02](02_SECURITY_AND_PARITY_GUARDRAILS.md); public extraction requires evidence from at least two independently completed verticals from [07](07_CLOSED_EXECUTION_ORCHESTRATION.md)

## Current issue

Auths is intentionally modular and does not intend to own every integration.
But “implements the interface” proves only shape. It does not prove binding,
atomicity, cancellation, boundedness, redaction, lifecycle, or recovery
behavior.

The opposite mistake is equally dangerous: a universal adapter conformance
kit can imply that providers from different effect domains share credential,
request, outcome, reconciliation, and receipt semantics. They do not.

## Components of the problem

- structural typing and Python protocols prove shape, not behavior;
- some obligations are cross-domain mechanisms while others belong to a
  concrete effect vertical;
- existing runners may accept caller-authored test bodies and merely verify
  case IDs, allowing an adapter to “certify” itself without executing Auths-owned
  behavior;
- deterministic contract and live-integration tests serve different purposes;
- TypeScript/Python reports can drift;
- passing cases must not imply Auths endorsement or production readiness.

## Product decision

Publish two different conformance systems:

1. **Mechanism conformance** for contracts proven to be independent of an
   effect domain.
2. **Profile-owned conformance** for provider request, credential, outcome,
   reconciliation, receipt, and domain-failure behavior.

There is no `certifyProviderAdapter` or generic
`certifyReconciler`. Auths-owned runners own and execute the test cases. Adapter
authors provide factories and test-controlled dependencies, not arbitrary
passing case bodies.

## Staged delivery

- **Milestone B:** inventory every current framework/adapter contract and label
  it `profile-owned`, `candidate-mechanism`, or `internal`. This classification
  requires no public extraction.
- **Milestone D:** for each candidate mechanism, attach evidence from two
  independent completed verticals. Publish `/framework` only if at least one
  contract passes; otherwise keep it absent.
- **Milestone F:** build the Auths-owned mechanism/profile runners, reports, and
  production-reference gates described below.

This split lets Milestone D make an evidence-based packaging decision without
pretending the entire conformance ecosystem already exists.

The Rust-owned catalog at
`product/conformance/v1/mechanism-profile-conformance.json` records the
decision. Signer/custody and atomic reservation satisfy the two-vertical gate
through MCP and Records and may appear in `/framework`. Bounded byte transport
remains an integration contract, approval transaction remains internal until a
second effect vertical proves identical meaning, and provider, result, and
reconciliation contracts remain MCP-owned. The generic framework adapter is
deleted.

## Extraction rule

A contract may move into cross-domain framework/testkit only after at least two
independent verticals use the same obligation with the same meaning. Shared
syntax or similar method names are insufficient. Until then, the contract
stays with its profile/domain package.

The review must answer:

- Does the obligation mean the same thing in both domains?
- Can it be tested without constructing either domain's action/result?
- Does moving it preserve credential timing and evidence meaning?
- Would a conforming implementation be substitutable without changing a
  profile's transition code?

If any answer is no, keep it profile-owned.

## Cross-domain mechanism families

Candidate public mechanism contracts are:

- identity method and signature-suite mechanics;
- identity/status resolution mechanics where freshness semantics are explicit;
- signer/custody mechanics;
- exact approval-transaction binding where approval policy is domain-neutral;
- atomic state/CAS stores and durability claims;
- clocks;
- telemetry/redaction exporters;
- bounded byte transports; and
- receipt storage mechanics that do not interpret receipt claims.

Credential acquisition is cross-domain only when it is a custody mechanism.
The timing, scope, audience, and application of credentials to an effect
request remain profile-owned.

## Mechanism runner examples

```ts
await certifyAtomicStore(() => new PostgreSqlAtomicStore(testDatabase));
await certifySigner(() => new KmsSigner(testKey));
await certifyByteTransport(() => new IrohTransport(testEndpoints));
```

```python
await certify_atomic_store(lambda: PostgreSQLAtomicStore(test_database))
await certify_signer(lambda: KmsSigner(test_key))
await certify_byte_transport(lambda: IrohTransport(test_endpoints))
```

The runner chooses inputs, schedules concurrency/cancellation, injects faults,
observes calls, checks bounds/redaction, and assigns results to Rust-owned case
IDs. The supplied factory cannot mark a case passed.

## Mechanism behavioral cases

### Common

- configuration parses before I/O;
- capability declarations are complete and bounded;
- cancellation and disposal are honored;
- malformed/oversized values fail with stable codes;
- failures and reports contain no secrets or unbounded remote text;
- fresh instances do not share undeclared state.

### Signer/custody

- identity and requested transaction match;
- exact preimage binding and duplicate behavior;
- expiry/cancellation and resource lifecycle;
- key material never leaves the adapter.

### Exact approval transaction

- exact transaction/configuration commitment binding;
- rejection, expiry, substitution, threshold, and duplicate behavior;
- authenticated principal evidence;
- approval never grants authority.

### Atomic store

- compare-and-swap and atomic reservation;
- exact replay versus conflict;
- process/thread/task concurrency;
- crash/reopen durability only where claimed;
- bounded stored values and conflict evidence.

The store suite does not prescribe a domain lifecycle or reconciliation
transition. Profiles test their use of the mechanism separately.

### Identity/suite/resolver/transport

- method/suite label binding and downgrade rejection;
- exact-message authentication;
- declared freshness/rotation/compromise evidence behavior;
- transport delivery never changes authorization;
- malformed and oversized bounded bytes.

## Profile-owned conformance

Each qualified profile package exposes its own testkit entry point and owns:

- action/plan canonicalization and display;
- authority projection and mutation fixtures;
- provider request construction;
- credential scope and acquisition timing;
- remote response/error parsing and bounded result evidence;
- not-applied, possible, and applied classifications;
- cancellation and timeout behavior by step;
- execution identity/provider idempotency derivation;
- reconciliation queries and accepted evidence;
- receipt claims and links; and
- profile/domain failure codes.

Illustrative shape:

```ts
import { certifyMcpProvider } from "@auths-dev/sdk/testkit";

await certifyMcpProvider(() => new CandidateMcpProvider(testServer));
```

```python
from auths.testkit import certify_mcp_provider

await certify_mcp_provider(lambda: CandidateMcpProvider(test_server))
```

This does not establish a base `Provider` protocol. A future Stripe or
Kubernetes suite may have entirely different factory inputs, cases, recovery
evidence, and live tests.

## Reports

Emit a bounded report with:

- schema and conformance-suite version;
- `mechanism` or exact profile identity/version;
- implementation name/version and declared capabilities;
- SDK/native semantic subject;
- runtime/platform;
- Auths-owned executed case IDs and results;
- deterministic versus live case classification;
- durability/custody/evidence claims relevant to that suite;
- build provenance and timestamp when requested; and
- no keys, credentials, signatures, proof/action/command bytes, or raw remote
  responses.

The report means only “this implementation passed these cases in this
environment.” It is not an endorsement, audit, security certification, or
production-readiness claim.

## Implementation steps

- [x] In Milestone B, inventory current framework ports and classify each as
  candidate cross-domain, profile-owned, internal, or premature abstraction.
- [x] In Milestone D, compare at least two completed verticals before extracting
  a shared mechanism contract and record the framework publish/omit decision.
- [x] Replace any caller-authored-case runner with Auths-owned executable cases
  and controlled fault injection.
- [x] Publish equivalent TypeScript/Python mechanism runners from testkit.
- [x] Publish the MCP profile-owned suite from the MCP package/testkit owner.
- [x] Add intentionally defective implementations proving detection of
  ordering, binding, replay, cancellation, durability, and redaction faults.
- [x] Generate bounded reports and validate their schemas.
- [x] Run packed-package and wheel-only conformance consumers with no internal
  imports.
- [x] Gate each later production reference from Spec 09 on its actual owning
  mechanism/profile suite.
- [x] Version case obligations through semantic-freeze review.

## Acceptance criteria

- No public universal provider/result/reconciler conformance API exists.
- Adapter authors cannot choose or implement the assertions that certify their
  own adapter.
- TypeScript and Python expose the same case IDs and meanings for each shared
  mechanism and qualified profile suite.
- The atomic-store suite detects races and false durability without prescribing
  one effect lifecycle.
- The MCP suite detects credential-before-reservation, request substitution,
  blind retry, wrong outcome classification, and invalid receipt evidence.
- Reports clearly separate deterministic cases from live integration cases and
  make no endorsement claim.
- A new profile can define stronger/different domain obligations without
  changing a universal provider contract.

## Non-goals

- Guaranteeing an integration is secure in every deployment.
- Requiring Auths maintainers to own or host third-party infrastructure.
- Allowing conformance to override Rust authorization decisions.
- Treating structural protocol compliance as behavioral evidence.
