# Epic 9 — Qualify an Immutable Release Candidate and Publish Assurance

Status: implementation specification

Parent: [0038](../0038-production-runtime-custody-observability-and-assurance.md)

Depends on: [Epic 8](epic_8.md)

## 1. Outcome

Freeze one immutable open-core release candidate, operate it under sustained
fault injection, obtain independent security review, close every release-
blocking finding, and publish a reproducible evidence bundle supporting the
bounded production claim in specification 0038.

This epic does not claim universal production readiness. It proves a named
artifact, configuration, database schema, custody mode, SDK matrix, and three
exact-effect profiles under a published threat model.

## 2. Current issue

Passing unit and integration tests proves implementation intent, not operating
history or independent scrutiny. A high-consequence authority system must show
that its semantic claims survive long-running concurrency, process loss,
dependency failure, upgrade, restore, hostile inputs, and an expert review that
did not originate with the authors.

Without a frozen candidate and a complete evidence manifest, individual green
checks can accidentally refer to different bytes.

## 3. Product constraint

Assurance must be understandable to a buyer or developer without asking them to
reverse-engineer CI. The public answer to “what exactly was tested?” is one
signed manifest, one concise assurance summary, and drill-down evidence for
specialists.

This is the trust equivalent of the Stripe-quality product surface: the simple
view is honest and useful; the full technical evidence remains available under
progressive disclosure.

## 4. UX

Publish an assurance summary shaped like:

```text
Auths open production candidate 1
Artifact digest        sha256:...
Qualification window   30 days / complete
Fault scenarios        42 / 42 passed
SDK matrix             TypeScript and Python / passed
Independent review     complete / 0 open blockers
Known limitations      7 / read before use
Verify evidence        cargo xtask assurance verify bundle.json
```

The summary links to the threat model, scope, exact configuration, profile
claims, review report, remediation records, fault outcomes, and known
limitations. It must distinguish “not tested,” “failed,” and “not applicable.”

## 5. Architecture

```text
immutable RC digest
      |
      +-- sustained fault lab --------+
      +-- SDK/profile conformance -----+--> signed evidence manifest
      +-- supply-chain verification ---+
      +-- independent review ----------+--> bounded production claim
```

Every evidence record names the candidate digest. A code, dependency, build,
deployment, configuration, schema, or semantic fixture change creates a new
candidate and restarts the required qualification window. Documentation-only
clarifications may retain the candidate only when they cannot change executable
meaning and the evidence manifest records the change.

## 6. Assurance APIs

Add a versioned Rust-owned evidence manifest schema:

```text
AssuranceManifestV1
  candidate_digest
  source_commit
  build_provenance_digest
  image_digest
  package_digests[]
  configuration_commitment
  schema_version
  semantic_freeze_digest
  supported_runtime_matrix[]
  qualified_profiles[]
  qualification_window
  test_evidence[]
  review_evidence[]
  known_limitations[]
  statement_digest
  signer
  signature
```

Provide:

```text
cargo xtask assurance candidate
cargo xtask assurance record <evidence>
cargo xtask assurance sign <manifest>
cargo xtask assurance verify <manifest>
cargo xtask assurance summarize <manifest>
```

The verifier must work offline from checked-in schemas and public verification
material. It validates artifact binding, manifest canonicalization, signatures,
required evidence kinds, date bounds, and the absence of unresolved blocking
findings. It does not infer that an omitted test passed.

The checked-in signer catalogue is the offline trust root. A manifest signed by
an arbitrary key is invalid even when its signature is mathematically correct.
The initial catalogue and candidate remain empty and incomplete until a real
release assurance key, immutable candidate, thirty-day run, and independent
review exist; implementation must never synthesize those facts.

The candidate command parses a strict candidate-input object and computes its
digest from the complete canonical representation. The digest is not a
caller-selected identifier and cannot remain unchanged when any bound input
changes.

## 7. Candidate freeze

1. Select the exact source commit after Epic 8 passes.
2. Build Rust artifacts, npm package, Python wheels, container, SBOM, and
   provenance only through the release builder.
3. Record every digest in `AssuranceManifestV1`.
4. Freeze the production-candidate config, dependency lockfiles, database
   schema, semantic identities, profile identifiers, and differential vectors.
5. Sign the candidate statement using a release key distinct from runtime
   receipt custody.
6. Reject evidence whose candidate, configuration, or fixture digest differs.

## 8. Sustained qualification program

Run the immutable candidate continuously for at least thirty days. If the
project has not yet reached the operational capacity for a continuous hosted
run, use repeated scheduled windows whose aggregate duration and gaps are
published; do not describe that as uninterrupted operation.

The program exercises:

### 8.1 Lifecycle and store

- concurrent create, delegate, execute, and resume across three nodes;
- duplicate delivery and conflicting idempotency keys;
- lease-holder death before and after reservation;
- PostgreSQL restart, failover, saturation, slow queries, and connection loss;
- transaction rollback and deadlock retry;
- backup, point-in-time recovery, and clean-environment restore; and
- same-candidate rolling restart and deliberate incompatible-schema refusal.

### 8.2 Custody

- KMS and PKCS#11 latency, throttling, timeout, disable, and key rotation;
- malformed, substituted, stale, and wrong-key signing responses;
- verifier failure and unavailable verification material;
- key disable during in-flight execution; and
- proof that private key material never enters process memory or evidence.

### 8.3 Providers and profiles

- success, denial, deterministic failure, pre-call timeout, post-call timeout,
  ambiguous remote outcome, and reconciliation for every profile;
- provider credential acquisition only after sealed authorization and durable
  reservation;
- payload, plan, order, region, target, and approval mutation; and
- profile isolation: credentials or actions from one profile cannot satisfy
  another.

### 8.4 SDKs and wire

- all supported Node, browser, CPython, and operating-system combinations;
- installed artifacts with no Rust toolchain or repository checkout;
- Rust/TypeScript/Python differential and adversarial corpus;
- offline receipt verification;
- unknown version and future-field rejection; and
- maximum-size values and allocation bounds.

### 8.5 Operations and privacy

- alert delivery and each runbook;
- telemetry cardinality budgets under hostile inputs;
- recovery backlog and SLO burn alerts;
- redaction scans over logs, metrics, traces, crash reports, and evidence; and
- operator drills that recover work without viewing protected payloads.

## 9. Independent review

Commission review from people who did not implement the candidate. The scope
must include:

- authority and attenuation semantics;
- lifecycle/replay/budget atomicity;
- recovery-reference security and provider-unknown handling;
- custody request/response binding and key lifecycle;
- receipt disclosure and telemetry privacy;
- Rust unsafe-code and dependency review;
- WASM, PyO3, and client boundary review;
- deployment hardening and PostgreSQL threat model; and
- the three exact-effect profile gateways.

Classify findings with a published severity rubric. Critical and high findings,
or any finding that invalidates a stated security property, block release.
Remediation that changes executable bytes creates a new candidate and reruns the
affected qualification plus the minimum full-window rule set defined in the
threat model. Do not waive a semantic finding as “operational.”

## 10. Evidence storage

Check the manifest, schemas, summaries, deterministic fixtures, and public
review artifacts into:

```text
release/assurance/open-production-candidate-1/
  manifest.json
  summary.md
  threat-model.md
  limitations.md
  reviews/
  qualification/
  fixtures/
```

Large machine logs may live in immutable object storage, but the manifest must
carry content digests and retention metadata. The checked-in evidence must be
sufficient to verify every external object after download. Never publish
secrets, raw protected actions, provider credentials, recovery references, or
unauthorized full receipt disclosures.

## 11. CI and release control

1. Add the assurance schema and manifest to release-control subjects.
2. Require offline `assurance verify` in authoritative and compliance phases.
3. Ensure the release workflow signs only the candidate represented by the
   reviewed manifest.
4. Fail on stale builder, package, image, schema, fixture, or semantic-freeze
   digests before expensive qualification jobs start.
5. Publish the assurance summary beside release artifacts.
6. Prevent the release tag when a required evidence kind is missing, expired,
   failed, or bound to another candidate.

## 12. Files to change

- `xtask/src/` for assurance commands and release gates
- `product/spec/v1/` for the evidence manifest schema
- `release/assurance/open-production-candidate-1/`
- release builder and assessment inputs
- CI planner classifications and authoritative/compliance workflows
- release-contract and semantic-freeze snapshots
- the documentation site location for the assurance summary

Do not add an enterprise compliance portal, tenant evidence API, audit-retention
service, or fleet reporting system. Those belong to specification 0039.

## 13. Exit gate

- One immutable candidate is named by digest across all evidence.
- The sustained qualification program completes with no unexplained gaps or
  unresolved failures.
- Independent review has no open release-blocking findings.
- Restores, failovers, reconciliation, custody rotation, and installed SDK
  workflows pass against the candidate.
- Privacy review finds no prohibited data in operational or assurance output.
- The signed manifest verifies offline and CI rejects stale evidence early.
- The published limitations bound the claim honestly.
- A non-specialist can understand the assurance summary, while a specialist can
  reproduce and audit its supporting evidence.
