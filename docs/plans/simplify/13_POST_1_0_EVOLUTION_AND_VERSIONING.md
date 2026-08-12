# 13 — Post-1.0 evolution and versioning

**Status:** implemented; stable publication remains blocked by independent evidence gates
**Gate:** required before publishing any `1.0.0` Rust crate, npm package, or Python wheel
**Design dependencies:** current machine inventories; stable readiness additionally requires completed Milestones A–F

## Current issue

The simplification program correctly treats the repository as prelaunch and
permits clean breaks. That rule expires when Auths publishes 1.0. At that point
applications may persist authority, profile identifiers, execution state,
receipts, stable error codes, and conformance reports for longer than one SDK
release.

Without an explicit evolution policy, “stable” would describe package numbers
while the security meaning, wire evidence, profiles, and recovery behavior
could still change independently.

## Components of the problem

- Rust, npm, and Python packages have related but distinct version numbers;
- package ABI and semantic subject are not the same version axis;
- profile actions, provider behavior, recovery, and receipts evolve together;
- persisted proofs/receipts need longer verification life than authoring APIs;
- error codes and conformance case IDs are operational dependencies;
- security fixes may require urgent rejection of previously accepted input;
- prelaunch deletion rules must not leak into stable releases;
- compatibility cannot depend on aliases and shims forever.

## Product decision

Prelaunch clean breaks remain allowed only while every affected public artifact
is below 1.0. Publishing the first stable artifact requires a single reviewed
stability contract covering all three SDKs and the Rust semantic waist.

Auths versions five explicit axes:

| Axis | Owns | Compatibility rule |
| --- | --- | --- |
| Package version | Rust crate/npm/wheel API and supported runtime contract | Semantic Versioning plus the rules below |
| Portable/native ABI | exact functions, bounded shapes, handles, and capabilities | packaged artifacts must match exactly or fail load |
| Semantic subject | canonical meaning, accepted/rejected values, commitments, decisions, transitions, receipts | any meaning change receives a new subject identity |
| Profile identity/version | actions, authority projection, provider session, recovery, receipt claims, failures | exact version selection; no silent reinterpretation |
| Conformance suite version | Auths-owned case IDs and required obligations | reports pin exact suite; changed meaning gets a new case ID |

No single version number substitutes for another axis.

## Stable package policy

### Patch release

May include bug fixes, performance work, documentation, new internal ABI paired
inside the same coherent artifact, and security hardening that does not change
valid semantic outcomes. It may add no required public field, remove no public
symbol, and change no existing stable code/case meaning.

### Minor release

May add optional public APIs, optional error codes, new profile versions, new
conformance cases, supported runtimes, and additive receipt projections. Old
valid calls and stored evidence continue to work under their pinned versions.

### Major release

Is required for public API removal/rename, changed required call shapes,
removing a supported runtime, changing an existing profile version's meaning,
dropping stable authoring/execution support, or removing verification support
for published evidence.

Package-major alignment across Rust, TypeScript, and Python is required when a
shared customer journey breaks. Language-only idiomatic additions may release
independently only when the cross-language capability matrix remains truthful.

## Semantic changes and security emergencies

- An existing semantic subject is immutable. A correction that changes
  canonical bytes, accepted input, authorization, attenuation, transition, or
  receipt meaning creates a new subject and fixtures.
- A security release that must reject previously accepted unsafe input may ship
  urgently at the smallest operationally safe package version, but it must
  include a security advisory, new semantic subject, exact affected versions,
  migration/verification behavior, and fail-closed mixed-version tests.
- Emergency policy never permits silently accepting broader authority or
  reinterpreting existing signed bytes.

## Profile evolution

- Profile identity includes an immutable semantic version selected exactly in
  authority, actions, execution state, and receipts.
- Additive action/provider/recovery behavior that changes commitments creates a
  new profile version even if the package change is minor.
- Existing profile versions are never mutated in place and are never silently
  upgraded during parsing, authorization, resume, reconciliation, or verify.
- Verification of every published stable proof/receipt profile version remains
  available throughout the current package major and the next major for at
  least twelve months.
- Authoring/execution support for a stable profile version remains for at least
  twelve months after its successor becomes stable. Retirement requires a
  minor-release announcement, machine-readable capability change, migration
  guide, and at least ninety days' notice.
- A removed execution integration does not remove inert verification support
  for already issued evidence.

## Error-code evolution

- Stable error codes are globally unique within their owner namespace and are
  never reused for different meaning.
- Wording and bounded remediation may improve in patch releases without
  changing effect/retry classification.
- New codes are additive minor changes. Changing stage, retry, effect, or
  reference eligibility creates a new code.
- Retirement marks a code inactive with its replacement and final producing
  version. Documentation remains available; physical removal requires a major
  release.
- TypeScript and Python must preserve unknown future codes as bounded unknown
  values rather than crash, retry, or infer effect state.

## Receipt and stored-state evolution

- Canonical proof, receipt, execution-reference, and persisted-state schemas
  carry exact schema, semantic-subject, and profile identities.
- Existing signed bytes are never rewritten under a new version.
- Additive display/inspection projection does not change the signed schema.
- A new required signed field, commitment rule, link, or verification outcome
  creates a new schema/semantic subject.
- Readers reject unsupported future schemas with a stable bounded error; they
  never guess or partially verify.
- Recovery state may be migrated only by a Rust-owned, crash-safe, idempotent
  migration that preserves the original commitment and produces auditable
  before/after metadata. No binding-authored migration may invent meaning.

## ABI and artifact coherence

- The npm package contains the exact WASM ABI/capability/semantic metadata it
  was built and tested against.
- The Python wheel contains the exact native ABI/capability/semantic metadata
  it was built and tested against.
- Internal packaged ABI may evolve independently when consumers cannot link to
  it directly and exact artifact coherence remains enforced.
- Any public external native ABI follows its own Semantic Versioning contract
  and cannot rely on package-private exceptions.
- Mixed package/native/WASM semantic subjects fail at initialization before
  parsing customer authority or action data.

## Conformance evolution

- A case ID has immutable meaning. Strengthening, weakening, or changing its
  observations creates a new ID.
- Suites declare added, required, superseded, and retired cases by version.
- A minor release may add optional cases; making a new case mandatory for a
  previously stable contract requires its declared compatibility window or a
  major contract version.
- Reports pin package, ABI, semantic subject, profile, suite, cases, runtime,
  and implementation version.
- An old passing report never claims compliance with a newer suite.

## Release classification and workflow

Every release change records:

1. affected package/API, ABI, semantic subject, profile, error, receipt/state,
   and conformance axes;
2. patch/minor/major classification for each published artifact;
3. updated Rust-owned registries, semantic freeze, and canonical fixtures;
4. TypeScript/Python capability and installed-artifact parity;
5. persisted-evidence and mixed-version tests;
6. support/retirement dates where applicable; and
7. generated release notes and migration guidance.

CI rejects a version classification that conflicts with public API snapshots,
semantic-freeze changes, profile manifests, error registries, receipt schemas,
support matrices, or conformance manifests.

## Implementation steps

- [x] Inventory every artifact/registry that carries one of the five version
  axes and assign one owner.
- [x] Add machine-readable release classification covering all axes.
- [x] Make release tooling compute required version floors from authoritative
  diffs and reject under-versioned changes.
- [x] Add mixed-version package/WASM/wheel/profile/receipt/state fixtures.
- [x] Add unknown-future error/profile/schema behavior tests in both SDKs.
- [x] Add profile and error retirement metadata with generated documentation.
- [x] Add crash-safe persisted-state migration test infrastructure without
  creating a migration before one is actually required.
- [x] Generate one cross-language compatibility and support page.
- [x] Run a mock patch, minor, major, profile-successor, error-retirement, and
  emergency-security release through the complete release workflow.
- [x] Keep the prelaunch history statement explicitly prelaunch-only and make
  the generated lifecycle registry and migration contract authoritative at
  the 1.0 cut.

## Implementation evidence

- `release/evolution-policy-v1.json` owns the five axes, diff classification,
  support windows, and stable launch state.
- `release/evolution-lifecycle-v1.json` owns profile, error, and conformance
  lifecycle metadata.
- `release/fixtures/evolution/` covers mixed artifacts, mock releases, and the
  empty-but-enforced Rust migration contract.
- `cargo xtask evolution-policy` validates those inputs, classifies the full
  pull-request diff when CI supplies its base revision, enforces stable version
  floors, and generates `docs/product/COMPATIBILITY_AND_SUPPORT.md`.
- TypeScript and Python preserve bounded unknown future error codes without
  inferring retry or effect, while unknown profile and receipt versions fail
  before interpretation.

## Acceptance criteria

- No stable artifact can publish with an unexplained API, semantic, profile,
  error, receipt/state, ABI, or conformance change.
- Old stable proof/receipt fixtures continue to verify for the declared window.
- Exact profile versions cannot be silently upgraded or reinterpreted.
- Stable error/case IDs are never reused and unknown future values fail safely.
- Mixed semantic subjects fail before customer security data is processed.
- Mock releases prove tooling distinguishes patch, minor, major, and emergency
  changes consistently across Rust, TypeScript, and Python.
- Public support/retirement dates are generated from machine-readable data.
- `1.0.0` publication remains blocked until every criterion passes.

## Non-goals

- Preserving compatibility between prelaunch revisions.
- Maintaining every profile's effect integration forever.
- Using deprecation shims as a substitute for versioned support.
- Treating Semantic Versioning alone as proof of unchanged security meaning.
