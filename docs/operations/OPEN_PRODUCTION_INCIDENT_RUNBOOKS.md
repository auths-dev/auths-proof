# Open production incident runbooks

Every response begins by preserving lifecycle state and preventing an unsafe
retry. Authentication, transport health, provider availability, and telemetry
success never substitute for authorization or effect evidence.

## Store outage

- **Detection:** lifecycle readiness is red or store operations return the
  stable unavailable code.
- **Impact:** new effect-capable workflows remain unready; existing effects may
  require later recovery.
- **Actions:** stop admission, preserve opaque references, restore the exact
  candidate schema, then run read-only consistency checks.
- **Forbidden:** local fallback state, a second database, schema repair, or
  replaying provider calls.
- **Closure:** readiness, lease exclusivity, recovery, and receipt retrieval
  pass from two runtime instances.

## Unknown-effect age

- **Detection:** the oldest possible-effect age crosses its frozen objective.
- **Impact:** the provider may have applied an effect; budget and ordering stay
  held.
- **Actions:** acquire the recovery lease and invoke only the profile observer.
- **Forbidden:** fresh execution, manual success, capacity release without
  conclusive evidence, or changing the original request.
- **Closure:** authenticated observation commits one terminal outcome and the
  receipt verifies offline.

## Reconciliation failure

- **Detection:** recovery backlog is not draining or observers are unavailable.
- **Impact:** later ordered work remains safely blocked.
- **Actions:** restore observer access, verify clock and configuration identity,
  and resume by opaque reference.
- **Forbidden:** bypassing the observer, editing lifecycle rows, or replacing
  the profile gateway.
- **Closure:** another node can acquire the lease and converge without provider
  re-entry.

## Receipt failure

- **Detection:** persistence or retrieval probes fail.
- **Impact:** effects may be known but auditable completion is unavailable.
- **Actions:** keep the immutable lifecycle outcome, restore receipt storage,
  and regenerate only from committed canonical evidence where the contract
  permits.
- **Forbidden:** synthesizing receipt fields, marking the effect absent, or
  exposing raw state as a substitute.
- **Closure:** the stored signed receipt and disclosure projection verify.

## Custody revocation or outage

- **Detection:** lifecycle state is revoked/disabled or custody readiness fails.
- **Impact:** new signatures stop; verification and recovery observation remain
  available.
- **Actions:** follow the custody lifecycle runbook and publish a new governed
  descriptor if rotation is required.
- **Forbidden:** falling back to an old key, repeating an ambiguous request, or
  importing private material.
- **Closure:** conformance passes for the active descriptor and no new signature
  names the old version.

## Configuration drift

- **Detection:** required and executed configuration commitments differ.
- **Impact:** the node is unready before any effect-capable boundary.
- **Actions:** deploy the exact candidate configuration and re-run startup
  binding.
- **Forbidden:** weakening required configuration, ignoring the mismatch, or
  serving partial profiles.
- **Closure:** commitments are byte-identical on every replica.

## Credential failure

- **Detection:** the closed gateway cannot acquire its scoped credential after
  reservation.
- **Impact:** the effect has not been authorized merely because identity or
  transport succeeded.
- **Actions:** inspect workload identity and provider policy through redacted
  readiness evidence, then resume according to the stable outcome.
- **Forbidden:** embedding static production credentials or acquiring them
  before execution intent.
- **Closure:** one scoped credential is acquired after one durable reservation.

## Trusted clock failure

- **Detection:** the trusted clock probe is unavailable or outside its bounded
  skew policy.
- **Impact:** freshness, expiry, and lease decisions cannot be trusted.
- **Actions:** stop admission, restore the trusted time source, then re-evaluate
  only requests that remain valid.
- **Forbidden:** using local wall-clock guesses or extending validity windows.
- **Closure:** all replicas agree within the candidate bound.

## Telemetry exfiltration

- **Detection:** a seeded privacy value appears in metrics, traces, logs,
  support bundles, HTML, or an unauthorized disclosure.
- **Impact:** operational evidence may have disclosed protected data; Auths
  decisions and lifecycle state remain independent.
- **Actions:** stop exporters, preserve bounded evidence, rotate affected
  credentials, and audit against the field registry.
- **Forbidden:** deleting lifecycle evidence or disabling authorization to fix
  an exporter.
- **Closure:** the secret-seeded privacy corpus finds no protected value.

## Emergency denial

- **Detection:** the governed emergency-denial state is active.
- **Impact:** new effect-capable work is intentionally stopped.
- **Actions:** confirm the signed state, preserve existing recovery work, and
  require the governed release procedure.
- **Forbidden:** treating denial as node failure, editing state directly, or
  accepting work through another replica.
- **Closure:** the release authorization is verified and all replicas observe
  the same state.
