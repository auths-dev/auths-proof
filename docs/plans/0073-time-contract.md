# AP073 time ownership and provenance

**Status:** next implementation contract, 27 October 2026. Only the WebAuthn
provenance correction is implemented; hosted evidence is pending. See the
[assessment](0073-foundation-assessment.md) and
[foundation spec](../specs/0073-identity-authority-and-enforcement-foundation.md).

## Three distinct meanings

| Time | Authority | Permitted use |
| --- | --- | --- |
| Evaluation time | Deployment's maintained clock adapter, with explicit trust state | Evaluate grant/task validity and evidence age at a particular boundary. |
| Historical observation/event time | The particular evidence issuer or trusted observation process | State when the named fact was established. Re-verification cannot renew it. |
| Monotonic deadline | Process-local monotonic clock and bounded duration | Limit credential exposure, I/O, drain and retry work. Never serialize it as a portable timestamp. |

One clock acquisition port cannot make these meanings interchangeable. The
kernel continues accepting explicit time and immutable evidence; it must not
read the host clock. Provider-specific freshness meaning remains in its profile.

## Source-backed current boundary

`GatewayEngine` uses `wall_clock_seconds` directly across activation, proof
verification, observation, reservation and recovery. `QualificationGate` owns a
separate sealed `DeploymentClock`; commissioning reads that clock, while ordinary
submission reads the engine helper. Managed reads add a private test-only clock
callback. `materializer::task_lease_deadline` independently reads wall and
monotonic time. Several `Instant::now` calls enforce exposure and drain deadlines.

```mermaid
flowchart LR
    W[Host wall clock] --> E[Engine time helper]
    W --> Q[Qualification clock adapter]
    W --> M[Materializer deadline conversion]
    E --> R[Task and read checks]
    Q --> C[Qualification and commissioning]
    T[Test callback] --> R
    I[Monotonic clock] --> M
```

Separate reads do not inherently create a vulnerability: these stages often
need fresh samples. The architectural problem is different acquisition and
failure/trust rules, plus no single deterministic seam for the whole execution
path. Centralization should unify the authority and sampling contract, while
retaining fresh checks at each stage.

## Selected cutover

Extract the existing sealed deployment clock into a gateway-owned module rather
than invent a parallel cross-workspace clock framework. Qualification and engine
use the same installed clock instance. Samples carry the wall observation,
monotonic reference where needed, and clock trust together. No proof, recipe or
application can supply clock implementation, trust or timestamp overrides.

```mermaid
flowchart TB
    A[Maintained deployment clock adapter] --> S[Explicit time sample and trust]
    S --> Q[Qualification and commissioning]
    S --> E[Engine validity and admission]
    S --> D[Credential deadline conversion]
    I[Monotonic timeout checks] --> D
    O[Trusted evidence issuer] --> H[Historical fact and observation time]
    H --> V[Pure assurance age evaluation]
    S --> V
```

The adapter must not label the process clock synchronized merely because it can
read it. Retain the production synchronization-marker checks and explicit
development policy. Required-clock failure refuses authority-dependent work;
no zero timestamp or unchecked fallback is a usable sample. Qualification
status reporting may still describe a refusal without admitting an operation.

Deadline conversion consumes an explicit sample; materializers must not read a
second wall clock themselves. Preserve subsecond precision or apply a documented
conservative bound so truncation cannot extend a credential past task expiry.
The result is capped by the source lease deadline and checked after async work.
Monotonic references are process-local and must be reconstructed after restart.

Tests must exercise unreadable/untrusted time, exact expiry, expiry during
materialization, trust loss before entry, backward/forward wall jumps and
monotonic expiration independently. A deterministic test adapter must be confined
to test support and shared across the real execution path; injecting time only
into an isolated predicate is insufficient.

Do not claim that a central port establishes global trustworthy time. Detecting
rollback within a process, detecting restored durable state and enforcing a
cross-host epoch are separate contracts. Persistent rollback requires an anchor
outside the restored state's failure domain, as specified in the
[participant contract](0073-engagement-participant-contract.md).

## Adoption boundary

First complete the gateway path and delete its superseded acquisition helpers
and private read-clock callback after their tests run through the shared seam.
Keep operation-specific expiry codes and conservative accounting. Verify that
test qualification clocks and invocation contexts use the same authority before
cutting over; otherwise tests can accidentally compare unrelated timelines.

Only then compare other product consumers for promotion to a shared product
primitive under the repository's abstraction gate. Provider token expiry,
certificate validity and historical attestation age are not one common policy.
The current SPIFFE `workload-attested` evaluation timestamp needs its own semantic
review; changing it solely because WebAuthn changed would conflate different
evidence contracts.
