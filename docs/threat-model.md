# Threat Model

## Protected claim

The verifier protects the integrity of a local decision that a cryptographic
principal held an attenuated authority chain covering an exact action and
context.

## Trust assumptions

- The host selects trustworthy principal adapters and trust anchors and binds
  their exact configuration commitment into the trusted context.
- Cryptographic dependencies behave according to their specifications.
- The host supplies the intended body, audience, challenge, time, and policy.
- The executor executes the same body it asked Auths to verify.
- Private signing keys are protected outside this repository.

## Threats and controls

| Threat | Control |
|---|---|
| Weaker adapter substitution | Adapter, method, and algorithm are signed; registry is explicit |
| Hidden adapter configuration | Context and result bind the exact executable registry and every adapter configuration digest |
| Prover weakens quorum | Host context independently requires the exact plan and minimum branch/actor/root diversity |
| Same signer cloned into leaves | Distinct-actor and distinct-root obligations count principals, not proof references |
| Same key under another identifier | Principals use exact identifier equality |
| Algorithm confusion | Exact algorithm registry and key compatibility checks |
| Body modification | SHA-256 of exact body is signed |
| Cross-service replay | Audience and verifier challenge are signed |
| Time replay | Short action/grant windows checked against explicit time |
| Authority expansion | Permission subset, contained validity, decreasing depth |
| Grant reordering/removal | Signed parent `GrantId` chain |
| Self-declared trust | Roots exist only in local verifier context |
| Evidence replacement or smuggling | Evidence is content-addressed; each successful statement binding exactly equals adapter-reported consumption |
| Backdating after key revocation | Historical key state alone is insufficient |
| Non-canonical signature bytes | Closed deterministic CBOR and low-S P-256 |
| Parser resource exhaustion | Byte/collection/depth limits before cryptography |
| Adapter fallback | Exact lookup; unsupported is `Indeterminate` |
| Hidden network trust | Verification performs no resolution or I/O |
| Truncated/stale embedded KEL | KERI claims current/revocation status only when the exact accepted state matches a fresh verifier-bound checkpoint |
| Forged bundled `did:web` document | Document digest must match explicit host trust supplied outside the proof |
| Removed `did:web` key backdates a statement | Historical document state and exact-statement existence are separate required claims |
| Host retry amplification | `Indeterminate` never authorizes; hosts must bound retries and require new trusted facts |

## Not protected

Auths cannot prevent:

- a trusted root from intentionally granting unsafe authority;
- a currently accepted private key from signing malicious statements;
- misleading application capability/resource names;
- an executor from verifying one body and executing another;
- leakage of metadata present in the proof;
- replay if the host reuses challenges and has no consumption cache;
- compromised adapter or host code;
- global overspend, rate-limit, or exactly-once failures without shared state.

## Raw-key limitation

Raw-key principals have no native rotation or revocation. Their damage window
is bounded only by grant/action expiry and local trust-anchor changes. Verdicts
report this limitation.

## Embedded-KEL limitation

A valid embedded KERI event log can still omit a later event known elsewhere.
The KERI adapter validates the supplied chain, including rotations and
pre-rotation commitments, but cannot prove non-existence of a later rotation
without an external freshness or witness mechanism. Current-state,
witness-quorum, and revocation-check claims therefore require an exact fresh
checkpoint in the verifier configuration.

## `did:web` trust limitation

A resolver trust record is verifier configuration, not evidence an untrusted
prover may self-assert. Compromise of the process that created current or
historical records, its clock, DNS/TLS validation, archival pin store, or the
trust-record file can authorize a forged DID document. The pure kernel
performs no resolution and the pinned records are not a transparency log.

## Reporting

Security reports should follow `SECURITY.md`. This prelaunch implementation is
pre-audit and must not be represented as production-hardened.
