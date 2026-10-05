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
| Prover weakens quorum | Approval requirements (K of N named approvers) are held by the verifier's trusted context or a grant, never by the proof; approvals bind the verifier's requirement identifier, so a proof cannot lower K or change the set. For plan compositions, the host context requires minimum branch/actor/root diversity and, when set, the exact plan |
| Stray, forged, or repeated approvals | An approval counts only when it binds the exact action, audience, challenge, window, and requirement, verifies under the approver's anchor, and passes status; each listed approver counts once; order is irrelevant |
| Self-approval | An approval by any principal of the action's authority chain (a grant issuer or subject, or an actor) never counts |
| Same signer cloned into leaves | Distinct-actor and distinct-root obligations count principals, not proof references |
| Same key under another identifier | Principals use exact identifier equality, so one key anchored under two principal methods (for example `did:key` and `raw-key-v1`) counts as two principals; the host anchors each key under one method |
| Algorithm confusion | Exact algorithm registry and key compatibility checks |
| Body modification | SHA-256 of exact body is signed |
| Cross-service replay | Audience and verifier challenge are signed |
| Time replay | Short action/grant windows checked against explicit time |
| Authority expansion | Permission subset, contained validity, decreasing depth |
| Grant reordering/removal | Signed parent `GrantId` chain |
| Self-declared trust | Roots exist only in local verifier context |
| A partner's status issuer overrides another root's subjects | Each status trust rule carries a scope (`own`, `anchors`, `any`); a statement whose issuer's scope does not cover the branch's trust anchor takes no part in status evaluation (AP-SPEC-064) |
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

## Production gateway: provider-secret custody and recipe qualification

This section covers the generalized gateway's production deployment
([AP-SPEC-066](specs/0066-production-gateway-polish-and-recipe-qualification.md)).
The verifier's claim above is unchanged. What is added is a claim about where a
provider credential lives and about what a `qualified` label means.

**Status.** The production credential store, the release verifier, the
issuance tooling, and the runtime qualification gate exist. The support
bundle does not. No qualification trust root or release signer has been
created, no recipe is qualified, and the protected run has not been held: the
qualification controls below are enforced in code and exercised only under
keys made for tests. A row marked *specified* names a control with frozen
vectors and no implementation; it protects nothing yet.

### Added trust assumptions

- The cloud provider's workload identity correctly names the gateway
  workload, and its access policy is the operator's.
- The secret manager returns the exact version requested, or fails.
- The qualification trust root's private key is offline: absent from this
  repository and from pull-request and qualification runners.
- The protected release environment releases the signing key only after
  manual approval. That key is software-held; nothing here claims hardware
  protection or non-exportability for it.
- The deployment's time synchronization is honest when it reports a trusted
  clock.

### Threats and controls

| Threat | Control | Status |
|---|---|---|
| An application, action, or recipe selects a credential generation, store, location, or version, or an action or store chooses the injection header | The recipe source and the submission frame refuse unknown members; the store kind is a closed operator choice; a store receives a view that holds identity, generations, and commitment only. The injection header is the recipe's committed declaration under the approved digest: a bearer recipe has none to set, and a reserved header is refused at compile | enforced |
| A credential store is asked to find "the current" secret | The sealed binding names the exact credential generation; a lease reads that generation and searches for no other; a superseded credential never serves a later generation | enforced for the in-repository stores |
| Another workload assumes the gateway's identity and reads provider secrets | Workload identity scoped to the gateway's namespace and to read-only access on its own secret names; the qualification signer, observer, application, and grant-root identities are distinct from it | specified |
| The secret manager is compromised or returns other material | The connection record seals a commitment to the exact material; the lease compares it in constant time and fails before any request byte exists; the gateway requests an exact immutable version, never a stage or alias | commitment check enforced; exact-version read specified |
| The secret manager is unreachable | The lease fails closed as `gateway.credential.unavailable`; there is no fallback to another generation, a local file, an environment variable, or cached material | specified |
| A plaintext development store is used in production | Production policy refuses the local file kind; unknown kinds are refused, not defaulted | kind type enforced; production refusal specified |
| Rotation leaves an attempt with half of each generation | Generation and commitment are replaced as one record; an admitted attempt keeps its whole old generation, retained for 20 seconds, longer than the 15-second transport bound | delay invariant enforced at compile time; rotation commands specified |
| A possibly compromised credential keeps being used during cutover | Disable, wait the retirement delay, rotate, revoke, enable; an attempt that has not entered when the old generation is revoked is recorded not entered and never retried with the new one | specified |
| Secret material leaks through logs, traces, metrics, debug output, or a support bundle | Secret types print a fixed redacted form and have no serialization; the support bundle excludes every listed source and is scanned for planted canaries | debug forms enforced; bundle specified |
| A recipe, connection, SDK, flag, or operator declares a recipe qualified | The qualification state has no parser; it is derived only from verified signed inputs. A recipe that names a qualification member is refused at compile | enforced: the state is derived only by the gate from verified inputs; production refuses the optional policy |
| The qualification trust root is compromised | Every certificate and revocation it signs is forgeable; recovery is a separately reviewed release that pins a successor root, never a runtime fetch. The root signs only certificates and revocations, so its key is used rarely and offline | specified; residual risk accepted |
| The release signer is compromised | The root revokes the signer, which invalidates every attestation it issued regardless of issue time. A signer cannot sign a certificate, a revocation, or a root: each artifact kind has its own signing domain and the certificate lists the kinds it permits | domains and closed kinds enforced; revocation specified |
| A forged, replayed, or cross-kind signature is presented | Each signature covers the schema, a NUL byte, and the canonical statement; a signature for one artifact kind never verifies as another | enforced: the verifier checks each signature under its own domain |
| An expired or stale input keeps a recipe enabled | Freshness comes only from signed fields with fixed maxima (90 days, 365 days, 72 hours); no configuration, flag, or grace period widens them; a revocation list past its next update disables every required recipe | enforced at decode and at the gate before every lease |
| The gateway's clock is wrong | A closed clock trust state from a maintained deployment adapter; an untrusted clock, or local time behind a signed issue time, disables every required recipe | enforced; the production adapter reads one synchronization service's marker |
| The provider changes its API while the recipe bytes stay the same | The provider contract identifier is a digest of the API release, the OpenAPI slice, the manual assumptions, the environment class, the corpus, the oracle version, and the declarations; any change makes the qualification stale | identifier enforced; staleness specified |
| An older revocation list or release index is replayed | Revocation lists carry an increasing sequence; a list older than the one already accepted is refused | enforced: the gate treats an older list as unusable and import refuses it; revocations are remembered per host |
| The runtime gateway becomes a qualification runner, or the runner becomes a runtime credential broker | The gateway performs no provider call, network trust fetch, or qualification run for readiness; the qualification credential is environment-scoped and distinct from every production connection credential; the qualification model depends on no core or provider crate, enforced by `architecture.toml` | enforced: the gate reads local inputs only and a gateway build contains no issuance crate |
| A pull request signs or imports a qualification | Pull-request jobs produce unsigned proposals only and cannot reach either private key or update the release index | enforced: a test reads the workflow; the signing environment admits only the default branch with a reviewer; import refuses anything no signer indexed |
| A successful HTTP response is counted as a qualified live effect | A record whose live effects are not all confirmed by read-back does not decode | enforced |

### Not protected by this section

- An application that holds its own provider credential can call the provider
  directly. Custody removes the credential from the application; it cannot
  remove one the application already has.
- A provider secret is exportable by nature: it exists in gateway memory for
  the length of one request. Custody bounds where it rests, not that.
- Qualification is evidence about one pinned recipe and provider contract at
  one time. It does not say the provider performed, settled, or will preserve
  the effect, or that it will behave tomorrow as it did during the run.
- A compromised cloud account, secret manager operator, or gateway host is
  outside these controls.
- Separation of persons: a second key does not prove a second person. The
  human release review is a judgment recorded on the program board.

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
