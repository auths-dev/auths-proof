# External-consumer SDK scorecard

This scorecard describes the AP-SPEC-040 prelaunch cutover. Earlier
token-and-endpoint, caller-defined executor, and GitHub-specific launch
scorecards are superseded and are not compatibility commitments.

## Ordinary consumer shape

| Measure | Current contract |
| --- | --- |
| Root connection inputs | local discovery options only; no token, credential, or remote endpoint |
| Provider API | generated domain client and typed method |
| Provider selection | optional non-secret connection alias on the domain constructor |
| Provider credentials | local agent/credential store only |
| Domain meaning | concrete Rust profile vertical |
| Success | generated domain DTO with Auths metadata |
| Possible effect | typed recovery error with a sealed handle; no blind retry |
| Extension ABI | public, versioned `@auths-dev/sdk/profile-runtime` subpath |
| Registry startup cost | generated digest plus bounded runtime projection; no eager full-registry load |

## Repository-local evidence

- The root and profile-runtime public API inventories are exact snapshots.
- Compile-time contracts reject application tokens and remote endpoints and
  require exhaustive outcome narrowing.
- A packed consumer sees the reviewed public topology and profile-runtime
  declarations.
- Root startup uses the generated registry digest without hashing or eagerly
  importing the complete error registry.
- The four launch examples use only the local session and generated Stripe
  client.
- The Python wheel includes the public profile-runtime module, and sealed
  outcome tests cover success and ambiguous-response recovery.
- Deleted prelaunch security tests are individually inventoried in
  `bindings/security-evidence-cutover-v1.json` with replacement or explicit
  retirement evidence.

## Remaining release gates

- Qualify at least one real provider profile, then complete the clean-machine
  local-agent journey against its operator-provisioned connection.
- Pass all profile generator, hostile-boundary, effect-safety, restart, and
  cross-platform hosted checks on the exact revision.
- Obtain independent review and artifact provenance.

The SDK capability files intentionally keep evidence at
`repository-local-in-progress` and publication blocked until those gates pass.
