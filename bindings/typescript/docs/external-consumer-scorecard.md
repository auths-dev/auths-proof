# External-consumer SDK scorecard

This scorecard describes the AP-SPEC-040 prelaunch cutover. Earlier
token-and-endpoint, caller-defined executor, GitHub-specific, and local-agent
session launch scorecards are superseded and are not compatibility
commitments.

## Ordinary consumer shape

| Measure | Current contract |
| --- | --- |
| Write inputs | proof bytes and canonical action bytes only; no token, credential, URL, or request body |
| Write path | operator-run gateway over a local socket |
| Provider credentials | gateway connection store only |
| Domain meaning | operator-reviewed compiled recipe and Rust verifier |
| Result | closed gateway outcome: denied, indeterminate, not-entered, unknown, response-recorded, observed, or observed-by-provider |
| Possible effect | `unknown` outcome; recover by a gateway-signed outcome or read-back, never a blind retry |
| Registry startup cost | generated digest plus bounded runtime projection; no eager full-registry load |

## Repository-local evidence

- The root, gateway, and every other public API inventory are exact
  snapshots.
- Compile-time contracts reject application tokens and remote endpoints and
  keep receipts and identities package-minted.
- A packed consumer sees the reviewed public topology, and the removed
  local-agent connector and `./profile-runtime` subpath do not resolve.
- Root startup uses the generated registry digest without hashing or eagerly
  importing the complete error registry.
- The installed Python wheel and the packed npm package each run against the
  gateway test harness.
- Deleted prelaunch security tests are individually inventoried in
  `bindings/security-evidence-cutover-v1.json` with replacement or explicit
  retirement evidence.

## Remaining release gates

- Qualify at least one real provider recipe, then complete the clean-machine
  gateway journey against its operator-provisioned connection.
- Pass all hostile-boundary, effect-safety, restart, and cross-platform hosted
  checks on the exact revision.
- Obtain independent review and artifact provenance.

The SDK capability files intentionally keep evidence at
`repository-local-in-progress` and publication blocked until those gates pass.
