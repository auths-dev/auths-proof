# Gateway trust and Git-signing runbook

This runbook covers the production trust around the credential-isolated
gateway, its observer, and Git signing: separating principals, rotating the
observer key, updating observer anchors in the trust, and issuing Git-signing
revocation records. Custody-provider lifecycle (enrolment, rotation, emergency
disablement, outage) is in the [custody lifecycle runbook](CUSTODY_LIFECYCLE_RUNBOOK.md).

Nothing here asks an operator to copy private key material into Auths.

## 1. Principals

A production deployment keeps three principals apart.

| Principal | Holds | Where it appears |
| --- | --- | --- |
| Root | Grant-issuing key, in qualified custody; production roots MAY be several keys under an M-of-N composition | Trust anchors of the trusted context |
| Operator | The gateway host, its admin socket, and the provider credentials | `--operator-principal` at install |
| Observer | The key that signs what the gateway saw, in qualified custody | Observer anchors of the trusted context |

Install a production gateway with:

```text
auths-gateway install --deployment production --operator-principal <principal> ...
```

Install and every `serve` refuse an overlap with one stable code:

| Code | Meaning |
| --- | --- |
| `gateway.install.operator-principal-required` | Production install without an operator principal |
| `gateway.trust.operator-is-root` | The operator is a trust anchor |
| `gateway.trust.operator-is-observer` | The operator is an observer anchor or the gateway's observer key |
| `gateway.trust.observer-is-root` | An observer anchor, or the gateway's observer key, is a trust anchor |
| `gateway.trust.observer-not-anchored` | The gateway's observer key is not an observer anchor of the trust |

The kernel separately refuses, per proof, an observer that appears in the
proof's authority chain (`observer-in-authority-chain`).

### Root M-of-N

A root can be several keys, none of which authorizes alone. List each key as
its own trust anchor and pin a composition requirement of `M` authorized
branches from `M` distinct roots. A proof then carries one branch per signing
root, combined in a `KOfN` plan. With three anchors and
`CompositionRequirement::new(None, 2, 1, 2)`, two roots authorize; one root,
even with two branches, is denied with `composition-requirement-not-met`
before any claim or credential lease. The root ceremony record, naming who
held which key, is operator evidence and is not produced by this code.

## 2. Production substrate

- **Attempt store.** A production installation keeps logical-operation
  claims, provider-bound evidence, and outcome stages in the multi-host
  PostgreSQL store (its qualification, AP-SPEC-038 Epic 2, is open), through
  the reference deployment's secret slots
  `AUTHS_POSTGRES_URL`, `AUTHS_POSTGRES_CA_PEM`, and
  `AUTHS_POSTGRES_SERVER_NAME`. Connections are TLS-only with
  certificate and server-name verification. The schema is
  `auths.lifecycle.postgresql/4`; it installs only into an empty database.
  A database created at schema 3 is disposable prelaunch state: recreate it.
- **Several gateway processes** may serve from the same database. Each
  logical operation is claimed once, by an insert-once row; stage changes are
  compare-and-swap on the exact stored record. A second process that loses a
  race records nothing and answers `gateway.attempt.replay`. Gateway claims
  do not take the lifecycle store's singleton contract-row lock.
- **Connection state is per process.** Each gateway process keeps its own
  connection and credential state, so a disable, rotate, or revoke made
  through one process's admin socket applies to that process only. Processes
  must not share a state directory.
- **Development** installations keep the single-host file store under
  `<state-dir>/attempts`. It is not a multi-host store.
- **Observer custody.** A production installation refuses the software
  observer seed (`gateway.production.observer-software-custody`), and
  `observer-init` refuses to create one. The engine accepts a custody-held
  observer (`GatewayObserver::from_custody`). The `auths-gateway` binary has
  no maintained KMS or PKCS#11 client yet, so a production gateway currently
  runs without signing observations; observation requests are refused with
  `gateway.observer.not-provisioned`.

## 3. Observer key rotation

Rotate the observer on a schedule, and immediately if the key or its
custody is suspect.

1. Enrol the new observer key in custody (KMS or PKCS#11) as a P-256 key
   presented as `raw-key-v1`, following the custody runbook's planned
   rotation. Do not disable the old key yet.
2. Record the new key's anchor facts: principal, `raw-key-v1`, verification
   method, `p256-sha256-v1`, both schemas (`auths.gateway-readback/1`,
   `auths.gateway-outcome/1`), and both subject namespaces. For a
   development seed, `auths-gateway observer-show` prints them together with
   `observer_custody`.
3. Update the trust as in §4, replacing the principal of the existing
   observer anchor and keeping its anchor ID, so grants whose observation
   requirements name that anchor stay valid.
4. Check the separation codes in §1 against the new trust before install.
5. Install the updated trust into a new gateway state directory and switch
   the gateway to it. In production, attempts stay in PostgreSQL, so replay
   protection carries over. In development, move the old `attempts`
   directory into the new state directory before serving; starting with an
   empty file store would forget every claim.
6. Observations signed by the old key stop satisfying requirements as soon
   as the new trust is installed. An agent holding one gets
   `observation-missing` and must request a fresh observation.
7. Disable, then revoke, the old key in custody.

Never keep both keys under one anchor ID and never fall back to the old key
after the new one fails.

## 4. Observer-anchor updates in the trust

An observer anchor is part of the trusted context, which is independently
provisioned and digest-pinned at install
(`trusted_context_sha256` in `installation.json`).

1. Build the new trusted context with the anchor's principal, accepted
   method (`raw-key-v1`), schemas, subject namespaces, and validity window.
   The validity window must cover the whole period the anchor should count.
2. Keep the verifier configuration the gateway prints; a context that pins
   another configuration is denied with `verifier-configuration-mismatch`.
3. Review that no anchor principal is a root, the operator, or an actor
   under the trust.
4. Install and switch as in §3 steps 4–5. The gateway refuses a changed
   `trusted.context.cbor` in an existing state directory
   (`gateway.serve.installation-changed`); there is no in-place edit.

## 5. Git-signing revocation records

A revocation is its own Auths proof: the pinned root signs a
`git/revoke-grant` action over one grant ID for one repository. It takes
effect for a verifier exactly when the record is in the trust material that
verifier reads.

1. Identify the grant: the terminal grant of the delegation file installed
   for the key or workload being revoked.
2. Sign the record with the root:

   ```text
   auths-git revoke --root <label> --repository <host/owner/name> \
     --grant <delegation.json> --out .auths/git/revocations/<name>.sig
   ```

   The `auths-git` CLI signs with a local software root. A custody-held
   root signs the same record through the library's `CustodyKeySigner`
   over `auths-custody`, since the CLI has no KMS or PKCS#11 client yet:
   the grant or revocation request is
   transaction-bound, the provider response is checked centrally, and the
   signature is verified locally before the record is written. A root whose
   custody lifecycle is not `ready` or `active-current` cannot sign
   (`custody.lifecycle-not-permitted`); restore it or rotate the root first.
3. Commit the record under `.auths/git/revocations/` and merge it to the
   protected branch that verifiers read trust from.
4. Verify: a signature under the revoked grant is denied with
   `git.grant-revoked`. A record that is malformed, names another
   repository, or is not authorized by the root fails the whole trust
   (`git.revocation-invalid`) rather than being ignored.
5. Revocation does not reach verifiers that read an older trust commit, and
   it cannot be withdrawn by deleting the record from a commit that
   verifiers no longer read. Keep the record for the life of the trust.

Git trust pins a single root anchor today; the M-of-N composition in §1
applies to gateway trust.
