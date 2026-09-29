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
| Operator | The gateway host, its admin socket, and the provider credentials | A signed operator attestation at install |
| Observer | The key that signs what the gateway saw, in qualified custody | Observer anchors of the trusted context |

A production installation names its operator only through a signed
`auths.gateway-operator-attestation/1` statement. `operator-request` prints
the statement for the installation and the preimage the operator's own
signer signs; the operator assembles the statement, the base64url signature,
and at most four control-evidence objects into a file of at most 16 KiB,
readable only by its owner:

```text
auths-gateway operator-request --recipe recipe.json --profile-lock profile.lock.json \
  --trusted-context trusted.context.cbor --provider <provider> --alias <alias> \
  --deployment production --operator-principal <principal> \
  --principal-method did-key-v1 --verification-method <method> --signature-suite ed25519-v1
auths-gateway install --deployment production --operator-attestation operator-attestation.json ...
```

`install` and every `serve` start verify the attestation as the kernel
verifies a signed object: the named method (`raw-key-v1`, `did-key-v1`, or
`did-keri-v1`) establishes the key from the control evidence for assertion,
and the named suite verifies the signature. Its installation block must
equal the installation, and its signing time may be at most 300 seconds
ahead of the gateway clock. `operator-attest --replace` replaces it offline,
with every gateway process stopped. A development installation may omit it
and then has no operator.

Install and every `serve` refuse an overlap with one stable code:

| Code | Meaning |
| --- | --- |
| `gateway.install.operator-attestation-required` | Production install or serve without an operator attestation |
| `gateway.install.operator-attestation-invalid` | The attestation does not verify, names another installation, or is issued in the future |
| `gateway.trust.operator-is-root` | The operator is a trust anchor |
| `gateway.trust.operator-is-observer` | The operator is an observer anchor or the gateway's observer key |
| `gateway.trust.observer-is-root` | An observer anchor, or the gateway's observer key, is a trust anchor |
| `gateway.trust.observer-not-anchored` | The gateway's observer key is not an observer anchor of the trust |
| `gateway.trust.key-aliased` | Two distinct trust or observer anchor identifiers name one key |

Two principals overlap when their identifiers are equal or their key
identities are: the SHA-256 of the canonical `raw-key-v1` descriptor of the
one key a `raw-key-v1` or `did:key` identifier names. One Ed25519 or P-256
key under both methods therefore overlaps itself. Other methods (`raw-key-v2`,
`did:keri`, keyless methods) name no single key and keep identifier
comparison, so anchor each key under one principal method and keep the
custody of the three principals separate. An authenticated operator holds the
key it names; separation of persons stays a human gate.

The kernel separately refuses, per proof, an observer whose identifier
appears in the proof's authority chain (`observer-in-authority-chain`).
Before the claim, the gateway also refuses an observer of a satisfying
observation that overlaps by key the root, a grant issuer or subject, or the
actor of an authorized branch
(`gateway.trust.observer-key-in-authority-chain`).

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
  `auths.lifecycle.postgresql/5`; it installs only into an empty database.
  A database created at schema 4 or earlier is disposable prelaunch state:
  recreate it. Gateway claims are stored as attempt record
  `auths.gateway-attempt/3`; a store holding `/2` records is refused as
  corrupt, so the file store's attempts directory is recreated too.
- **Several gateway processes** may serve from the same database. Each
  logical operation is claimed once, by an insert-once row; stage changes are
  compare-and-swap on the exact stored record. A second process that loses a
  race records nothing and answers `gateway.attempt.replay`. Gateway claims
  do not take the lifecycle store's singleton contract-row lock.
- **Spend limits.** A grant's bounded policy (evaluator
  `auths.gateway.argument-ceiling-window-count/2`) counts per link subject in
  fixed, epoch-aligned windows, in the attempt store: every gateway process
  sharing the store charges the same count and sum slots, reserved with the
  claim. A namespace served from two stores, or a store that is wiped or
  restored, counts separately; reinstall under a new namespace after a loss.
  `serve` deletes count and sum slots one full window after their window
  ends, at most 1 024 every 60 seconds, and never deletes a claim.
- **Connection state is shared.** The connection record
  (`auths.provider-connection/2`) lives in the attempt store, so every process
  sharing the store reads it before each claim, again before the credential
  lease, and again before entry. A disable, enable, rotation, or revocation
  committed through any process's admin socket stops new leases and entries
  in every process at its next reload. Each process keeps its own credential
  store (`credentials.cbor`), and nothing secret enters the shared store. The
  first host runs `install`; each further host runs `install --join` with the
  same recipe, trust, lock, provider, alias, deployment, and store, and the
  same secret, which it stores only when its reference commitment under the
  record's credential generation matches (`gateway.install.join-commitment-mismatch`
  otherwise). A `rotate` through a process holding the current secret commits
  a new generation; every other process then runs its own `rotate` with the
  same secret to take it (`gateway.admin.generation-conflict` for another
  secret). Until it does, that process refuses entries before the claim
  (`gateway.connection.credential-generation-missing`). A later disable or
  enable leaves every process that holds the secret able to lease. After a
  revocation, run `revoke` on each process to delete its stored secrets.
  A submission refused while the connection is disabled or revoked is
  refused before the claim, so the gateway records nothing and signs no
  outcome for it. A valid proof refused this way is `unverified` in the
  offline audit and fails it, with or without `--allow-unverified-refusals`;
  explain such entries from the attempt store.
  A store holding an `auths.provider-connection/1` record is obsolete
  prelaunch state: recreate it.
- **Development** installations keep the single-host file store under
  `<state-dir>/attempts`, or under the absolute directory `--attempt-store`
  names so that several processes on one host share it. It is not a
  multi-host store.
- **Sockets.** `serve` keeps separate capacity for the app socket
  (`--app-capacity`, 1–1 024, default 64) and the owner-only `admin.sock`
  (4), so `auths-gateway disable`, `enable`, `revoke`, `rotate`, `status`,
  and `reobserve` still connect while the application holds or refills the
  app socket. A connection past either socket's capacity is closed at accept
  without a response. An admin change commits without waiting for any
  submission or provider call, then waits at most 20 seconds for this
  process's entries already past their final reload, and answers `drained`
  with the remaining `in_flight` count. `serve` refuses to start when the
  descriptor limit is below both capacities plus the store pool plus 32
  (`gateway.serve.descriptor-limit`). A failed accept is logged as
  `gateway.serve.accept-failed` and retried; it does not stop `serve`.
- **Observer custody.** A production installation refuses the software
  observer seed (`gateway.production.observer-software-custody`), and
  `observer-init` refuses to create one. The engine accepts a custody-held
  observer (`GatewayObserver::from_custody`). The `auths-gateway` binary has
  no maintained KMS or PKCS#11 client yet, so a production gateway currently
  runs without signing observations; observation requests are refused with
  `gateway.observer.not-provisioned`. Its audit bundles therefore carry no
  outcomes: `auths-gateway audit` reports every entry `unverified` and exits
  non-zero (`audit.unverified`), and `--allow-unverified-refusals` does not
  change that for any entry whose proof verifies.

## 3. Observer key rotation

Rotate the observer on a schedule, and immediately if the key or its
custody is suspect.

1. Enrol the new observer key in custody (KMS or PKCS#11) as a P-256 key
   presented as `raw-key-v1`, following the custody runbook's planned
   rotation. Do not disable the old key yet.
2. Record the new key's anchor facts: principal, `raw-key-v1`, verification
   method, `p256-sha256-v1`, both schemas (`auths.gateway-readback/1`,
   `auths.gateway-outcome/2`), and both subject namespaces. For a
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
