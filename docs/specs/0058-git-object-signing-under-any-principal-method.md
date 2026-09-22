# AP-SPEC-058: Git object signing under any principal method

- **Status:** Draft; written as the first commit of AP-SPEC-057 Epic 3.
  Nothing in this document is implemented.
- **Depends on:** [AP-SPEC-057 Epic 3](0057-evidence-program-for-the-exact-action-boundary.md),
  [AP-SPEC-045](0045-oidc-workload-principal-adapter.md),
  [AP-SPEC-046](0046-sigstore-keyless-evidence-adapter.md),
  [AP-SPEC-047](0047-algorithm-agnostic-verification-foundations.md), the
  principal and status registries in `core/spec/v1/registry.md`, and the
  [profile/domain abstraction boundary plan](../target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md)
- **Scope:** one vertical product package that signs Git commit and tag
  payloads with an Auths proof, verifies them through a pinned trusted
  context, and issues and revokes delegation grants for signing agents;
  the `did:key`, `sigstore-keyless`, and `oidc-workload` principal methods
  for signers; no KERI code path
- **Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** specify
  implementation requirements

## 1. Decision and claim

The only working agent commit-signing path today lives in the KERI-coupled
sibling project: `auths sign HEAD --scope sign_commit`, delegated agents
created with `auths id agent add`, and verification that replays the
root's key event log. Proofs from that path cannot be produced by any other
identity system. That supports the review's strongest strategic objection
(review §H, product 1): the format is tied to one identity method.

This spec moves commit and tag signing onto the auths-proof kernel. A signer
under **any registered principal method** produces one Auths proof over the
exact Git object payload. One verifier action accepts that proof when it
chains, through attenuated grants, to a root pinned in the verifier's trusted
context. Delegation is a signed grant. Revocation is a signed status record
under `auths-grant-status-v1` or `auths-principal-status-v1`. No method's
ledger is involved.

Defaults, from the board decision of 2026-09-21:

| Signer | Principal method | Why |
| --- | --- | --- |
| Local agent or developer | `did-key-v1` | Self-certifying, offline, no issuer |
| CI workload | `sigstore-keyless-v1` | Short-lived key; Rekor supplies authenticated signing time |
| CI workload, live gate only | `oidc-workload-v1` | No log dependency, but verification needs the issuer key set current at gate time |
| Grant-issuing human root | `did-key-v1` in this epic; `webauthn-v1` / `hsm-attested-v1` after it (§7) | See §7 for why the live WebAuthn ceremony is deferred |
| Any | `did-keri-v1` | Available because it is registered, never a default, and never required |

**Claim, once accepted.** For a pinned trusted context, the verifier accepts a
commit or tag exactly when a valid Auths proof authorizes `git/sign-commit`
or `git/sign-tag` for that repository and that exact unsigned payload, under
a grant chain that is unexpired and unrevoked **at the verifier's evaluation
time and in the status records the verifier holds**. It says who authorized
the object. It does not say who wrote the content, that the Git author or
committer fields are true, or that a revocation the verifier never received
has taken effect.

**Not a claim.** A signed commit is not an executed effect. There is no
provider, credential lease, or reservation. The enforcement boundary is the
consumer that refuses unverified objects, such as a branch-protection
required check. A repository that does not run the verifier is unaffected.

## 2. UX

Operator (root) setup, once per repository or organization:

```text
$ auths git root init --out root.did-key          # or: an existing root principal
$ auths git trust init --root <root-principal> --repository github.com/acme/app \
    --out .auths/git-trust.cbor
```

Delegating a local agent (the port of `auths id agent add`):

```text
# On the agent host:
$ auths git agent init --label claude-release     # prints did:key:z6Mk…; no secret on stdout
# On the root host:
$ auths git grant --root <root> --subject did:key:z6Mk… \
    --repository github.com/acme/app --capability sign-commit,sign-tag \
    --expires-in 90d --out claude-release.grant.cbor
# On the agent host:
$ auths git agent install-grant claude-release.grant.cbor
$ git config gpg.format x509
$ git config gpg.x509.program auths-git-sign
$ git config user.signingkey auths:claude-release
$ git commit -S -m "…"                            # headless; no prompt, no re-signing
```

Delegating a CI workload names the exact workload subject rather than a key:

```text
$ auths git grant --root <root> \
    --subject 'oidc-workload:<pct-issuer>#<pct-subject>' \
    --repository github.com/acme/app --capability sign-tag --expires-in 365d
```

`sigstore-keyless-v1` and `oidc-workload-v1` name the same principal: the
workload identity `oidc-workload:<issuer>#<subject>`
(`core/adapters/auths-oidc-workload/src/lib.rs:486`,
`core/adapters/auths-sigstore-keyless/src/lib.rs:638`). They differ only in
verification method (`#fulcio-…` versus `#oidc-…`). One grant to a workload
therefore admits either method. The verifier's enabled method set decides
which method is accepted. The subject is the exact percent-encoded issuer
and `sub` claim, such as GitHub's `repo:acme/app:ref:refs/heads/main`. It is
not a pattern.

Revocation (the port of the sibling project's one-line revoke):

```text
$ auths git revoke --root <root> --grant <grant-id> --out status/<grant-id>.cbor
# Merge the status record into the verifier's trust material (§3.5).
```

Verification:

```text
$ auths git verify origin/main..HEAD --trust-from-ref origin/main
  3 commits verified
  a1b2c3d  did:key:z6Mk… (claude-release) ← root did:key:z6Mf…  git/sign-commit
  …
$ auths git verify HEAD --trust-from-ref origin/main --json
```

`git verify-commit` and `git log --show-signature` MUST also work through the
same program when `gpg.x509.program` is set. They report good or bad; the
detailed result comes from `auths git verify`.

The terminal and JSON output MUST show the signing principal, each grant in
the chain, the root, the capability used, the evaluation time, and the digest
of the trusted context. They MUST NOT present the Git author email as the
signer.

## 3. Contract

### 3.1 Profile and actions

This introduces the profile **`auths.git-signature/1`**. It is not the existing
`auths.git/1` (`product/spec/v1/git-action.md`). That profile authorizes ref
mutations against a target object ID. This one authorizes a signature over an
object payload. The evidence differs, so under the boundary plan
("If two effects require different evidence… they are separate profiles")
they are separate profiles. `core/spec/v1/registry.md` lists `commit` under
`auths.git`. That row MUST be corrected in the same change that registers
this profile.

The profile has two typed actions. Each has its own decoder, evaluator, and
verified command. Neither dispatches on a generic operation tag:

| Field | `CommitSignatureAction` | `TagSignatureAction` |
| --- | --- | --- |
| `repository` | canonical lowercase `host/owner/name` | same |
| `object_format` | `sha1` or `sha256` | same |
| `payload_digest` | 32-byte SHA-256 (§3.2) | same |
| `tag_name` | absent | the exact tag name as it appears in the payload |

Capabilities and resources, using the registered `uri-namespace-v1` matcher:

```text
git/sign-commit   git://<repository>/commits
git/sign-tag      git://<repository>/refs/tags/<tag_name>
```

A grant on `git://<repository>/refs/tags/` covers every tag in that
repository. A grant on `git://<repository>/refs/tags/release/` covers only
tags under `release/`. The sibling project's `sign_commit` and `sign_release`
scopes map to `git/sign-commit` and `git/sign-tag`. There is no alias
spelling (AGENTS.md prelaunch rule).

### 3.2 What exactly is signed

A commit's object ID covers its own signature header, so a proof cannot bind
the object ID it is embedded in. 0057 Epic 3's phrase "over the object
digest" is therefore read as **over the digest of the exact unsigned
payload**:

```text
payload_digest = SHA-256( "auths.git-signature/1\0" || kind || "\0" || payload )
kind           = "commit" | "tag"
payload        = the exact bytes Git passes to the signing program:
                 the commit object without any gpgsig / gpgsig-sha256 header,
                 or the tag object without its trailing signature block
```

The verifier MUST recompute `payload` from the object it is verifying. It MUST
NOT use a payload supplied alongside the proof. A difference of one byte
produces `git.payload-digest-mismatch`.

For tags, the verifier MUST also check that the payload's `tag` header equals
`tag_name` in the action.

### 3.3 Where the proof lives

The proof is carried in Git's native signature slot through the external
signing-program interface (`gpg.format = x509`, `gpg.x509.program`), the
same mechanism `gitsign` uses:

```text
gpgsig -----BEGIN SIGNED MESSAGE-----
 <base64 of: "AUTHS-GIT-SIGNATURE/1\n" || proof CBOR || canonical action CBOR>
 -----END SIGNED MESSAGE-----
```

It was chosen over the alternatives below because it travels with the
object, needs no history rewrite, and makes `git commit -S` headless:

| Alternative | Rejected because |
| --- | --- |
| Commit-message trailers | Changes the payload, which forces a rewrite after commit (the sibling's `--autostash` re-signing) |
| `refs/notes/auths` | Not pushed or fetched by default; easy to drop silently |
| SSH signature slot (`SSHSIG`) | The envelope binds an SSH key, not a principal method or grant chain |

Accepted costs: GitHub shows these commits as "Unverified"; a commit cannot
also carry a GPG or SSH signature; and a verifier configured with a different
x509 program (such as `gitsign`) fails to parse the envelope. Each failure is
closed rather than a false accept. Step 1 of §6 MUST confirm the armor and the
status-line protocol against Git on hosted Linux and macOS before any other
code lands. If Git rejects the envelope, this section is revised before
implementation continues.

### 3.4 Signing

`auths-git-sign` is the program Git invokes. It:

1. reads the payload from stdin and computes `payload_digest`;
2. builds the canonical action from the payload and the repository recorded
   by `auths git agent init` (`auths.repository` in Git config); if the
   payload cannot be parsed as the expected kind, or the repository is unset,
   it refuses;
3. checks locally that an installed grant covers the capability and
   resource. This fails early for usability only; the verifier is the
   authority;
4. signs through the principal method's signer; for `did:key`, a local key
   under the custody described below;
5. writes the armored envelope and the status lines Git expects.

Local `did:key` custody in this epic is a software Ed25519 key in a file with
mode `0600` under the Auths state directory. The signer MUST report custody as
`software`. That tells a verifier or reader it is not hardware-protected.
Secure Enclave or PKCS#11 custody for agent keys is outside this epic (§7).
The private key MUST NOT appear in argv, the environment, stdout, stderr,
logs, or Git config.

For `sigstore-keyless`, the signer performs the AP-SPEC-046 producer journey
(ephemeral key → Fulcio → Rekor → `auths-sigstore-bundle-import`) and embeds
the imported evidence in the proof. For `oidc-workload`, it requests a token
whose audience commits to the ephemeral key (AP-SPEC-045). Network
acquisition happens in the signer, never in the verifier.

### 3.5 Trust, status, and evaluation time

The verifier's trusted context names the pinned roots, the accepted principal
methods, the Fulcio and Rekor anchors and pinned OIDC issuer key sets when
those methods are enabled, the expected repository, the status records, and
the executable registry configuration commitment. Its source is outside the
objects being verified:

- `auths git verify` MUST take trust from `--trusted-context <path>` or
  `--trust-from-ref <ref>`. With `--trust-from-ref`, it MUST refuse with
  `git.trust-from-verified-range` when the ref resolves to a commit inside the
  verified range. A pull request cannot supply its own trust.
- The provided CI action MUST read trust from the protected base branch.

Status records (`.auths/git-status/*.cbor`) sit next to the trusted context
and are selected revoked-dominant under the registered status methods. In
this epic, revocation takes effect for a verifier **when the revocation record
is present in the trust material it reads**. Status freshness (a maximum age
after which the verifier requires a newer signed "active" record) is
supported by the registry but is **off by default**. Turning it on requires a
root that re-signs status periodically, which conflicts with a rarely used
human root. Without freshness, rolling back the trust material by deleting a
revocation record from the protected branch would restore the old grant.
Branch protection on the trust path is the control for that. The status
freshness mode is documented, not defaulted.

Evaluation time is supplied by the verifier: the wall clock for a gate, or an
explicit `--at` time. This is **gate-time verification**. Re-verifying an old
commit after its grant expired returns `denied`, which is correct for the
gate question and wrong for the historical question. Historical verification
is a non-goal (§7). The one exception is `sigstore-keyless`: it carries
authenticated signing time. The epic MUST NOT use that time to widen grant
validity until a separate decision records the rule.

### 3.6 Limits

| Input | Limit | On excess |
| --- | ---: | --- |
| Unsigned payload | 1 MiB | `git.payload-too-large` |
| Armored envelope | 192 KiB | `git.envelope-too-large` |
| Decoded proof | 128 KiB, and each method's registered evidence ceiling | kernel stage code |
| Grant chain depth | 4 | kernel stage code |
| Commits in one `verify` range | 10,000 | `git.range-too-large` |
| Status records read | 4,096 | `git.status-set-too-large` |

### 3.7 Stable codes

Profile codes are owned by `auths-git-signing`, not by core `error-codes.md`.
They use the `git.` prefix. Kernel stage codes pass through unchanged.

| Code | Class | Meaning |
| --- | --- | --- |
| `git.unsigned` | denied | No signature header |
| `git.not-auths-envelope` | denied | Signature present but not this envelope |
| `git.envelope-malformed` | denied | Envelope armor, prefix, or CBOR framing invalid |
| `git.payload-digest-mismatch` | denied | Recomputed payload does not match the action |
| `git.kind-mismatch` | denied | Commit action on a tag, or the reverse |
| `git.tag-name-mismatch` | denied | Tag header differs from `tag_name` |
| `git.repository-mismatch` | denied | Action repository differs from the trusted context |
| `git.object-format-mismatch` | denied | Action format differs from the repository's |
| `git.trust-from-verified-range` | indeterminate | Trust source is inside the verified range |
| `git.payload-too-large`, `git.envelope-too-large`, `git.range-too-large`, `git.status-set-too-large` | denied | §3.6 |

## 4. Placement and architecture

```text
product/integrations/auths-git-signing/     (new vertical package)
  canonical.rs   CommitSignatureAction, TagSignatureAction, payload digest
  object.rs      bounded commit/tag payload parsers; envelope armor
  evaluate.rs    per-action evaluators and VerifiedCommitSignature / VerifiedTagSignature
  grant.rs       grant and revocation authoring over existing auths-author
  signer.rs      did:key software custody; sigstore/oidc producer calls
  verify.rs      range verification, trust-source rule, result rendering
  bin/auths-git-sign.rs
product/runtime/auths-node      `auths git …` subcommands (thin)
.github/actions/verify-commits  composite action for branch protection
```

- Core is unchanged unless a missing canonical binding is shown. Principal
  methods are supplied to the existing registry assembly
  (`core/crates/auths-registries/src/lib.rs`); the verifier configuration
  commitment covers exactly the enabled set.
- Git object parsing is its own bounded parser. It MUST NOT use libgit2
  object decoding on untrusted objects. `auths-github` and `auths-radicle`
  are not refactored to share it; the boundary plan allows that only after
  equivalence is shown.
- The sibling project is a reference for UX only. No code, types, KEL
  replay, or storage layout is ported (AGENTS.md: retired repositories are
  not sources of truth).
- The package is registered in `architecture.toml` and `compliance.toml`,
  with claim-to-test evidence, in the change that creates it.

The boundary plan's Phase 2 (a durable exact-effect boundary) mostly does
not apply, and this spec says so rather than inventing state. There is no
credential, provider, reservation, or replay store. A proof is bound to one
exact payload in one repository, and presenting it again for the same object
is the same verification. The irreversible step is a merge, which the
consumer's branch protection controls.

## 5. Principal-method neutrality requirement

"No KERI code path" is checked mechanically, not by review:

1. `auths-git-signing` and the `auths git` subcommands MUST NOT depend,
   directly or transitively, on `auths-did-keri`. An `xtask arch` rule
   enforces this.
2. The default verifier registry for `auths git verify` enables `did-key-v1`,
   `sigstore-keyless-v1`, and `oidc-workload-v1`. `did-keri-v1` is enabled
   only by an explicit operator flag, and its absence is tested.
3. One verifier invocation over one range MUST accept commits whose chains
   end in all three default methods under one root.

## 6. Epic and acceptance

Sizes are for one engineer or agent, as in 0057 §3.

1. **Envelope spike** (1–2 days). A hosted CI test makes Git on Linux and
   macOS call a stub `auths-git-sign` for `commit -S`, `tag -s`,
   `verify-commit`, and `verify-tag`, and records the exact argv, stdin, and
   status lines. Done: the test is green on the exact revision, and §3.3 is
   confirmed or amended in the same PR.
2. **Fixtures first** (2–3 days). Canonical valid and invalid vectors for
   both actions, hostile payloads (extra headers, duplicated `gpgsig`, CRLF,
   NUL, oversized, SHA-256 repositories), and envelope mutations. Done: vectors
   exist and fail against the empty implementation.
3. **Actions, evaluators, verifier** (1 week). §3.1–3.2 and §3.5–3.7 with
   `did:key` only. Done: the vector corpus passes; denial happens before any
   status or network access; `--trust-from-ref` inside the range is refused.
4. **Signer and delegation commands** (1 week). `auths-git-sign`, `agent
   init`, `grant`, `install-grant`, `revoke`, and software custody. Done: a
   hosted test commits with `git commit -S` headlessly, verifies it, revokes
   the grant, and sees the next verification denied.
5. **Sigstore and OIDC signers** (1 week). Done: a hosted GitHub Actions job
   signs one commit through `sigstore-keyless` and one through
   `oidc-workload`, and a single `auths git verify` over a range holding
   those two and one `did:key` commit accepts all three under one root, with
   `auths-did-keri` absent from the dependency graph (§5).
6. **Branch-protection action and dogfood** (2–3 days). The composite
   action, and this repository's own agent commits signed through it in
   place of the sibling project's `claude-release` agent. Done: a PR in this
   repository shows the required check passing on agent-signed commits and
   failing on an unsigned one.

**Acceptance (from 0057 Epic 3), split by who can supply the evidence:**

| Clause | Evidence | Who |
| --- | --- | --- |
| The same verifier accepts proofs chained to Sigstore keyless and to `did:key`, with no KERI code path | Step 5 hosted run and the §5 dependency rule | Agent |
| Delegation commands ported | Step 4 hosted test | Agent |
| Demo from three principal methods | Step 5 range | Agent |
| Twenty external repositories verify agent-signed commits through the pinned root | Public list of repositories with the action required | Humans; board §9 |
| One organization enforces verification in branch protection | That organization's settings or a written statement from it | Humans; board §9 |

The epic is **engineering-complete** after steps 1–6. It is **accepted** only
when the two human rows have evidence. A commit title MUST NOT say
`complete` for this epic before that (0057 §2).

## 7. Non-goals

- **Historical verification** of objects whose grants have since expired,
  including using Rekor time to widen grant validity. It needs its own
  decision on trusted time.
- **A live WebAuthn or HSM root ceremony.** Verifier support for chains
  rooted in `webauthn-v1` and `hsm-attested-v1` is tested with testkit
  vectors. Interactive root signing from the CLI is later work.
- **Hardware custody for agent keys** (Secure Enclave, PKCS#11). The software
  custody label keeps this visible.
- **GitHub's "Verified" badge**, co-signing with GPG or SSH, or mapping Git
  author emails to principals.
- **Signing arbitrary files or release artifacts.** That is the
  `auths.supply-chain` profile's work.
- **Porting KEL rotation.** An agent key is rotated by granting the new key
  and revoking the old grant.
- **Sharing a Git object parser** with `auths-github` or `auths-radicle`
  before a Phase 5 comparison.

## 8. Readings this spec had to choose

| Sentence | Readings | Pick |
| --- | --- | --- |
| 0057 Epic 3: "proof over the object digest" | (a) over the object ID; (b) over the unsigned payload | (b): (a) is impossible because the object ID covers the signature (§3.2) |
| Registry: `auths.git` operations include `commit` | (a) extend `auths.git/1`; (b) new profile | (b): different evidence (§3.1); the registry row is corrected |
| Registry: "pinned manifest `33` repeated 32 times" | (a) any other registry set is denied, so enabling `sigstore-keyless-v1` / `oidc-workload-v1` needs a new manifest; (b) the configuration commitment already covers caller-supplied sets | **Not checked.** Step 3 MUST resolve this before step 5; if (a), the manifest change is a reviewed wire change under AGENTS.md |
| 0057: "one-line revoke" | (a) revocation effective everywhere at once; (b) a signed record that verifiers apply when they hold it | (b): offline verification cannot learn of records it was not given (§3.5) |

## 9. Verification and release boundary

Development is fixture-first. Hosted CI on the exact revision is the gate;
this specification runs no checks and asserts no outcomes. Until step 6 is
green, the sibling project's `claude-release` agent remains the only working
agent signing path. Documentation MUST NOT describe auths-proof as able to
sign commits before then.
