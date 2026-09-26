# AP-SPEC-057: Evidence program for the exact-action boundary

- **Status:** Active evidence program; Epic 2 is complete for the documented
  single-host development deployment, while Epics 1 and 3–5 retain open
  evidence gates; this is a sequencing and acceptance specification, not a
  new mechanism
- **Depends on:** [AP-SPEC-051](0051-self-hosted-developer-profiles.md)
  through [AP-SPEC-056](0056-openapi-derived-operation-contracts.md),
  [AP-SPEC-025](0025-closed-bounded-authorization-policy.md),
  [AP-SPEC-038 Epic 2](0038/epic_2.md), and the independent review
  [How revolutionary is Auths Proof, really?](../research/competition/2026-09-21-how-revolutionary-is-auths-proof.md)
  (cited below as "the review", by section letter)
- **Scope:** five epics that produce the three results the review says would
  change its assessment, three explicit non-epics, and the claim-wording
  corrections the review identified
- **Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** specify
  implementation requirements

## 1. Decision and claim

Work is sequenced by the evidence that is missing, not by the feature that
is next. The review scored mechanism novelty 3/10, execution 6/10, and
defensibility 4/10, and named three results that would materially change
those scores (review §I):

1. a released gateway survives a hostile-application test while the
   application demonstrably lacks alternate credential access, including
   restart and competing-instance cases;
2. a published vendor corpus and unfamiliar-user trials show which real
   operations derive and how much provider-specific work remains;
3. an adversarial corpus produces identical parser decisions, canonical
   bytes, commitments, and verification outcomes across packaged Python,
   TypeScript, and native consumers.

This spec assigns result 3 to Epic 1, result 1 to Epic 2, and result 2 to
Epic 4. Epic 3 answers the review's strongest strategic objection (§H,
product 1) by making identity-method agnosticism demonstrable. Epic 5 adds
the one capability (§B, §C) that incumbents can copy as a feature but not
as an offline-verifiable artifact.

The claim boundary does not move during this program. Until Epic 2's
acceptance holds, every document MUST describe the self-hosted path as an
enforced ordering property of a voluntarily called SDK (review §C). Until
Epic 4's wording corrections land, no document may say "formally verified
verifier", "agents have no OIDC identity", or "the stack governs actions"
without the qualifications in §6.

The program's verb is not "unseat". Its strategic outcome is that the
authority-and-evidence format Auths produces is one that existing
credential owners can emit and accept (review §H, §I). Epic 3 is the
cheapest demonstration of that; Epic 2 is the most consequential.

## 2. Evidence rules

Every epic's acceptance is judged by these rules, taken from the review's
own method:

- A claim about code cites `file:line`. A claim about a spec cites its
  number and section.
- "Specified", "built", "tested", and "shown live" are four columns, never
  one word. A commit title that says `prove`, `complete`, or `independent`
  MUST carry that evidence in its own diff or be retitled (review appendix:
  `dc2ad2b`, `9b31882`).
- Hosted CI on the exact revision is the gate. A local run is not evidence.
- "Not checked" is a valid and required answer when something was not
  checked.

## 3. Sequencing

```text
 Epic 1  freeze on evidence        ~1–2 wk   ─┐
                                              ├─ Epic 3  signing, any method   ~3–4 wk (parallel)
 Epic 2  gateway + hostile proof   ~6–8 wk   ─┤
                                              ├─ Epic 4  publish the evidence  ~2 wk   (parallel, non-code)
 Epic 5  bounded policy in path    ~3–4 wk   ─┘  (after Epic 2)
```

Epic 1 gates everything: no epic starts implementation on a red PR. Epics
3 and 4 run beside Epic 2 and MUST NOT share its branch. Epic 5 starts when
Epic 2's hostile suite passes. Sizes are planning estimates for one
engineer or one agent per epic, not commitments.

## 4. Epics

### Epic 1 — Freeze the self-hosted SDK on evidence, not compilation

Closes review §D, the red state of PR #123, and the commit-title audit.

1. Turn review §D's table into one shared adversarial fixture consumed by
   the Python parser (`bindings/python/python/auths/_profile_cli.py:61`),
   the TypeScript parser (`bindings/typescript/tools/profile-cli.mjs:22`),
   both integer projections (`self_hosted.py:86`, `self-hosted.ts:727`),
   and the native canonicalizer: CR-only and U+2028 line delimiters, a
   leading U+FEFF, the name `probe--name` with no explicit command, the
   JSON tokens `1.0`, `1e0`, and `-0` in an integer field, and the
   leading-zero and underscore integer spellings found earlier. Every
   implementation MUST return the same decision, and the fixture MUST fail
   the build when one differs. Where the review left a rule undefined
   (whether `-0` is rejected lexically, at the canonical wire, or as a
   language value: AP-SPEC-054 §5.1), this epic decides it and records the
   decision in the fixture.
2. Fix the TypeScript default-command-name crash
   (`profile-cli.mjs:63`) and the generated conformance starter that calls
   `CONTRACT.decode` with `TextEncoder` bytes instead of an object
   (`profile-cli.mjs:367`). The packed test
   (`test/package/packed-profile-cli.test.js:10`) MUST execute the generated
   starter against the fake provider, not only compile it.
3. Make PR #123 green from its own evidence: the stale `EXPECTED_EXPORTS`
   inventory (`bindings/python/tests/test_public_api_v2.py:48`), the
   pending generated-artifact update, then each remaining failing check by
   its log. Record the root cause of each in the PR description.
4. Complete the freeze blockers already identified: the `auths` console
   script collision (landed as `auths-profile` in `ea54a9d`, renamed back to `auths` on
   2026-09-26 once the deployment binary became `auths-node`; confirm the
   npm `bin` and every document use the new name); TypeScript
   `doctor --production` parity or honest wording (landed in `ea54a9d`;
   confirm); the field-lab SDK pin advanced to the freeze commit with both
   demo workflows green.
5. Apply the commit-title rule retroactively where cheap: publish the
   AP-SPEC-054 Epic 5 participant report that `9b31882` claims, or amend
   the title. State in the claim ledger
   (`docs/product/SELF_HOSTED_CLAIM_LEDGER.md:13`) that the packaged
   consumer path is exercised in CI and that the self-hosted gate is
   voluntary, next to `run_once` in both READMEs
   (`bindings/python/python/auths/execution.py:1`).

**Acceptance:** PR #123 and both field-lab demo workflows are green on one
commit; the adversarial fixture passes identically in Python, TypeScript,
and native; the generated TypeScript starter runs; no commit title on the
branch claims evidence its diff does not contain. This is review result 3.

### Epic 2 — Build the credential-isolated gateway and prove the boundary

Closes review §C and result 1. This is AP-SPEC-053 Epics 1–4 executed
against the review's acceptance rather than the spec's.

1. Recipe AST and compiler (AP-SPEC-053 Epic 1 steps 2–3). Airtable,
   Todoist, and GitHub recipes compile from packaged SDKs with no Auths
   source edit; hostile substitutions of origin, path, header, body key,
   and recipe digest fail before claim.
2. The separate gateway process, operator channel, and credential binding
   (AP-SPEC-053 Epic 2). The deployment doctor MUST test effective
   permissions — can the application process read the secret, the admin
   socket, or gateway memory — not the presence of a configuration file.
   Review §C's assumption table is the checklist; each row needs a test.
3. Claim semantics (AP-SPEC-053 Epic 3) decided by the abstraction case:
   SDK `confirmed` is adapter acceptance, not lifecycle `Committed`. The
   gateway records `response-recorded`, `unknown`, or `observed` and never
   `confirmed`. The multi-host claim reuses `PostgresLifecycleStore`
   (`product/stores/auths-stores/src/lifecycle.rs:714`) after measuring its
   singleton-row lock under competing instances; if the measurement fails
   the target, that is a finding for AP-SPEC-038 Epic 2, not a new store.
4. The hostile-application suite: a test application that holds no
   provider credential attempts every path in review §C (direct provider
   call, forged action, replayed proof, new challenge on the same logical
   operation, competing instance, crash after claim, restart) and produces
   zero provider entries. Live Airtable and Todoist writes go through the
   gateway with independent read-back (AP-SPEC-053 Epic 4 steps 1–2).

**Acceptance:** on one documented isolated deployment the application
cannot use the bound credential except through an authorized exact recipe;
the hostile suite reports zero unauthorized provider entries across restart
and competing instances; the ledger states what the gateway, not the SDK,
now guarantees and under which deployment assumptions. This is review
result 1.

### Epic 3 — Signing on auths-proof under any principal method

Closes review §H (product 1) and the fact that the only working signing
path today runs on the KERI-coupled sibling project, not on this one.

1. Write AP-SPEC-058: git commit and tag signing that emits an Auths proof
   over the object digest under any registered principal method
   (`core/spec/v1/registry.md`): `did:key` for local agents,
   `sigstore-keyless` and `oidc-workload` for CI, `webauthn` or
   `hsm-attested` for a human root, `did:keri` available and never
   default. Delegation grants with scope, expiry, and revocation through
   the principal-status registry, not through any one method's ledger.
2. Implement the signer and a verifier action that checks through a pinned
   trust context. Port the delegation commands from the sibling project
   (`id agent`, scopes, one-line revoke) without its identity model.
3. Demonstrate one proof format from three principal methods verified by
   one action, and state precisely which segment lacks convenient OIDC
   issuance (local and offline agents) instead of the broad claim the
   review corrected.

**Acceptance:** twenty external repositories verify agent-signed commits
through the pinned root; at least one organization enforces verification
in branch protection; the same verifier accepts proofs chained to a
Sigstore keyless identity and to a `did:key`, with no code path that
depends on KERI.

### Epic 4 — Publish the evidence the review asked for

Closes review §E, §F, §G, result 2, and the GTM overstatements. Mostly not
code.

1. Vendor corpus by hand: GitHub `issues/create` plus two more real vendor
   documents, each run through AP-SPEC-056 §§3.1–3.3 without a mapper,
   with the unmodified rejection list and the override set that makes the
   operation derive. Publish under `bindings/fixtures/openapi-corpus/`.
   This is the measured rejection wall and it precedes any 056
   implementation.
2. Run the AP-SPEC-054 Epic 5 trial with a participant unfamiliar with
   this implementation and publish the redacted report the spec requires
   (`docs/specs/0054-self-hosted-adapter-developer-experience.md:475`). If
   an agent substitutes for a human, say so in the report's first line.
3. Land the wording corrections in §6 of this spec.
4. Rewrite the GTM document's "why the incumbent cannot copy quickly" rows
   as "what remains distinctive", using review §H's estimates, and change
   its verb from "unseat" to "become the format they emit and accept".

**Acceptance:** the corpus and trial report exist on the reviewed revision;
every phrase in §6 is corrected at its cited location; the GTM document
cites review §H for each incumbent estimate. This is review result 2.

### Epic 5 — Bounded policy in the verification path

Closes the gap the review notes in §B and §C: `verify_command`
(`bindings/python/python/auths/self_hosted.py:423`,
`bindings/typescript/src/self-hosted.ts:373`) and the gateway consult no
policy; per-principal bounds do not exist.

1. Grants carry an AP-SPEC-025 policy commitment; the gateway evaluates it
   beside the proof, before claim. Only the 0025 tranches this requires
   (§21 items 4–6 as needed); the 0025 status line stays honest about the
   rest.
2. Two principals share one contract with different bounds; the bounds are
   enforced by the verifier and are offline-verifiable from the proof and
   grant alone — the property review §H says incumbents can add as a UI
   feature but not as a portable artifact.
3. The Stripe pilot from the GTM document runs with more than one agent
   principal.

**Acceptance:** the hostile suite from Epic 2 gains per-principal cases
(agent A signs inside A's bound, outside A's bound, inside B's bound) and
reports zero unauthorized provider entries; 0025's status line names the
implemented tranches.

## 5. Non-epics

The following are explicitly not epics of this program, with the reason
recorded so they are not re-proposed:

| Proposed work | Why it is not an epic here |
| --- | --- |
| Implementing AP-SPEC-056 derivation | It needs AP-SPEC-053's recipe AST (Epic 2 step 1) and the measured rejection wall (Epic 4 step 1). Implementing before both would encode guesses. It reduces authoring effort; it does not create the enforcement boundary. |
| AP-SPEC-024 work | Status `Implemented`. The 2026-09 amendment touched Non-goals and Deferred work only; nothing in code or inventories referenced the old wording. |
| A multi-host attempt-store spec | AP-SPEC-038 Epic 2 specifies and `PostgresLifecycleStore` implements the multi-host durable store. The remaining decision is reuse (Epic 2 step 3), and a measured limit of the singleton lock is a finding for 038, not a new spec. |
| A universal MCP or HTTP gateway, an agent identity platform, a unified API, a standalone receipt product | Refused by AP-SPEC-024 §4, AP-SPEC-053 §7, and the GTM documents; unchanged. |

## 6. Claim wording corrections

Each row is a defect with an owner. Epic 4 step 3 lands them; no epic may
be marked complete while its row is open.

| Current phrase | Corrected phrase | Location |
| --- | --- | --- |
| "formally translated verifier" | "a verifier whose authority, attenuation, lifecycle, and bounded-policy predicates are translated to Lean and refined under stated assumptions; decoding, cryptography, and storage are outside that surface" | GTM primitive table; `formal/README.md:29` stale scope summary; claim ledger |
| "the stack governs writes only" / "agents cannot take unauthorized actions" | "the self-hosted and gateway paths govern writes; the records API governs exact reads; an agent with an independent read credential is not constrained by a write gate" | GTM product 4; AP-SPEC-053 §1 |
| "agents have no OIDC identity" | "CI agents obtain workload identity through OIDC today; local and offline agents do not; Auths treats Sigstore keyless and OIDC workload identity as principal methods" | GTM product 1 |
| "why the incumbent cannot copy quickly" | "what remains distinctive after the incumbent's cheapest response", with review §H's estimate per row | GTM §2, every product |
| `prove`, `complete independent … trial` in commit titles | evidence in the diff, or a title that describes the diff | `dc2ad2b`, `9b31882`; rule in §2 |
| "non-bypassable" anywhere before Epic 2 acceptance | "enforced ordering within a voluntarily called SDK" | quickstart, READMEs, ledger |

## 7. Verification and release boundary

Hosted CI on the exact revision is the gate for every epic; this
specification does not run checks or assert their outcome. An epic is
complete only when its acceptance holds on one reviewed revision, its
ledger sentence is updated, and its §6 rows are closed. No merge while any
required check is red or while the two repositories disagree on the SDK
revision (AP-SPEC-052 §5).

The program is complete when the review's three results exist on one
revision. At that point the review SHOULD be re-run by an independent
reader with the same brief, and the delta in its three scores — not this
spec's own assessment — is the measure of whether the program worked.
