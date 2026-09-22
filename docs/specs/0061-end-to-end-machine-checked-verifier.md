# AP-SPEC-061: End-to-end machine-checked verifier

- **Status:** Draft; written on owner direction before its epic starts
  (board §4, 2026-09-22). Nothing in this document is implemented. This is a
  multi-month program with a public claim sentence at each phase gate, not
  one deliverable.
- **Depends on:** [AP-SPEC-011](0011-rich-authority-refinement-and-bounded-authorization.md)
  Milestones 0–2 (implemented: the rich authority model and the Aeneas route
  for pure authority predicates), [ADR 0011](../adr/0011-rich-authority-rust-lean-link.md),
  the qualification in `formal/qualification/aeneas/qualification.toml`
- **Constrains:** [AP-SPEC-060](0060-evidence-conditioned-authority.md). Its
  predicates must be extractable from their first commit (060 §7).
- **Followed by:** the reference-monitor theorem (board §3), which needs this
  spec's end-to-end statement as its verifier premise
- **Scope:** extend the machine-checked surface from the authority algebra and
  rich authority predicates to the whole path
  `verify_v1(proof_cbor, action_cbor, context_cbor) → result_cbor`: canonical
  decoding, domain-separated hashing, signature verification, staged control
  flow, and the self-certifying principal methods
- **Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** specify
  implementation requirements

## 1. Decision and claim

AP-SPEC-011 §13 lets Auths say that Lean proves the rich authority semantics
and that the isolated pure Rust authority kernel refines them. It forbids
saying that Lean proves "the entire verifier, codecs, cryptography, store
engine, external evidence, credentials, or provider behavior." `formal/README.md`
excludes "codecs, cryptography, adapters, clocks, networking, storage, and
complete verifier control flow."

The attack surface sits in those excluded parts. A proof about authority is
only as good as the decoder that turned bytes into the values it is about, and
the signature check that tied those values to a key. This spec moves the
decoder, the hashing and signature boundary, and the control flow inside the
proof, in that order. Each phase has its own permitted claim sentence (§5).

**Target theorem** (informal; the Lean statement is fixed in phase 0):

> For all byte strings `p`, `a`, `c` within the declared limits:
> `verify_v1(p, a, c)` terminates within the declared work bound without
> panicking. If it returns `Authorized(r)`, then there exist unique decoded
> values `P`, `A`, `C` with `encode(P) = p`, `encode(A) = a`, `encode(C) = c`,
> such that every signature in `P` satisfies the signature suite's
> **specification** on the exact domain-separated preimage bytes, and
> `RichAuthorized(P, A, C)` holds in the AP-SPEC-011 model, and `r` reports
> exactly those values.

**Trusted computing base after completion.** The Lean kernel and pinned
toolchain; the Rust compiler; the Charon/Aeneas translation and its pinned
external models; the cryptographic specifications (RFC 8032 Ed25519, FIPS
186-5 ECDSA over P-256, FIPS 180-4 SHA-256) as stated in Lean; the link from
those specifications to the verified implementation (§3.2); and the
premises of adapters outside the proved set (§4).

**Never claimed.** Unforgeability (EUF-CMA) of any suite; constant-time
execution or freedom from side channels; correctness of adapters outside
§4's set; correctness of trusted-context provisioning, clocks, or status
freshness; store, provider, or credential behavior.

## 2. Current state (not checked beyond what is cited)

| Component | Lines | Today |
| --- | ---: | --- |
| Authority algebra (`auths-algebra-kernel`) | generated | Lean-proved, generated into Rust, Kani-checked |
| Rich authority predicates (`auths_authority`, `auths_model` carriers, `auths_bounded_policy`) | — | Charon/Aeneas-translated (qualification rows at `qualification.toml:189–299`) |
| Canonical codec (`core/crates/auths-codec`) | 4,097 | Tested and fuzzed; tokenizes with `minicbor::Decoder` (`decode.rs:36`) |
| Signature suites (`auths-signature-core`) | 342 | Tested; calls `ed25519-dalek` and `p256` (`lib.rs:7–8`) |
| Verifier control flow (`auths-verifier/src/lib.rs`) | 3,752 | Tested; registries are passed as `&dyn` trait objects |

## 3. Technical approach

### 3.1 Codec

`minicbor` is outside any proof, and it sits on the attacker-facing boundary.
The kernel's decode path MUST move to an in-repo, extractable tokenizer
restricted to the canonical CBOR subset the protocol accepts. That means
definite lengths only, shortest-form integers, and sorted, duplicate-free map
keys, as `domain-separation.md` and the CDDL require. The encoder follows.
Theorems:

1. **Totality and bounds:** decode terminates on every input and reads at
   most the input length. Depth and collection counts stay within
   `VerifierLimits`.
2. **Canonical uniqueness:** `decode(b) = some v → encode(v) = b`. At most
   one byte string is accepted per value, which rules out malleability.
3. **Round trip:** `decode(encode(v)) = some v` for every well-formed `v`.

The swap is a source cutover under the prelaunch rule. The existing
`core/fixtures/v1` corpus and fuzz targets are the oracle. Any changed byte
decision is a wire bug in one side and is resolved before merge, not
accepted.

### 3.2 Hashing and signatures

Proving elliptic-curve implementations in Lean from scratch is out of scope.
The spec uses an implementation already verified for functional correctness
against the standard, and states the link as a named, reviewed axiom:

```text
axiom ed25519_impl_meets_spec :
  ∀ pk msg sig, impl_verify pk msg sig = true ↔ Ed25519.Spec.verify pk msg sig
```

The same holds for P-256 ECDSA with low-S and for SHA-256. Candidate:
`libcrux`, whose HACL*-derived Ed25519, P-256, and SHA-2 carry functional
correctness proofs in F*. **Not checked:**

- its `no_std` fit and API against `auths-signature-core`;
- whether its P-256 exposes the low-S rule the registry requires;
- licensing;
- whether its proofs cover the exact code paths used.

Phase 2 starts by answering these. If no verified implementation fits, the
suites stay behind a specification axiom over `ed25519-dalek` and `p256`.
The claim sentence for that phase says "specification-axiomatized", not
"verified crypto". It is a smaller claim, not a skipped phase.

Replacing `ed25519-dalek` or `p256` is a dependency change under AGENTS.md:
workspace dependency, `deny.toml`, `architecture.toml` forbidden-list
review, and differential tests against the current implementation on the
full corpus.

### 3.3 Control flow

The verifier's stages become extractable. Aeneas's support for trait objects
is limited (**not checked** for the current Charon pin). The proved entry
point therefore uses a **closed enum** of the proved registry set rather than
`&dyn`, and the `&dyn` path becomes a thin shell that is tested equal to it on
the corpus. Loops are bounded by `VerifierLimits` and carry explicit
decreasing measures. Work accounting is part of the model, so "within the
declared work bound" is a theorem, not a test.

## 4. Proved adapter set

| In | Out (stay tested trust boundaries, listed in the manifest) |
| --- | --- |
| `raw-key-v1`, `did-key-v1` (self-certifying: key in identifier), `auths-principal-status-v1`, `auths-grant-status-v1`, `uri-namespace-v1`, `exact-v1`, `numeric-ceiling-v1`, `exact-marker-v1`, and 060's observation stage when it lands | `did-keri-v1`, `did-web-bundled-v1`, `spiffe-x509-v1`, `webauthn-v1`, `hsm-attested-v1`, `oidc-workload-v1`, `sigstore-keyless-v1` |

A verifier configuration that enables an out-of-set method still verifies.
The result's configuration commitment shows the method was used, so a relying
party can tell a fully proved decision from one that crossed a tested
boundary. The result MUST carry a boolean `proved_configuration`, set when
every executed handler is in the proved set.

## 5. Phases, gates, and permitted claims

| Phase | Work | Size | Claim permitted after its gate is green |
| --- | --- | --- | --- |
| 0 | Fix the Lean statement of the target theorem, the codec model, and the axiom list. Add them to `assurance-manifest-v1.toml` as open claims. | 2 wk | None; the statement is public |
| 1 | Extractable canonical codec with §3.1's three theorems; cutover; corpus and fuzz parity | 6–10 wk | "Canonical decoding is machine-checked to be total, bounded, and unique." |
| 2 | Hashing and signature link (§3.2), domain-separated preimage construction proved | 4–8 wk | "Signature checks are proved against the RFC/FIPS specifications, assuming [named verified implementation or specification axiom]." |
| 3 | Control flow and the §4 adapter set; closed-enum entry point; work bound | 8–12 wk | "For the proved configuration, `verify_v1` is machine-checked end to end against the rich authority model, assuming the published trusted computing base." |
| 4 | 060 predicates (if landed) join; `proved_configuration` in results and all bindings | 2 wk | Same, with observation requirements included |

The total is about 5–8 months for one engineer. Each phase gate is:
`cargo xtask formal` green in hosted CI on the exact revision; the new claims
in the assurance manifest with their transitive axiom sets; no `sorry`;
generated artifacts reproduced twice byte for byte; and AP-SPEC-011 §13's
claim table updated in the same PR.

## 6. Relationship to other work

- **AP-SPEC-060** MUST write its condition evaluator and freshness check as
  pure, bounded, extractable predicates. If 060 lands first, phase 4 absorbs
  it. If 061 phase 3 lands first, 060's gate includes extension of the
  theorem.
- **AP-SPEC-058** adds no kernel code. Its Git payload parser is product code
  and is outside this theorem. The theorem covers the proof it verifies
  when the signer uses `did:key`.
- **The reference-monitor theorem** composes this result with the gateway's
  ordering (claim before credential, closed request), which needs its own
  model of the gateway. It is not part of this spec.

## 7. Non-goals

- Cryptographic security proofs (EUF-CMA, collision resistance).
- Constant-time or side-channel guarantees. They stay governed by library
  choice and review.
- Proving `did:keri`, X.509, WebAuthn, HSM attestation, OIDC, or Sigstore
  adapters. Each is a separate, much larger effort.
- Proving bindings. Bindings stay thin and differential-tested against native
  (AGENTS.md).
- Proving the compiler, Lean, or Aeneas.

## 8. Readings this spec had to choose

| Sentence | Readings | Pick |
| --- | --- | --- |
| Board: "with verified crypto" | (a) prove curve arithmetic in Lean; (b) link a verified implementation by a named axiom; (c) axiomatize the spec over the current libraries | (b), with (c) as the explicit smaller-claim fallback (§3.2) |
| Board: "End-to-end" | (a) every adapter; (b) a stated proved configuration | (b), with `proved_configuration` in results (§4) |
| Board: "After 059/060" | (a) do not start until both land; (b) start phases 0–1, which touch neither | (b): the codec and statement are independent; 060 is constrained to be extractable (§6) |

## 9. Verification and release boundary

Hosted CI is the gate. This spec runs no checks. Until each phase's gate is
green, public text uses the previous phase's sentence, and before phase 1
AP-SPEC-011 §13's current sentence.
