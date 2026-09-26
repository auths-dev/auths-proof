# AP-SPEC-061: End-to-end machine-checked verifier

- **Status:** Draft. It was written on owner direction before its epic starts
  (board §4, 2026-09-22), and nothing in it is implemented.
  - A feasibility spike on 2026-09-26 checked the translation route and the
    crypto candidate against `main` at `8b96f2ca` (§10). Its findings are folded
    into §2–§5 and §8.
  - This is a multi-month program with a public claim sentence at each phase
    gate, not one deliverable.
- **Depends on:**
  - [AP-SPEC-011](0011-rich-authority-refinement-and-bounded-authorization.md)
    Milestones 0–2, which are implemented: the rich authority model and the
    Aeneas route for pure authority predicates;
  - [ADR 0011](../adr/0011-rich-authority-rust-lean-link.md);
  - the qualification in `formal/qualification/aeneas/qualification.toml`.
- **Evidence:**
  - [Aeneas translation feasibility](../research/formal/0001-aeneas-translation-feasibility.md);
  - [libcrux as the verified signature and hash implementation](../research/formal/0002-libcrux-verified-crypto-fit.md).
- **Absorbs:** [AP-SPEC-060](0060-evidence-conditioned-authority.md). It has
  landed, and its predicates are already translated (§6).
- **Followed by:** the reference-monitor theorem (board §3), which needs this
  spec's end-to-end statement as its verifier premise.
- **Scope:** extend the machine-checked surface from the authority algebra and
  rich authority predicates to the whole path
  `verify_v1(proof_cbor, action_cbor, context_cbor) → result_cbor`. That
  covers:
  - canonical decoding;
  - domain-separated hashing;
  - signature verification;
  - staged control flow;
  - the self-certifying principal methods.
- **Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** specify
  implementation requirements.

## 1. Decision and claim

AP-SPEC-011 §13 lets Auths say two things: Lean proves the rich authority
semantics, and the isolated pure Rust authority kernel refines them. It forbids
saying that Lean proves "the entire verifier, codecs, cryptography, store
engine, external evidence, credentials, or provider behavior."
`formal/README.md` excludes "codecs, cryptography, adapters, clocks,
networking, storage, and complete verifier control flow."

The attack surface sits in those excluded parts. A proof about authority is
only as good as two things underneath it: the decoder that turned bytes into
the values it is about, and the signature check that tied those values to a
key. This spec moves three things inside the proof, in this order:
1. the decoder;
2. the hashing and signature boundary;
3. the control flow.

Each phase has its own permitted claim sentence (§5).

**Target theorem** (informal; the Lean statement is fixed in phase 0):

> For all byte strings `p`, `a`, `c` within the declared limits:
> `verify_v1(p, a, c)` terminates within the declared work bound without
> panicking. If it returns `Authorized(r)`, then there exist unique decoded
> values `P`, `A`, `C` with `encode(P) = p`, `encode(A) = a`, `encode(C) = c`,
> such that every signature in `P` satisfies the signature suite's
> **specification** on the exact domain-separated preimage bytes, and
> `RichAuthorized(P, A, C)` holds in the AP-SPEC-011 model, and `r` reports
> exactly those values.

**Trusted computing base after completion:**
- the Lean kernel and pinned toolchain;
- the Rust compiler;
- the Charon/Aeneas translation and its pinned external models;
- the cryptographic specifications as stated in Lean: RFC 8032 Ed25519,
  FIPS 186-5 ECDSA over P-256, and FIPS 180-4 SHA-256;
- the link from those specifications to executable code (§3.2):
  - under the linked-implementation reading, HACL*'s F* proofs, the
    unverified translation of that code to Rust, and libcrux's edits to it;
  - under the fallback, a specification axiom over the current libraries;
- the premises of adapters outside the proved set (§4).

**Never claimed:**
- unforgeability (EUF-CMA) of any suite;
- constant-time execution or freedom from side channels;
- correctness of adapters outside §4's set;
- correctness of trusted-context provisioning, clocks, or status freshness;
- store, provider, or credential behavior.

## 2. Current state

| Component | Lines | Today |
| --- | ---: | --- |
| Authority algebra (`auths-algebra-kernel`) | generated | Lean-proved, generated into Rust, Kani-checked |
| Rich authority predicates, and AP-SPEC-060's 11 observation predicates (`auths_authority`, `auths_model`, `auths_bounded_policy`) | — | Charon/Aeneas-translated; rows in `qualification.toml` |
| Canonical codec (`core/crates/auths-codec`) | 5,007 | Tested and fuzzed; tokenizes with `minicbor`. Charon extracts it, but Aeneas does not translate it (§3.1). |
| Signature suites (`auths-signature-core`) | 162 | Tested; calls `ed25519-dalek` and `p256`. Ed25519 key validation accepts some encodings that RFC 8032 decoding rejects (§3.2). |
| Verifier control flow (`auths-verifier/src/lib.rs`, `verify_v1` at line 910) | 3,964 | Tested; registries are passed as `&dyn` trait objects. Charon extracts the full `verify_v1` closure, but Aeneas produces no Lean for it (§3.3). |

## 3. Technical approach

### 3.1 Codec

`minicbor` is outside any proof, and it sits on the attacker-facing boundary.
The kernel's decode path MUST move to an in-repo, extractable tokenizer. It
accepts only the canonical CBOR subset the protocol allows, as
`domain-separation.md` and the CDDL require:
- definite lengths only;
- shortest-form integers;
- sorted, duplicate-free map keys.

The encoder follows. The new tokenizer and encoder MUST follow the extraction
rules in §3.4. The theorems are:

1. **Totality and bounds:** decode terminates on every input and reads at
   most the input length. Depth and collection counts stay within
   `VerifierLimits`.
2. **Canonical uniqueness:** `decode(b) = some v → encode(v) = b`. At most
   one byte string is accepted per value, which rules out malleability.
3. **Round trip:** `decode(encode(v)) = some v` for every well-formed `v`.

The spike (research 0001) confirmed that this style works:
- A head decoder over `&[u8]` with an explicit index, returning `Result` and
  using one loop per helper, passes Charon and Aeneas under the strict flags.
  It builds in Lean with no external axioms.
- Aeneas represents each loop as a partial fixpoint without fuel. Theorem 1's
  termination is therefore proved in Lean, with a well-founded measure over
  the unread input.
- The codec already rejects input whose re-encoding differs. Once the encoder
  is extracted as well, that check yields theorem 2.

The current codec has 27 loop-shape errors in 24 functions and 26
function-value errors, not counting `minicbor`. Fixing them is a mechanical
restyle.

The swap is a source cutover under the prelaunch rule. The existing
`core/fixtures/v1` corpus and the fuzz targets are the oracle. Any changed
byte decision is a wire bug in one side, and is resolved before merge, not
accepted.

### 3.2 Hashing and signatures

Proving elliptic-curve implementations in Lean from scratch is out of scope.
The link from the Lean specifications to executable code is one of two
readings. The owner decides between them when phase 2 starts (§8).

- **(b) Linked verified implementation.**
  - **What:** `libcrux-ed25519`, `libcrux-ecdsa` (P-256) and `libcrux-sha2`,
    `=`-pinned with `default-features = false`.
  - **What is proved:** their verify and hash cores are HACL* code, proved in
    F* against `Spec.Ed25519`, `Spec.ECDSA` and `Spec.Agile.Hash`. The Rust is
    an unverified translation of that code (KaRaMeL's Rust backend), which
    libcrux has edited by hand.
  - **Fit (research 0002):**
    - it fits `no_std`, WASM, MSRV 1.91 and `auths-proof-wasm`;
    - it is Apache-2.0;
    - it gave 0 corpus disagreements with the glue below.
  - **Blocker:** `cargo deny` fails on RUSTSEC-2026-0173 through `hax-lib`. So
    (b) requires either an owner-reviewed advisory exception or an upstream
    release without that dependency.
- **(c) Specification axiom** over `ed25519-dalek`, `p256` and `sha2`, with the
  smaller claim sentence. It is a smaller claim, not a skipped phase.

Under either reading, the link is a named, reviewed axiom per primitive:

```text
axiom ed25519_impl_meets_spec :
  ∀ pk msg sig, impl_verify pk msg sig = true ↔ Ed25519.Spec.verify pk msg sig
```

There is one of these for Ed25519, one for P-256 ECDSA, and one for SHA-256.
The P-256 axiom states ECDSA as specified, which allows any s ∈ [1, n−1]; the
low-S rule is part of the glue.

**Suite glue.** The axioms cover only the primitive. The glue around them MUST
be extracted and proved under either reading:

1. **Ed25519 key.**
   - Exactly 32 bytes.
   - A canonical encoding: y < p, and not x = 0 with the sign bit set
     (RFC 8032 §5.1.3).
   - Not one of the 8 canonical small-order encodings.

   **Ed25519 signature.**
   - Exactly 64 bytes.
   - R is not a small-order encoding.

   S < L and the cofactorless verification equation sit inside the axiom.
2. **P-256 key.**
   - Exactly 33 bytes, with prefix `0x02` or `0x03`.
   - Decoded by the verified `compressed_to_coordinates` under (b), or after
     the prefix check under (c).
   - The decoded point MUST validate.

   **P-256 signature.**
   - Exactly 64 bytes, `r ‖ s`.
   - s ≤ ⌊n/2⌋, checked with one big-endian comparison before the primitive
     runs.
3. **SHA-256.** One-shot calls only. No streaming API on the proved path.
4. **Under (b):** the glue passes only fixed-size arrays produced by verified
   decoders into `validate_point` and `verify`. It never calls libcrux-ecdsa's
   `PublicKey::try_from`, whose defects research 0002 lists.

Rule 1's canonical-encoding check tightens today's `validate_ed25519_key`. For
a non-canonical key, the result class changes from a verification failure to
`InvalidKey`. That change MUST land in phase 2 with corpus vectors, and with
the Go and TypeScript verifiers agreeing. Rule 2 is the registry's key rule.
The Go and TypeScript verifiers enforce it, and Rust enforces it after the
P-256 key-encoding change (§10). Under (c), the axioms
are true only once these rules hold, because RFC 8032 decoding and the
registry reject inputs that the current libraries accept.

Replacing `ed25519-dalek` or `p256` is a dependency change under AGENTS.md. It
requires:
- a workspace dependency;
- a `deny.toml` review, including the advisory exception;
- an `architecture.toml` forbidden-list review;
- a lockfile review (research 0002 lists additions that are never compiled);
- differential tests against the current implementation, which stays as a
  test oracle.

Research 0002's corpus run reached only 4 P-256 tuples, so phase 2 MUST add
P-256 corpus vectors before its gate.

### 3.3 Control flow

The verifier's stages become extractable. Research 0001 found `dyn` to be one
of nine classes of construct that the pinned Aeneas rejects or crashes on. The
proved entry point therefore uses a **closed enum** of the proved registry set
rather than `&dyn`. The `&dyn` path becomes a thin shell, tested equal to the
enum path on the corpus.

The staged verifier MUST be restructured under §3.4 and extracted as
**per-stage slices** with explicit `--opaque` boundaries, as `fn reproduce`
already does for the authority kernel. Each slice is gated with
`--error-on-warnings` and `-warnings-as-errors` from its first commit. The
reason: Aeneas fails all-or-nothing, and each blocker hides the next (the spike
went through six layers).

- **Loops** are bounded by `VerifierLimits` and carry decreasing measures,
  which are proved in Lean.
- **Work accounting** is an explicit counter in the Rust code. "Within the
  declared work bound" is a theorem about that counter, because the
  translation cannot supply fuel.
- **The P-256 primitive** stays opaque (Charon overflows its stack on it) and
  is covered by §3.2's axiom.

### 3.4 Extraction rules

Code on the proved path MUST:

1. use index-based loops over slices, with no `Iterator` adapters or closures
   over iterators;
2. place each loop in its own helper function. A loop that contains an early
   exit (`?`, `return`, or `break`) MUST be its helper's first construct. No
   loop may sit inside an `if`, and no `break` or `continue` may target an
   outer loop;
3. dispatch through closed enums or generics, never `dyn` or function
   pointers, and pass explicit closures instead of function items or
   constructors;
4. compare identifiers as bytes, with no `char` or `str` pattern operations;
5. use sorted `Vec` instead of `BTreeSet` and `BTreeMap`, and give each
   remaining std function a reviewed Lean model, in the style of
   `generated/model/FunsExternal.lean`;
6. have no mutually recursive derived impls; recursive types compare through
   free functions.

Each rule matches a construct class that Aeneas `3a8586fa` rejected or crashed
on in research 0001. The strict translation gate enforces the rules, not
review. A toolchain update that lifts a rule is recorded in the qualification
together with its evidence.

## 4. Proved adapter set

| In | Out (stay tested trust boundaries, listed in the manifest) |
| --- | --- |
| `raw-key-v1`, `did-key-v1` (self-certifying: key in identifier), `auths-principal-status-v1`, `auths-grant-status-v1`, `uri-namespace-v1`, `exact-v1`, `numeric-ceiling-v1`, `exact-marker-v1`, and AP-SPEC-060's observation stage | `did-keri-v1`, `did-web-bundled-v1`, `spiffe-x509-v1`, `webauthn-v1`, `hsm-attested-v1`, `oidc-workload-v1`, `sigstore-keyless-v1` |

A verifier configuration that enables an out-of-set method still verifies.
The result's configuration commitment shows which methods were used. A
relying party can therefore tell a fully proved decision from one that crossed
a tested boundary. The result MUST carry a boolean `proved_configuration`, set
when every executed handler is in the proved set.

## 5. Phases, gates, and permitted claims

Sizes are at agent speed, from research 0001 and 0002.

| Phase | Work | Size | Claim permitted after its gate is green |
| --- | --- | --- | --- |
| 0 | Fix the Lean statement of the target theorem, the codec model, and the axiom list. Add them to `assurance-manifest-v1.toml` as open claims. | 2–3 days | None; the statement is public |
| 1 | Extractable canonical codec under §3.4, with §3.1's three theorems; cutover; corpus and fuzz parity | 2–3 weeks | "Canonical decoding is machine-checked to be total, bounded, and unique." |
| 2 | Decide §3.2's reading; extract and prove the suite glue; tighten Ed25519 key validation with vectors; add P-256 corpus vectors; prove domain-separated preimage construction | 1–2 weeks | (b): "Signature checks are proved against the RFC 8032, FIPS 186-5 and FIPS 180-4 specifications, assuming the pinned libcrux Ed25519, P-256 ECDSA and SHA-256 code meets them; that code is verified in F* (HACL*) and translated to Rust by an unverified compiler." (c): "Signature checks are proved against the RFC 8032, FIPS 186-5 and FIPS 180-4 specifications, assuming a specification axiom that `ed25519-dalek`, `p256` and `sha2` implement them; those libraries are tested, not verified." |
| 3 | §3.4 refactor of the staged verifier and the §4 adapter set, as gated per-stage slices; closed-enum entry point; work counter and bound | 4–7 weeks | "For the proved configuration, `verify_v1` is machine-checked end to end against the rich authority model, assuming the published trusted computing base." |
| 4 | AP-SPEC-060's translated observation predicates join the end-to-end statement; `proved_configuration` in results and all bindings | 2–3 days | Same, with observation requirements included |

The total is about 2–3 months, and phase 3's refinement proofs dominate it.
Phase 3's all-or-nothing translation behavior is the largest risk; per-stage
slices bound it.

Each phase gate requires all of the following:
- `cargo xtask formal` is green in hosted CI on the exact revision;
- the new claims are in the assurance manifest, with their transitive axiom
  sets;
- there is no `sorry`;
- generated artifacts are reproduced twice, byte for byte;
- AP-SPEC-011 §13's claim table is updated in the same PR;
- in phase 3, every slice passes the strict translation flags before any
  proof about it merges.

## 6. Relationship to other work

- **AP-SPEC-060** has landed. Its 11 observation predicates are translated and
  linked to the model by 14 Lean refinement theorems. Phase 4 adds them to the
  end-to-end statement. Any later 060 extension MUST keep its predicates pure,
  bounded and extractable under §3.4.
- **AP-SPEC-058** adds no kernel code. Its Git payload parser is product code
  and is outside this theorem. The theorem covers the proof it verifies when
  the signer uses `did:key`.
- **The reference-monitor theorem** composes this result with the gateway's
  ordering (claim before credential, closed request). That needs its own model
  of the gateway, so it is not part of this spec.

## 7. Non-goals

- Cryptographic security proofs (EUF-CMA, collision resistance).
- Constant-time or side-channel guarantees. These stay governed by library
  choice and review.
- Proving the `did:keri`, X.509, WebAuthn, HSM attestation, OIDC, or Sigstore
  adapters. Each is a separate, much larger effort.
- Proving bindings. Bindings stay thin and are differential-tested against
  native (AGENTS.md).
- Proving the compiler, Lean, Aeneas, or the HACL*-to-Rust translation.

## 8. Readings this spec had to choose

| Sentence | Readings | Pick |
| --- | --- | --- |
| Board: "with verified crypto" | (a) prove curve arithmetic in Lean; (b) link a verified implementation by a named axiom; (c) axiomatize the spec over the current libraries | (b) if the owner approves the RUSTSEC-2026-0173 exception when phase 2 starts; otherwise (c). PROVISIONAL default: (c), the narrower reading, with no new dependency and a smaller claim. Both need §3.2's glue. |
| Board: "End-to-end" | (a) every adapter; (b) a stated proved configuration | (b), with `proved_configuration` in results (§4) |
| Board: "After 059/060" | (a) do not start until both land; (b) start phases 0–1, which touch neither | (b). This is now moot: both have landed. |

## 9. Verification and release boundary

Hosted CI is the gate. This spec runs no checks. Until each phase's gate is
green, public text uses the previous phase's sentence. Before phase 1, it uses
AP-SPEC-011 §13's current sentence.

## 10. Feasibility spike (2026-09-26)

Two read-only investigations were run against `main` at `8b96f2ca`.

- **[0001 Aeneas translation feasibility](../research/formal/0001-aeneas-translation-feasibility.md).**
  - Charon extracts the full `verify_v1` closure (2,431 bodies), but Aeneas
    translates none of it.
  - It found nine blocker classes, with sites and fixes.
  - An extractable tokenizer passes the strict gates and builds in Lean.
  - This is the basis for §3.1, §3.3, §3.4 and §5's sizes.
- **[0002 libcrux fit](../research/formal/0002-libcrux-verified-crypto-fit.md).**
  - It fits `no_std`, WASM and MSRV.
  - It gave 0 corpus disagreements once the suite glue was applied.
  - Its Rust is an unverified translation of F*-proved code.
  - Using it needs an advisory exception.
  - This is the basis for §3.2 and §8.

The spike also found that P-256 key validation accepted SEC1 forms outside
`registry.md`'s 33-byte compressed rule, which the Go and TypeScript verifiers
already rejected. The P-256 key-encoding change corrects this.
