# Liquid surface implementation roadmap

Status: all 11 implementation items complete on `dev-decouple`; merge pending

## North star

Auths should provide a secure liquid surface through which data and identity can move without acquiring unrelated semantics.

```text
bounded data
    |
    v
decoded identity
    |
    v
validated identity
    |
    +--------------------------> application-owned use
    |
    +-- explicit promotion ---> authority principal
                                      |
                                      +--> capabilities
                                      +--> review and approvals
                                      +--> enforcement and receipts
```

Every downward transition adds a precise security claim. No transition is ambient, automatic, or inferred from transport success.

## How to use this roadmap

Work in the order below. Later items assume the invariants established by earlier items.

For each item:

1. Read the linked design note completely.
2. Re-audit the referenced implementation before changing it; scratch notes are proposals, not authority.
3. Write or strengthen a failing test that demonstrates the boundary being changed.
4. Implement the smallest coherent change that meets the note's acceptance criteria.
5. Run focused tests and the repository architecture, semantic-freeze, and compliance checks relevant to the change.
6. Update the checkbox and evidence block in this README only after the item is implemented and verified in its focused commit.
7. Do not mark an item complete when compatibility work, migration, release metadata, or required tests remain. Record PR merge evidence separately when it becomes available.

Use one focused commit per numbered item. Prefer one pull request per item, but an explicitly authorized ordered implementation branch may carry all commits without collapsing their boundaries.

## Ordered checklist

### Phase 1: Make trust transitions safe

- [x] **1. Make identity validation state explicit**
  Design: [01_VALIDATED_IDENTITY_TYPES.md](01_VALIDATED_IDENTITY_TYPES.md)
  Why first: structural decoding must not be confused with identity validation while the rest of the surface is being reshaped. This closes the most immediate misuse boundary.
  Complete when: decoded, validated, and authenticated states are distinct; bare public-identity receivers validate explicitly; adversarial tests prove that malformed or forged relationships cannot be promoted.
  Evidence: commit `aceaff1`; decoded, validated, and authenticated type states plus adversarial promotion tests.

### Phase 2: Remove duplicate semantic truth

- [x] **2. Establish one canonical raw-key identity**
  Design: [02_CANONICAL_RAW_KEY_IDENTITY.md](02_CANONICAL_RAW_KEY_IDENTITY.md)
  Depends on: item 1.
  Why now: identity and authority cannot compose while the same key produces different principals. The compatibility decision must precede the bridge.
  Complete when: one descriptor and identifier derivation is normative; identity and authority paths produce the same principal; old identifiers have a fail-closed migration rule; vectors cover current and variable-length keys.
  Evidence: commit `9a72cff`; raw-key V2 is the single canonical descriptor and identifier derivation.

- [x] **3. Establish one implementation of signature semantics**
  Design: [03_SINGLE_SIGNATURE_SEMANTICS.md](03_SINGLE_SIGNATURE_SEMANTICS.md)
  Depends on: item 1.
  Why now: a suite identifier must not have separate security implementations before identity and authority are joined.
  Complete when: identity and proof adapters delegate to one Ed25519 verification implementation or an equally strong single semantic owner; cross-port conformance tests prevent drift.
  Evidence: commit `6636d8e`; identity and proof adapters share the canonical signature implementation and cross-port tests.

### Phase 3: Join identity to authority without coupling them

- [x] **4. Unify the identity and authority identity models**
  Design: [04_UNIFY_IDENTITY_MODELS.md](04_UNIFY_IDENTITY_MODELS.md)
  Depends on: items 1–3.
  Why now: the explicit bridge should be built only after validation state, identifiers, and suite semantics have one meaning.
  Complete when: a validated identity can be explicitly promoted into an authority principal without application-owned re-derivation; unvalidated identity cannot enter the authority stack; identity-only applications retain zero authority dependencies.
  Evidence: commit `7e92d9a`; explicit validated-identity promotion bridge with no reverse identity-to-authority dependency.

- [x] **5. Make identity credential-shape agnostic**
  Design: [05_CREDENTIAL_SHAPE_AGNOSTIC_IDENTITY.md](05_CREDENTIAL_SHAPE_AGNOSTIC_IDENTITY.md)
  Depends on: item 4.
  Why now: generalize the unified model before treating its public API and wire shape as stable. Avoid building the bridge around a permanent one-key/one-suite assumption.
  Complete when: the model honestly supports simple raw keys plus bounded composite, rotating, or resolver-shaped verification relationships; the raw-key path remains concise; no capability or approval concepts enter identity.
  Evidence: commit `406c659`; bounded descriptor and relationship model covers raw, rotating, composite, and resolver-shaped identities.

### Phase 4: Make data movement replaceable

- [x] **6. Define an opaque bounded-byte transport port**
  Design: [06_OPAQUE_BYTE_TRANSPORT_PORT.md](06_OPAQUE_BYTE_TRANSPORT_PORT.md)
  Depends on: item 1; should follow item 5 so transport tests use the intended identity surface.
  Why now: the protocol shape is stable enough to prove transport substitution without mixing transport decisions into identity design.
  Complete when: the same identity exchange runs over two byte-channel implementations; protocol orchestration contains no Iroh types; transport peer facts do not automatically become Auths identities.
  Evidence: commit `712c49c`; neutral byte-channel port with memory and Iroh adapters and enforced dependency boundaries.

### Phase 5: Remove authority-product coupling

- [x] **7. Decouple human-readable review from approval**
  Design: [07_DECOUPLE_REVIEW_FROM_APPROVAL.md](07_DECOUPLE_REVIEW_FROM_APPROVAL.md)
  Depends on: no code dependency on items 1–6, but follows them to keep the critical identity sequence uninterrupted.
  Why now: profiles should expose deterministic meaning, while approval remains an optional consumer.
  Complete when: generic profiles expose neutral review data; approval providers consume it through their own layer; automated profiles need no approval vocabulary or provider dependency.
  Evidence: commit `a8a6348`; neutral deterministic review data is produced independently and consumed by optional approval providers.

- [x] **8. Split the generic kernel from profile-specific runtimes**
  Design: [08_SPLIT_KERNEL_FROM_PROFILE_RUNTIMES.md](08_SPLIT_KERNEL_FROM_PROFILE_RUNTIMES.md)
  Depends on: item 7, so the extracted generic runtime uses neutral review concepts.
  Why now: public SDK layers cannot be made honest while the generic kernel package imports MCP-specific runtime semantics.
  Complete when: the generic kernel has no MCP dependency; MCP behavior lives in an inward-dependent runtime; minimal verification does not compile exchange, receipts, or profile implementations unnecessarily.
  Evidence: commit `d30cb19`; profile-free `auths-kernel-runtime` extracted and protected from MCP/profile dependencies.

### Phase 6: Expose the layers as products

- [x] **9. Expose layered public SDK surfaces**
  Design: [09_LAYERED_PUBLIC_SDK_SURFACES.md](09_LAYERED_PUBLIC_SDK_SURFACES.md)
  Depends on: items 4–8.
  Why now: public entry points should be drawn around proven internal boundaries, not used to guess those boundaries in advance.
  Complete when: users can adopt transport, identity, authentication, authority, approval, and enforcement incrementally; concrete adapters are opt-in; Rust and language bindings present matching layers.
  Evidence: commit `b6988ba`; layered Rust and TypeScript identity, authority, approval, and profile entry points with API snapshots.

- [x] **10. Freeze and version identity protocol semantics**
  Design: [10_FREEZE_IDENTITY_PROTOCOL_SEMANTICS.md](10_FREEZE_IDENTITY_PROTOCOL_SEMANTICS.md)
  Depends on: items 1–6 and the public-surface decision in item 9.
  Cross-cutting rule: every earlier semantic change must still update its required semantic identities and vectors. This item is the final consolidation that makes the new identity surface a protected release contract.
  Complete when: version dimensions are explicit; compliance names are accurate; wire bytes, signing preimages, identifier vectors, decoder rejections, and public APIs are protected by release checks.
  Evidence: commit `d67d716`; compatibility specification, canonical vectors and rejection corpus, identity ABI, and semantic freeze.

- [x] **11. Publish the modular components**
  Design: [11_PUBLISH_MODULAR_COMPONENTS.md](11_PUBLISH_MODULAR_COMPONENTS.md)
  Depends on: all previous items.
  Why last: publication turns internal experiments into compatibility promises. Ports should be published only after their trust states, semantics, boundaries, public entry points, and release protections are settled.
  Complete when: external smoke projects install packed or registry artifacts; identity and transport can be adopted independently; reference adapters remain optional; release qualification covers the published packages.
  Evidence: this focused commit; seven public modular roots, package security READMEs, compatibility/conformance docs, and executed packed-artifact consumer smoke tests.

## Completion rules

An item may be checked only when all of the following are true:

- Its design note's acceptance criteria are satisfied or deliberately revised with rationale.
- Focused unit, integration, adversarial, and conformance tests pass.
- `cargo xtask arch` passes and the intended dependency boundary is encoded in `architecture.toml`.
- Semantic changes have new semantic identities or versions and `cargo xtask semantic-freeze` passes.
- Compliance declarations and snapshots match the implementation.
- Public API snapshots are updated intentionally where applicable.
- Documentation and examples describe the new boundary accurately.
- The item exists as a focused commit and the evidence line records that commit and its decisive checks.
- When a pull request merges, its number and hosted CI result are appended without rewriting the implementation boundary.

After merging an item, normally return to `main`, pull `origin/main`, and create a fresh focused branch. When the user explicitly authorizes an ordered multi-item branch, preserve one focused commit per item and keep the checklist dependency order.

## Zero-context agent prompt

Copy the prompt below into a fresh coding-agent task. It is intentionally self-contained.

```text
Work through the Auths liquid-surface roadmap in this repository:

/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof

The roadmap and status tracker are here:

/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof/docs/scratch/README.md

Objective:
Create a secure liquid surface where bounded data and identity can flow through neutral ports, and where validation, authentication, authority, capabilities, review, approvals, and enforcement are added only through explicit transitions. Lower layers must never acquire dependencies on higher layers.

Operating procedure:

1. Inspect git status and preserve all user-owned or unrelated changes. Never stage or modify the untracked scripts/ directory unless the user explicitly asks.
2. Read docs/scratch/README.md completely.
3. Find the first unchecked roadmap item whose dependencies are complete.
4. Read that item's linked design note completely.
5. Audit the current implementation and recent relevant commits before planning. Treat the scratch document as a proposed design; correct it if repository evidence disproves an assumption, and record the rationale.
6. Work on exactly one numbered roadmap item at a time. Do not begin a later item in the same pull request unless the current item cannot be made coherent without it and the roadmap is updated to explain why.
7. Before implementation, identify:
   - the security invariant being established;
   - the packages that should own it;
   - forbidden dependency directions;
   - compatibility and semantic-version consequences;
   - the tests that will prove the boundary.
8. Add or strengthen a failing test for the problem, then implement the smallest complete solution.
9. Preserve these non-negotiable properties:
   - decoding data does not establish trust;
   - transport authentication is not automatically an Auths identity;
   - authenticated identity is not automatically authority;
   - authority is not automatically approval;
   - approval is not automatically execution;
   - identity-only and data-only consumers do not depend on capabilities, approvals, policy, lifecycle, or product runtime;
   - Auths owns ports, canonical semantics, and conformance—not an exhaustive adapter catalog.
10. Run focused tests plus every relevant architecture, API, semantic-freeze, formal, and compliance check. Run the full compliance suite before declaring the item complete when the change affects shared semantics or release surfaces.
11. Update docs/scratch/README.md only after the item is genuinely implemented and verified:
    - change its checkbox from [ ] to [x];
    - replace the Evidence placeholder with the focused commit, decisive tests, and any migration note;
    - update dependency wording for later items if the implementation changed the plan.
12. Do not check off speculative or partially implemented work. If the branch is unmerged, report that state explicitly and add the merged PR evidence later.
13. Use unsigned commits if signing is unavailable. Push the focused branch and open or update the pull request when authorized by the user.
14. Stop after one item is implemented and handed off unless the user explicitly asks you to continue automatically. Report what changed, what remains, and the next unchecked item.

Start by reporting:

- current branch and working-tree state;
- the first eligible unchecked item;
- why it is next;
- its concrete implementation and verification plan.
```

## Final outcome

When all boxes are checked, Auths should support this progression without redesign:

```text
move bytes
  -> describe identity
  -> validate identity
  -> authenticate exact data
  -> optionally establish authority
  -> optionally request review or approval
  -> optionally execute through a bounded profile
  -> optionally record receipts and lifecycle state
```

The system is liquid because each layer composes. It remains secure because every added meaning is explicit, typed, bounded, and independently testable.
