# Testing invariants

Rules for writing tests, harnesses, and proofs in this repository. Every rule here was learned from
a real defect found in this codebase — the examples are not hypothetical.

Applies to humans and agents equally.

---

## The one principle

**A check that cannot fail is worse than no check.**

No check is an honest gap. A check that cannot fail looks like coverage, counts as coverage, and
tells you nothing. It also survives review indefinitely, because reviewers read the *name* of a
check, not its falsifiability.

Every rule below is a way this failure mode hides.

## The one universal technique

**Mutation: break the thing under test, confirm the check goes red, restore it.**

If a check stays green while the code it guards is deliberately broken, that check is decoration.
This is the only way to know a check bites, and it applies to every test type in this document.

Do it when you write the check, not later.

```bash
# 1. write / already have the check
# 2. break the production code it guards (invert a condition, drop a branch)
# 3. run the check — it MUST go red
# 4. restore the production code
# 5. run again — it MUST go green
```

Real finding: four Kani harnesses passed for months. Mutating the code they "proved" left all four
**successful**. They were rewritten only because someone mutated first.

---

## Rules that apply to every test type

| # | Rule | The defect it prevents |
|---|---|---|
| 1 | The check must be able to fail. Prove it by mutation. | `assert_eq!(x, x)` — a real harness in this repo |
| 2 | Call production code. Never transcribe its logic into the test. | A harness re-implementing the arithmetic it proves passes forever while production drifts |
| 3 | A literal in a decision position is a bug. | `root_preserved: true`, `extensionsAttenuate := true` |
| 4 | Write the failing test **first**. The red is the finding, proven. | Fixes that were never needed; findings that were never real |
| 5 | Green on the first run is a result, not a failure. Record it. | A corrected false positive is as valuable as a confirmed bug |
| 6 | Never weaken a check to make it pass. | Every entry in this table started as someone doing exactly that |
| 7 | If behavior legitimately changed, update the check **and say so**, naming the change. | Silent assertion edits that erase the record |
| 8 | Test the **denial** path as hard as the success path. | This is an authorization system. Denials are the product. |
| 9 | A check must scan or run everything it claims to. | `binding_semantics` scanned 2 of 4 surfaces; the Kani gate ran 2 of 5 packages |
| 10 | Cited evidence must resolve to a real symbol. | Nine fixtures cited a Kani harness that does not exist |

---

## Unit tests

**Invariant: the test reaches the code under test directly, not through a caller that might be doing
the work for it.**

- Call the function you are testing. If an upstream guard would deny first, **bypass it** — otherwise
  you are testing the guard.
- Assert the specific reason, not just the outcome. `assert!(result.is_err())` passes for the wrong
  error.
- One behavior per test. A test named for one property that asserts five will be deleted by whoever
  breaks four of them.
- Name the test after the property, not the function. `denies_absent_budget_under_bounded_ceiling`
  beats `test_budget_covers`.

**Real defect:** the system denied `(bounded ceiling, absent request)` only because a verifier guard
ran at line 2227, before the algebra at line 2251. The algebra itself returned `Authorized`. Correct
behavior rested on statement order. No unit test reached the algebra directly, so nothing caught it.

**Rule:** when a guard protects a component, test the component **with the guard bypassed.** Otherwise
a regression in the component hides behind the guard forever.

## Integration tests

**Invariant: the seam is exercised, not mocked away.**

- If you mock the thing the test is named after, you are testing your mock.
- Assert on the boundary contract: the exact error code, the exact state transition, the exact bytes.
- Test the failure modes of the seam, not only its happy path: timeout, partial write, restart
  mid-operation, concurrent access.
- Any operation that can be interrupted needs a test that interrupts it.

## End-to-end and cross-boundary tests

**Invariant: meaning survives every boundary it crosses.**

Every serialization, FFI hop, or language projection is a place where a distinction can be silently
flattened. Test that it is not.

- Drive the **full** value space across the boundary, not one representative. If an enum has three
  variants, all three cross.
- Assert on the far side in that language's own terms — read the value a real caller would receive.
- Timing and ordering count as meaning. So does the *reason* for a decision, not just the decision.

**Real defect:** every error crossing the WASM boundary became a bare JS string. Code identity,
effect state, and recommended action were all destroyed. A round-trip test existed; it asserted only
that an error occurred.

**The specific rule for this codebase:** the effect axis — whether a real-world effect
`not-applied` / `possible` / `applied` — must arrive intact at every public API in every language.
Losing that distinction is a safety bug, not a formatting bug.

## Differential tests

**Invariant: identical inputs, both implementations, identical outputs — including the reason.**

Use this whenever two things claim to implement the same semantics: a runtime versus the kernel, a
binding versus its owner, an independent reimplementation versus the reference.

- Same bytes in. No translation layer between the two sides, or you are testing the translator.
- Assert the **full** result: verdict, denial reason, and requirement. Matching verdicts with
  different reasons is a disagreement.
- Drive it from the canonical corpus so the inputs are real.

**Real defect:** `auths-node` disagreed with the kernel on **103 of 103** canonical inputs. Nothing
compared them, so nobody knew. The differential test is now the acceptance criterion for that crate.

## Corpus and fixture tests

**Invariant: the corpus covers the input *space*, not just the code paths.**

A branch that no fixture reaches is untested no matter how green the suite is.

- When you add a conditional, add a fixture that takes each side.
- Optional fields need a fixture where the field is **absent**. Absence is the case everyone forgets.
- Adding a fixture is additive and needs no justification. **Changing an existing fixture's bytes is
  a protocol change** and needs written justification naming the decision that authorized it.
- Fixtures are oracles. Never edit one to make a refactor pass.

**Real defect:** all 102 canonical fixtures declared a `requested_budget`. The absent-budget branch
was never exercised, so three independent implementations silently disagreed about it for months.
The disagreement was invisible until one fixture was added.

## Kani harnesses

**Invariant: symbolic input over the real domain, and it must call production code.**

```rust
// WRONG — a unit test wearing a universally-quantified name
#[kani::proof]
fn exact_replay_never_becomes_absent_or_conflict() {
    assert_eq!(replay_code(true, true), ReplayCode::ExactReplay);
}

// RIGHT — quantifies, and calls the production function
#[kani::proof]
fn exact_replay_never_becomes_absent_or_conflict() {
    let seen: bool = kani::any();
    let same: bool = kani::any();
    let code = replay_code(seen, same);          // production code, not a copy
    kani::assert(!(seen && same) || code == ReplayCode::ExactReplay, "...");
}
```

- **Zero `kani::any()` means it is not a proof.** It is a unit test with a misleading name.
- Never transcribe the arithmetic into the harness. If production logic is not reachable, **extract
  it into a function** and call that from both.
- The harness name is a claim. If it says "never", it must quantify over everything that could make
  it happen.
- Mutation-test every harness. Four in this repo survived deliberate breakage.
- **Every `#[kani::proof]` must sit under a gated root.** `cargo xtask` enforces this via
  `kani_harness_inventory`; a harness outside a gated package fails the build rather than silently
  never running.

## Lean, Charon, Aeneas

**Invariant: the model must be able to express the property, and the theorem must be able to be
false.**

- **If the model lacks the field, the theorem is vacuous.** Check that the structure can represent
  what you are proving before you prove it.
- A theorem that holds for *any* definition of the thing it constrains proves nothing. If the proof
  never uses the hypothesis, it is not about the hypothesis.
- **Adding a hypothesis makes a theorem weaker.** That is sometimes unavoidable — disclose it
  explicitly and say why.
- Mutation applies here too: revert the definition to a literal, run `lake build`, confirm the
  theorems go **red**. Any theorem still green does not constrain the property.
- Refinement theorems must cover every dimension the Rust checks. A model narrower than the code
  means the refinement claim is narrower than it sounds.
- **Renaming a theorem means updating both citation sites** — `formal/Auths/Theorems.lean` and
  `formal/assurance-manifest-v1.toml`. A stale citation breaks the assurance audit.
- The translation source-closure pin asserts *"this Lean was produced from this source."* Updating it
  without re-running charon and aeneas fabricates that claim. Never write the digest by hand.

**Real defect:** `delegate_preserves_root` existed, was proved, and was trivially true — the root
field was copied forward, so the theorem held for any definition of delegation. Separately,
`extensionsAttenuate := true` was a literal because `Rich.Grant` had no extensions field: the proof
covered 10 of 11 dimensions and reported 11.

## Gates and conformance checks

**Invariant: a gate scans everything it claims to, and enforces at the level the leak travels.**

- Enumerate what the gate covers and compare it to what it claims. They drift.
- Enforce at the **symbol** level, not the crate level, when leaks travel through re-exports. A
  `Cargo.toml` can look clean while the source is coupled.
- Every declared contract needs a gate. An unenforced contract file drifts silently and nobody
  notices until it is wrong in production.
- If a gate cannot run locally (missing toolchain), say so explicitly. Do not let it pass by absence.
- Prefer inventory gates: rather than listing what to check, fail when something appears **outside**
  the checked set. That way the class cannot return.

---

## Before you open a PR

1. Did every new check fail before the fix? Paste the red output.
2. Did you mutation-test it? Which mutation, and did it go red?
3. Does any check assert a value against itself, or against a constant it also computes?
4. Does any harness transcribe production logic instead of calling it?
5. Is there a literal sitting where a decision belongs?
6. Did you add a conditional without a fixture for each side? An optional field without an
   absent case?
7. Does the denial path have the same coverage as the success path?
8. If you weakened anything — an assertion, a theorem, a gate's scope — did you say so explicitly
   and name the behavior change that justifies it?
9. If you renamed a symbol something cites, did you update the citation?

Any "no" is a change request, including on your own work.
