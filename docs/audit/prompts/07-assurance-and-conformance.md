# Prompt: assurance machinery (formal, conformance, fuzzing, CI)

Scope: `formal/`, `core/crates/auths-formal-refinement`, `auths-algebra-kernel`, Kani harnesses, the fuzz targets, `fixtures/`, the Go/TS verifiers, `xtask` (`conformance`, `wire`, `arch`, `ci`), `.github/workflows`, `architecture.toml`, `compliance.toml`.

Goal: work out what the assurance actually covers, and where a bug could slip past every gate.

Answer:
1. **Lean.**
   - List each theorem and its informal statement.
   - Which ones are about Aeneas-translated Rust, and which are about a hand-written model?
   - Is there any `sorry`, `axiom`, `admit`, or unchecked `decide`?
   - What does the refinement test compare, and could the model and the code drift apart unnoticed?
2. **Kani.** Which properties are checked, with what unwind bounds, and are those bounds meaningful?
3. **Fuzzing.** Which targets exist, what they reach, and for how long CI runs them. Are there any seeds for adversarial proof structures?
4. **Conformance.**
   - Do the Go and TS verifiers really share no code or generated artifacts with the Rust one?
   - What share of denial codes and branches does the fixture corpus cover?
   - Is there a vector for every kernel check? Map checks to vectors and list the checks that have none.
5. **Mutation test.** Pick 5 security-relevant lines in the verifier (e.g. a status check, an attenuation comparison, a K-of-N threshold). For each, say whether *any* gate would fail if the line were deleted or inverted. Run it if feasible.
6. **Architecture gates.** Are the dependency-direction and purity rules enforced by CI, or only documented?
7. **Coverage of product layers.** Which assurance applies to runtime, gateway and integration code? It is probably much less than for the kernel, so list the uncovered high-risk areas.

Output: a coverage map (property → gates that protect it → gaps), and the 5 cheapest additions that would have caught the most serious issues.
