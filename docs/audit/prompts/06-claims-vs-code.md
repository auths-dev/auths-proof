# Prompt: claims-vs-code audit

Scope: whole repo. Claims come from `README.md`, `product/README.md`, `docs/`, `protocol/`, manifests (`*.toml` at the root), demo READMEs, and doc comments.

Goal: build a ledger of every public claim and the evidence behind it.

Steps:
1. **Extract claims.** Take every sentence that asserts a guarantee, capability, coverage figure or status. Examples: "exactly once", "the agent never sees the credential", "works on every X", "three independent implementations agree", "proved in Lean".
2. **Classify the evidence for each claim:**
   - **Enforced by type**: path:line.
   - **Enforced by runtime check**: path:line, plus whether any path skips it.
   - **Tested**: which test, and whether it tests the adversarial case or only the happy path.
   - **Formally proved**: which Lean theorem, and whether it is about the Rust code (Aeneas translation) or only a model.
   - **Convention/doc only.**
   - **Contradicted by code.**
3. **Staleness.** List manifests and docs that disagree with the code: inventory status, crate lists, commands that no longer exist.
4. **Wording.** For each overstated claim, propose the exact wording that is true today.

Output: a table (claim | source | evidence class | path:line | proposed wording), sorted with contradicted claims first.
