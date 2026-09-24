# Prompt: kernel soundness (security)

Scope: `core/crates/*`, especially `auths-verifier`, `auths-authority`, `auths-model`, `auths-codec`, `auths-composition`, `auths-registries`.

Goal: find any way to obtain a `VerifiedAction` for an action a correct reading of the spec would deny.

Answer:
1. **Sealing.**
   - Can any `Verified*`/`Effective*` type be built outside its stage function? Look for pub fields, pub/`From`/`Default`/`Deserialize` impls, feature-gated or `cfg(test)` leaks, and `Clone` plus field access.
   - Is each stage bound to the same `TrustedContext`, or can a caller mix contexts across stages to skip a check?
2. **Every principal, every check.**
   - List each principal that appears in a chain: anchor, each issuer, each subject, the actor.
   - For each, list which checks run on it: signature, key state, status/revocation, method acceptance, assurance. Any missing cell is a finding.
3. **Attenuation.**
   - Check each narrowing dimension: permissions, audience, window, budget, depth, resources, extensions.
   - Is the check exact? Hunt for wildcards, prefix matches, empty-set-means-all, inclusive/exclusive window edges, and integer overflow in budgets.
   - Do the author-side and verifier-side rules match on the same edge (anchor → first grant, and grant → grant)?
4. **Composition.**
   - The proof-carried plan counts leaves. Independent signers and roots come from the verifier context's `CompositionRequirement` (see `core/spec/v1/protocol.md`, "Authorization plan"). Does every context that needs independent signers set `minimum_distinct_actors` or `minimum_distinct_roots`? Does any constructor make the unsafe choice easy?
   - Can one signer count as two principals, e.g. the same key under `did:key` and raw key? Don't propose counting distinct keys instead: keyless methods (OIDC workload, Sigstore keyless) use a new key for each signature.
   - Do result fields documented as "satisfied" include authorized leaves outside the satisfying path?
5. **Codec.**
   - Try to find two byte strings that decode to the same value, or one value with two digests.
   - Check depth/size/length bounds before allocation.
6. **Failure classification.**
   - Can any error path fall back to a default (`unwrap_or_default`, empty digest) that then gets signed, hashed or reported?
   - Does Indeterminate ever become Authorized?
7. **Purity.** Look for any clock, env, IO, randomness, or panic reachable from untrusted bytes.

For each finding, propose a canonical fixture vector (input → expected denial code) that would lock the fix in across the Rust, Go and TS verifiers.
