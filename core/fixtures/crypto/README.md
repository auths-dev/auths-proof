# Strict signature-suite corpus

`p256-sha256-v1.tsv` is shared by the native Rust implementation and the
independent Go and TypeScript verifiers. It contains 653 cases: 173 admitted
signatures over 98 distinct public keys, 369 equation/low-S refusals, 85
signature-encoding refusals, and 26 invalid-key/error-priority refusals.
The complete corpus spans 111 valid curve points.

The input is Project Wycheproof's complete 262-case P-256/SHA-256 IEEE P1363
verification corpus at commit
[`878e5366008753df2064d40c49f8e2f50f9c6af7`](https://github.com/C2SP/wycheproof/blob/878e5366008753df2064d40c49f8e2f50f9c6af7/testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json).
The exact source bytes have SHA-256
`c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986`.
The source is Apache-2.0 licensed; see the upstream
[license](https://github.com/C2SP/wycheproof/blob/878e5366008753df2064d40c49f8e2f50f9c6af7/LICENSE)
and this repository's [Apache license text](../../../LICENSE-APACHE).
Project Wycheproof's authors retain their attribution. No upstream private
key material is included.

The adapter retains every original signature and message; the vendored JSON
preserves the upstream classifications. It converts the published uncompressed point to the unique corresponding compressed SEC1
encoding; other SEC1 forms are independently refused by Auths. General ECDSA
accepts high-S signatures, while the registered Auths suite requires low-S.
Consequently each original valid high-S tuple is recorded as an Auths refusal
and receives its mathematically equivalent `n-s` low-S positive case. Each
original low-S tuple receives its reflected high-S refusal. Every valid tuple
also has a changed-message refusal. These transformations are explicit and do
not modify an upstream invalid verdict into an acceptance.

Additional cases cover exact widths, zero/out-of-range scalars, half-order
boundaries, uncompressed/compact/hybrid/infinity encodings, out-of-field and
non-curve coordinates, altered domain/profile/descriptor bytes, and invalid-key
precedence over a malformed signature. These altered-message examples exercise
exact-byte signature binding; they do not replace the separate caller-framing
and canonical-object proofs.

`import_p256_wycheproof.py` regenerates the TSV from a local copy of the exact
upstream JSON and refuses a changed source hash. Pass the source and output
paths, with `--write` to regenerate; omitting it checks byte equality. The
exact upstream JSON is vendored under `upstream/`, and qualification checks
byte-for-byte reproduction without network access. Normal test runs consume
the committed TSV.

Rust checks the native primitive and shipping `SignatureSuite` adapter, their
key validators, and the complete stable result/error mapping. Go and TypeScript
check the same boolean signature verdicts using their independent libraries;
Go also checks the key verdict. Tests pin the complete case, positive, and
distinct-positive-key counts. Hosted bindings conformance includes both
independent runners, and core-layer tests include the Rust integration test.
These are conformance results, not proofs of cryptographic arithmetic or
security, and do not discharge the explicit primitive premises in Lean.
