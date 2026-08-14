# Auths open production candidate 1 assurance

This directory is the public evidence boundary for one immutable Auths open
production candidate. It currently records an honest **in-progress** state. No
artifact digest, thirty-day qualification, independent review, or signed
production statement has been claimed.

| Gate | Current state |
| --- | --- |
| Immutable candidate binding | Pending |
| Sustained qualification | 0 of 2,592,000 seconds |
| Required evidence families | 0 of 7 |
| Independent security review | Pending |
| Signed statement | Absent |
| Production release eligible | No |

The release gate is executable:

```text
cargo xtask assurance candidate --bind candidate-binding.json release/assurance/open-production-candidate-1/manifest.json
cargo xtask assurance record qualification-or-evidence-or-review.json release/assurance/open-production-candidate-1/manifest.json
cargo xtask assurance sign release/assurance/open-production-candidate-1/manifest.json
cargo xtask assurance summarize release/assurance/open-production-candidate-1/manifest.json
cargo xtask assurance verify release/assurance/open-production-candidate-1/manifest.json
```

`summarize` is safe for an incomplete candidate. `verify` fails until all
required evidence is candidate-bound, passed, retained, independently reviewed,
and signed by a key in `../trusted-signers.json`. GitHub prerelease promotion
invokes the same verifier.

`candidate --bind` accepts the strict `auths.assurance-candidate-input/1`
shape. It computes the candidate digest from the complete canonical input;
callers cannot choose a label that fails to commit the packages, image,
provenance, configuration, schema, source commit, or semantic freeze.

Preparation is not qualification, and qualification is not release approval.
Any executable candidate, image, package, configuration, schema, or semantic
fixture change creates a new binding and invalidates evidence for prior bytes.
