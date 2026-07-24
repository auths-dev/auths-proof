# Security Policy

## Project status

`auths-proof` `0.1.x` is pre-audit software. Do not rely on it as the sole
production authorization control for high-value actions.

## Reporting

Please report suspected vulnerabilities privately through the repository
host's Security Advisory feature. Do not open a public issue containing an
exploit, private key, sensitive proof, or customer data.

Include:

- affected commit and crate;
- proof or input bytes where safe;
- expected and actual verdict;
- reproduction steps;
- security impact;
- whether the issue is already public.

## In scope

- deterministic encoding and domain separation;
- grant/action content identifiers;
- delegation attenuation;
- trust-anchor handling;
- adapter selection and algorithm confusion;
- raw Ed25519/P-256 verification;
- evidence and reference validation;
- replay/context binding;
- parser panic, memory, and CPU exhaustion;
- WASM/native verdict divergence;
- CLI behavior that could misrepresent a verdict.

## Explicit limitations

- Private keys are managed outside this repository.
- Raw-key principals have no rotation or revocation.
- `ExpiryOnly` grants cannot be revoked before expiry.
- The host owns challenge uniqueness and consumption.
- The host must execute the same body supplied to verification.
- The host selects trusted adapters, anchors, time, and policy.
- Milestone 1 has no KERI or grant-status adapter.

See `docs/threat-model.md` for the full boundary.

## Cryptographic changes

Changes to algorithms, key encodings, signature encodings, domain strings, or
signed bytes require:

- an ADR;
- positive, negative, and algorithm-confusion vectors;
- golden-wire review;
- conformance and fuzz coverage;
- explicit registry update;
- independent review before release.
