# Independent launch review scope

Review the immutable release-candidate commit and the artifacts produced by
`cargo xtask release-check`. At minimum, cover:

- verifier-required composition and signer/root independence;
- canonical CBOR, signed-byte construction, domains, and identifier rules;
- algorithm-confusion and signature-malleability resistance;
- delegation attenuation and graph/reference handling;
- status freshness, conflict selection, and sequence rollback;
- `Any`/`Every` assurance quantification;
- exact evidence binding and actual adapter consumption;
- adapter and whole-verifier configuration commitments;
- adapter-specific trust assumptions and externally sourced vectors;
- denial versus indeterminate classification;
- hostile CPU, memory, allocation, and stack behavior;
- native versus generated Node/WASM equivalence.

Deliverables are a versioned report, severity rubric, exact commit and
toolchain, retained proof-of-concept inputs, and a finding-resolution ledger.
High-value safe inputs become ordinary public regression vectors. A report is
complete only after fixes are reviewed against the same frozen candidate or a
clearly identified successor.

No independent review has yet been commissioned or completed. Repository
automation must not mark this human gate complete.
