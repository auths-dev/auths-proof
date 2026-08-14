# Epic 4 — Extract Installed SDK Surfaces and Publish the Docs Bundle

**Parent:** [AP-SPEC-040](../0040-stripe-quality-documentation-platform.md)

**Depends on:** Epics 1–3

**Blocks:** Epics 7–11

## Outcome

Extract exact signatures and source-owned documentation from the Rust crates,
packed npm package, and built Python wheel that users actually install. Join
those surfaces with the stable operation contract and publish one immutable,
checksummed documentation bundle for `auths-proof-docs`.

This epic is the automation waist. It must make an argument change, return-type
change, export change, or documentation change visible without hand-editing a
website reference page.

## Zero-context starting point

Read:

- `AGENTS.md`;
- `docs/specs/0040-stripe-quality-documentation-platform.md`;
- Epics 1–3 in this folder;
- `bindings/typescript/tools/public-api.mjs`, `package.json`, and `tsconfig.json`;
- `bindings/python/tools/check_public_api.py`, `check_wheel.py`,
  `pyproject.toml`, and `python/auths/_native.pyi`;
- `.github/workflows/typescript-sdk.yml` and `python-sdk.yml`;
- `xtask/src/package.rs` or the current packaging command implementation;
- `xtask/src/release.rs`, `release_control.rs`, and `docs_contract.rs`;
- `release/semantic-freeze.json`; and
- `release/release-subjects.toml`.

Current facts:

- TypeScript already inspects installed declaration exports and freezes their
  names.
- Python already installs wheels in CI, verifies explicit `__all__`, typing,
  and public-name snapshots.
- Rust semantic freeze identifies the public crate closure but does not expose
  a normalized per-item documentation model.
- Stable Rust 1.97 rustdoc does not expose JSON output in its normal help;
  structured Rust extraction therefore requires a separately pinned docs-only
  nightly. That toolchain must not change the shipping MSRV or stable build.

## Product constraint

The docs show the artifact users install, not a favorable source-tree
approximation. If a comment, overload, class, function, type, or Python object
does not survive packaging, it is not public documentation.

Cross-language pages join by operation identity. They may show idiomatic
language differences but must not imply parity where the capability contract
says unsupported.

## Architecture

```text
release candidate
  |
  +--> cargo package/crates --> pinned rustdoc JSON --> RustSurfaceV1
  |
  +--> npm pack/install ------> API Extractor JSON -> TypeScriptSurfaceV1
  |
  +--> wheel/install ---------> Griffe + inspect ---> PythonSurfaceV1
  |
  +--> runtime/profile/error/evidence facts --------> ProductFactsV1
                                                        |
                                                        v
                                  operation/projection completeness join
                                                        |
                                                        v
                                       AuthsDocsReleaseBundleV1
                                       contract + sources + fixtures
                                       manifest + checksums + provenance
```

Every extractor parses into a language-specific closed type. Only verified
surfaces may enter the cross-language join.

## Tool decisions

### Rust

- Pin one exact nightly date in `rust-toolchain.docs.toml`.
- Run rustdoc JSON only against packaged public crates with the release feature
  set.
- Pin the matching `rustdoc-types` schema in a build-only extractor.
- Normalize item IDs to crate coordinate plus public path; discard compiler-
  internal unstable IDs.
- Retain signatures, generics, bounds, fields, variants, impl relationships,
  stability, source-owned docs, and source provenance.

### TypeScript

- Add `@microsoft/api-extractor` at an exact locked version.
- Extract from `.d.ts` files inside a clean installed tarball consumer.
- Retain package subpath, exported name, overloads, type parameters, members,
  signatures, release tags, TSDoc, and declaration digest.
- Keep `public-api.txt` as the compact merge gate; the API model becomes the
  reference source.

### Python

- Pin Griffe in the docs build environment.
- Install the wheel into a clean virtual environment with no repository root
  on `sys.path`.
- Merge runtime exports/docstrings with `.pyi` signatures and types.
- Retain module, qualified name, call signature, overloads, members,
  annotations, docstring sections, runtime availability, and wheel digest.
- Fail if an object resolves from the source checkout instead of the wheel.

## Bundle contract

Publish an archive equivalent to:

```text
auths-docs-bundle-<release>-<digest>.tar.zst
├── manifest.json
├── auths-docs-contract-v1.json
├── surfaces/
│   ├── rust.json
│   ├── typescript.json
│   └── python.json
├── fixtures/
│   ├── scenarios.json
│   └── normalized-outcomes.json
└── provenance/
    ├── subjects.json
    └── checksums.json
```

The manifest binds product commit, release identity, semantic-freeze digest,
toolchain identities, extractor versions, package digests, contract digest,
and every member checksum. The bundle contains no compiled executable, secret,
private source file, arbitrary build log, or unbounded repository archive.

## Join and mapping rules

- A supported SDK projection must resolve to exactly one installed public
  symbol.
- A mapped symbol may represent multiple overloads but one product meaning.
- An installed maintained entrypoint symbol not classified as product,
  extension, testkit, or explicitly internal fails.
- All P0/P1 symbols must carry the Epic 2 documentation sections.
- A signature fingerprint change preserves its operation identity only when
  the meaning is unchanged; semantic change requires an operation version.
- A capability present in Rust and absent from TypeScript or Python requires an
  explicit support state and reason.
- Source provenance uses the release commit and repository-relative path, not
  mutable branch URLs or source line numbers as identity.

## Files to add or change

- `rust-toolchain.docs.toml`;
- `tools/docs-extractor/` or an existing build-tool location approved by
  architecture policy;
- `bindings/typescript/api-extractor.json` and package dependencies;
- `bindings/typescript/tools/docs-surface.mjs`;
- `bindings/python/tools/docs_surface.py`;
- `xtask/src/docs_contract.rs` and a narrow `docs_bundle.rs` module;
- release builder workflow steps and subject declarations;
- bundle schemas under `product/spec/v1/`; and
- deterministic extractor fixtures under `release/fixtures/docs/`.

## Implementation steps

- [ ] Pin and checksum the docs-only Rust toolchain and schema parser.
- [ ] Build each extractor against a minimal fixture artifact first.
- [ ] Normalize paths, ordering, whitespace, default values, and language-
  specific unstable IDs deterministically.
- [ ] Install the real release candidate artifacts into empty consumers.
- [ ] Extract source docs and signatures from installed artifacts.
- [ ] Join every projection through the Epic 1 operation identity.
- [ ] Join runtime/profile/error/evidence facts from Epic 3.
- [ ] Emit exact coverage and affected-operation reports.
- [ ] Build the bounded archive and verify every checksum after extraction.
- [ ] Add the bundle to release subjects and the reusable release builder.
- [ ] Add `cargo xtask docs-bundle <artifact-dir>` and a check-only verification
  command.

## Adversarial tests

Catch:

- an npm tarball missing a source-declared export;
- a `.d.ts` comment stripped during build;
- a wheel importing from the checkout;
- a Python runtime/stub signature mismatch;
- a Rust item present in source but absent from the packaged feature set;
- a rustdoc schema/toolchain mismatch;
- two symbols mapped to one operation accidentally;
- one symbol mapped to two incompatible operations;
- an undocumented P0/P1 installed symbol;
- hidden drift caused only by map ordering, CRLF, or absolute runner paths;
- a changed signature with an unchanged fingerprint;
- archive path traversal, symlinks, duplicate members, or checksum mismatch;
- a secret-like value or private build path in any public artifact; and
- a bundle claiming a different commit or package digest.

Run golden extractor fixtures on Linux, macOS, and Windows where the installed
package differs. Their normalized semantic output must match.

## Validation commands

```text
cargo xtask package
cargo xtask docs-contract
cargo xtask docs-bundle target/platform-artifacts
cargo xtask release-contract
cd bindings/typescript && npm run test:api
cd bindings/python && python tools/check_public_api.py
```

Also install and inspect the generated npm tarball and wheel from clean
temporary consumers. Run the repository pre-commit configuration before
committing.

## Exit gate

This epic is complete when one immutable bundle reconstructs exact installed
Rust, TypeScript, Python, runtime, profile, error, and evidence surfaces; every
supported projection joins by stable operation identity; toolchain and package
provenance are pinned; and changing a public argument or export changes the
bundle automatically without a website edit.
