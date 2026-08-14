# Epic 2 — Make the Public API Self-Documenting at Source

**Parent:** [AP-SPEC-040](../0040-stripe-quality-documentation-platform.md)

**Depends on:** Epic 1

**Blocks:** Epics 4, 7, 8, and 11

## Outcome

Give every maintained public Rust, TypeScript, and Python symbol enough
source-owned documentation to generate an accurate reference without writing
reference prose in the website repository.

This is foundational product work in `auths-proof`, not website copywriting.
The result must improve editor hover, `cargo doc`, TypeScript language-server
help, Python `help()`, and the generated site from the same source. Private
implementation is documented only where an invariant, trust boundary, or
non-obvious reason warrants it.

## Zero-context starting point

Read:

- `AGENTS.md`;
- `docs/specs/0040-stripe-quality-documentation-platform.md`;
- `docs/specs/0040/epic_1.md`;
- `release/semantic-freeze.json` public Rust roots and publishable closure;
- `bindings/public-topology-v1.json`;
- `bindings/typescript/src/index.ts`, `product.ts`, `identity.ts`, `verify.ts`,
  `profiles.ts`, `integrations.ts`, `framework.ts`, and `testkit/index.ts`;
- `bindings/typescript/tools/public-api.mjs` and
  `bindings/typescript/api/public-api.txt`;
- `bindings/python/python/auths/__init__.py`, `__init__.pyi`, `identity.py`,
  `verify.py`, `profiles/`, `integrations.py`, `framework.py`, and `testkit.py`;
- `bindings/python/tools/check_public_api.py`;
- the crate roots for `auths`, `auths-sdk`, `auths-runtime`,
  `auths-production-client`, and every public Rust root; and
- `xtask/src/public_naming.rs`, `sdk_experience.rs`, and `sdk_vocabulary.rs`.

Current facts:

- The public API snapshots primarily freeze exported names, not documentation
  completeness or reference-quality descriptions.
- Some Rust APIs have good `///` contracts and error sections, while the public
  closure does not uniformly deny missing documentation.
- Many TypeScript public declarations have expressive types but no TSDoc.
- Python splits runtime facades, native types, and `.pyi` signatures; a docs
  generator must merge these deliberately rather than treating one file as
  the entire API.
- Auths values minimal, truthful comments. A blanket quota for private comments
  would create noise and contradict that standard.

## Documentation priority policy

Apply these tiers in order:

| Tier | Surface | Required treatment |
| --- | --- | --- |
| P0 | Five verbs, normal product constructors, outcome types, recovery, verification, runtime endpoints, maintained profiles, stable errors | Complete contract, trust boundary, failures, and executable example identity |
| P1 | Every symbol exported by a maintained Rust root, npm entrypoint, or Python module | Summary, semantic behavior, parameters/fields where meaning is not encoded by type, return/outcome behavior, and relevant errors |
| P2 | Public extension ports, adapter contracts, custody/transport/store interfaces, protocol types | P1 plus implementer invariants and what the port must not infer |
| P3 | Public members in the publishable Rust closure not directly re-exported by a root | Accurate summary and safety/error contract; deeper prose only where useful |
| P4 | Private code | No coverage target. Document only security invariants, protocol rationale, unsafe assumptions, or surprising constraints |

P0 and P1 block the docs launch. P2 blocks publishing an extension surface.
P3 is enforced before its crate is independently marketed. P4 is never
measured by percentage.

## Content standard

Every P0/P1 symbol must have:

1. one plain-language summary sentence;
2. when to use it, if the name and type do not make that obvious;
3. semantic meaning for parameters or fields that cannot be inferred safely;
4. the closed return or outcome behavior;
5. errors, denials, indeterminate states, recovery behavior, and retry class
   where applicable;
6. a security or trust-boundary section when it accepts untrusted bytes,
   identity evidence, authority, custody, provider state, transport data, or
   disclosure material; and
7. a stable scenario identity for P0 executable examples.

Documentation must not:

- repeat a type signature in prose;
- promise behavior not fixed by tests or semantic identity;
- call an API “simple”, “safe”, “secure”, or “production-ready” without naming
  the bounded property;
- expose internal workflow/spec commentary;
- use migration, deprecation, or compatibility language for unpublished
  surfaces;
- paste credentials, private keys, receipt bodies, or realistic secrets; or
- explain private implementation where a public contract is sufficient.

## Language ownership

### Rust

Rust `///` and `//!` documentation is canonical for Rust public semantics.
Publishable public crates enable `missing_docs = "deny"` once their tier is
complete. Fallible functions document `# Errors`; public panics document
`# Panics`; unsafe APIs document `# Safety`; security-sensitive APIs use a
`# Security` section. Examples reference repository scenario sources and use
`no_run` only when a real external service is required.

Do not add `#[allow(missing_docs)]` to bypass a public surface. Generated code
may have one narrow, file-scoped allowance only when its generator emits the
corresponding reference metadata and CI tests it.

### TypeScript

TSDoc on exported declarations is canonical. Use standard `@remarks`,
`@param`, `@returns`, `@throws`, and `@example` tags plus exactly two configured
Auths tags:

- `@security` for trust and secrecy boundaries; and
- `@scenario` for a stable executable scenario identity.

API Extractor must preserve the comments in its `.api.json` model. Re-exports
inherit one canonical declaration comment; barrel files do not duplicate it.
Interfaces document fields only when their semantic meaning exceeds the type
and property name.

### Python

The public `.py` facade owns user-facing docstrings and runtime `help()`
behavior. `.pyi` files own signatures and types. Griffe merges the installed
runtime object with its stub; disagreement is a build failure.

Use one consistent section form: `Args`, `Returns`, `Raises`, `Security`, and
`Examples`. Only relevant sections are present. Public native `_native` symbols
remain private implementation details where possible. A native class that is
directly re-exported must expose a real runtime `__doc__` from its PyO3
definition and match its public stub identity.

Do not copy full Python docstrings into `.pyi`. The stub may carry a one-line
type-only clarification when necessary, but the merged model must have one
canonical narrative source.

## Architecture

```text
Rust ///          TypeScript TSDoc          Python .py + .pyi
   |                    |                         |
   v                    v                         v
rustdoc model      API Extractor model      Griffe merged model
   |                    |                         |
   +--------------------+-------------------------+
                        |
                        v
             public-doc policy checker
                        |
              summary / errors / security /
              scenario / runtime visibility
```

## Tooling and files

Add:

- `docs/public-api-documentation-policy.toml`: tier assignments, required
  sections, exemptions, owners, and expiry dates;
- `xtask/src/public_docs.rs`: Rust inventory and cross-language policy runner;
- `bindings/typescript/tools/public-docs.mjs`: TSDoc/API-model checker;
- `bindings/typescript/api/tsdoc.json`: exact custom tag configuration;
- `bindings/python/tools/check_public_docs.py`: installed runtime/stub/Griffe
  documentation checker; and
- `release/docs/public-docs-report.json`: generated bounded coverage report.

Prefer extending existing public API tooling rather than adding a parallel
export inventory. The generated report records counts and stable missing
symbol identities, not prose bodies.

## Implementation steps

- [ ] Inventory P0 operations from the Epic 1 contract.
- [ ] Map every maintained public symbol to P0–P3; default an unmapped public
  symbol to failure rather than P4.
- [ ] Establish the content rules and narrow exemption format. Every exemption
  requires an owner, reason, issue, and expiration date.
- [ ] Complete P0 Rust crate/module/item docs and enable missing-doc denial.
- [ ] Complete P0 TypeScript TSDoc and prove it survives declaration emission
  and packing.
- [ ] Complete P0 Python runtime docstrings and prove installed wheel/stub
  merging.
- [ ] Complete P1 across the public Rust roots and maintained SDK entrypoints.
- [ ] Complete P2 extension contracts before advertising adapter authoring.
- [ ] Add P3 enforcement incrementally across the publishable Rust closure;
  finish the closure before the docs launch.
- [ ] Add documentation checks to existing Rust, npm, and wheel package jobs.
- [ ] Generate a privacy-safe report grouped by tier, language, package, and
  owner.
- [ ] Run doctests and doc examples against deterministic fixtures or clean
  installed consumers.

## Adversarial tests

The checks must catch:

- a newly exported undocumented symbol;
- a documented barrel re-export whose canonical declaration is undocumented;
- TypeScript comments stripped from packed declarations;
- a Python name in `__all__` absent from its stub or runtime package;
- a Python stub signature paired with the wrong runtime object;
- a direct PyO3 public export with an empty runtime `__doc__`;
- `# Errors` or `Raises` text that omits a stable closed failure;
- a security-sensitive P0 operation without a security section;
- an example tag naming a nonexistent or incompatible scenario;
- a stale, expired, or overbroad exemption;
- secrets or realistic identifiers in documentation examples; and
- private-comment quantity being used to satisfy a public-doc requirement.

Snapshot tests must normalize whitespace without discarding semantic sections.
Doc-only edits must not change protocol, ABI, wire, or runtime commitments.

## Validation commands

```text
cargo xtask public-docs
cargo doc --workspace --no-deps
cargo test --doc --workspace
cd bindings/typescript && npm run build && node tools/public-docs.mjs
cd bindings/python && python tools/check_public_docs.py
cargo xtask package
```

Run the repository pre-commit configuration before committing.

## Exit gate

This epic is complete when every P0/P1 symbol in installed Rust, npm, and wheel
artifacts has source-owned, reference-quality documentation; P2 extension
contracts describe their invariants; the public Rust closure has a bounded P3
completion plan with no silent gaps; editor/runtime help exposes the same
meaning the docs extractor will consume; and no requirement rewards comments
on ordinary private implementation.
