# Epic 7 — Build Executable Cross-Language Examples

**Parent:** [AP-SPEC-040](../0040-stripe-quality-documentation-platform.md)

**Repository:** `auths-proof-docs`, consuming immutable `auths-proof` bundles

**Depends on:** Epics 4–6

**Blocks:** Epics 8, 10, and 11

## Outcome

Make every displayed Rust, TypeScript, and Python example originate from a real
source file that CI installs, compiles or executes, and compares against the
same Rust-owned fixtures and normalized outcomes.

Language switching becomes a semantic view over one scenario, not three
unrelated snippets that happen to look similar.

Content Epic 4 owns quickstart sequencing and explanation. This epic owns the
scenario artifacts, execution, comparison, provenance, and safe display
projection consumed by those pages.

## Zero-context starting point

Read:

- parent sections 8, 11, 13, and 19;
- Epics 1, 4, 5, and 6;
- the docs release-bundle schema and scenario inventory;
- `bindings/public-topology-v1.json`;
- the Rust, TypeScript, and Python installed-consumer tests;
- `bindings/typescript/test/` and `bindings/python/external/`;
- `product/fixtures/v1/` and core cross-language fixtures;
- `demos/open-production-reference/`; and
- `xtask/src/product_waist.rs`, `sdk_experience.rs`, and fixture tooling.

## Scenario contract

Define a closed manifest:

```yaml
id: auths.scenario.rest-authorize/1
operation: auths.operation.authority.execute/1
profile: auths.profile.application.rest-effect/1
languages: [rust, typescript, python]
steps: [create, execute, verify]
fixtures:
  action: rest-effect-v1
  authority: one-use-authority-v1
expected:
  first: completed
  replay: denied.replay-detected
  mutation: rejected.commitment-mismatch
display:
  files:
    rust: rust/rest-authorize/src/main.rs
    typescript: typescript/rest-authorize/index.ts
    python: python/rest-authorize/main.py
```

Parse into closed types. Bound step count, file count, output size, fixture
references, process duration, and normalized result size. Scenarios cannot
contain commands, environment-variable interpolation, arbitrary shell, or
network destinations.

## Launch scenarios

At minimum implement:

- protect one REST effect;
- delegate narrower authority to an agent;
- verify a receipt summary;
- request authorized receipt disclosure;
- deny exact replay;
- reject changed action bytes;
- expire authority;
- refuse delegation widening;
- return indeterminate trusted-context evidence; and
- return provider-unknown with recovery/resume.

Reuse one coherent fictional application where possible. Each scenario names
its exact operation/profile identities and expected closed outcomes.

## Architecture

```text
ScenarioV1 + Rust-owned fixtures
            |
    +-------+-------+
    |       |       |
    v       v       v
 clean    clean    clean
 Cargo    npm      wheel
 consumer consumer consumer
    |       |       |
    +-------+-------+
            |
            v
     normalized outcomes
            |
     exact differential join
            |
      TestedExample component
      reads source files only
```

The runner never evaluates code from MDX. It executes only checked scenario
entries from bounded local paths.

## Installed consumers

- Rust examples depend on the packaged crate tarballs or a release registry
  mirror, never a sibling path.
- TypeScript examples install the exact npm tarball into an empty directory
  with a generated lockfile captured as test evidence.
- Python examples install the exact wheel into an empty virtual environment
  and remove the repository root from import resolution.
- All consumers use deterministic public keys, fixtures, ports, and clocks
  intended for examples. Secret scanners inspect source and captured output.

Production-shaped scenarios may connect to the open reference container. They
must use an isolated ephemeral instance with bounded startup and teardown and
must not require a cloud account.

## Normalized outcome model

Compare product meaning, not language formatting:

```ts
type NormalizedOutcome =
  | { kind: "completed"; operation: OperationId; commitments: DigestSet }
  | { kind: "denied"; code: StableErrorCode; retry: RetryClass }
  | { kind: "indeterminate"; code: StableErrorCode; retry: RetryClass }
  | { kind: "recoverable"; state: RecoveryState; retry: "resume" }
  | { kind: "verified"; commitments: DigestSet }
  | { kind: "rejected"; code: StableErrorCode };
```

Do not compare random signatures, timestamps, receipt bytes, local paths, or
language-specific object strings. Do compare stable codes, effect state, retry
class, semantic commitments, member order, and required disclosure mode.

## Display contract

`<TestedExample scenario="..." />`:

- resolves the scenario through the verified page graph;
- reads the exact executed file and declared display range;
- synchronizes Rust/TypeScript/Python tabs by semantic step;
- shows the package version and last qualification digest;
- provides copy-file and source-at-release actions;
- never displays fixture secrets or captured environment; and
- renders useful fenced code plus source links in canonical Markdown.

The HTML renderer composes Epic 5's shared `CodeBlock` and
`CodeBlockWithResult` components. Each displayed source declares its SDK
language and whether the region is Bash. Bash installation/start commands
retain the selected SDK association but use Bash grammar. Displayed normalized
outcomes declare their result grammar and default to JSON. Switching the
page-wide language changes every applicable source region while preserving the
same semantic step and normalized result meaning.

The result panel is sourced from the bounded normalized outcome artifact for
the exact scenario run. It is not hand-authored display JSON and cannot contain
raw signatures, timestamps, receipt bytes, local paths, environment values, or
other fields excluded by the normalizer.

Use explicit source markers only to select meaningful regions from setup-heavy
files. Markers must be comments understood by the extractor and stripped from
display; they cannot contain prose that belongs in the guide.

## Files to add

In `auths-proof-docs`:

- `examples/scenarios/*.yaml`;
- `examples/rust/<scenario>/`;
- `examples/typescript/<scenario>/`;
- `examples/python/<scenario>/`;
- `tools/run-scenarios/`;
- `tools/normalize-outcome/`;
- `site/src/components/TestedExample.astro`;
- scenario schemas and golden normalized results; and
- tests for source extraction and tab synchronization.

In `auths-proof`, change only fixture/export support required by a scenario.
Do not add docs-site dependencies or duplicate examples in SDK READMEs.

## Implementation steps

- [ ] Freeze the scenario schema and stable IDs.
- [ ] Implement one REST scenario in all languages and qualify the runner.
- [ ] Add exact differential comparison and readable mismatch reports.
- [ ] Add the remaining launch scenarios incrementally.
- [ ] Build `TestedExample` over source files and scenario metadata.
- [ ] Render source/result through the shared code components and validate
  language, Bash override, result grammar, copy payload, and global selection.
- [ ] Reject MDX code fences marked as executable.
- [ ] Add source-at-release URLs through provenance, not branch URLs.
- [ ] Cache immutable package downloads by digest without sharing mutable
  installation directories between jobs.
- [ ] Bound output and redact before artifact upload.
- [ ] Add a matrix across supported Node, Python, browser/WASM, and stable Rust
  versions where the example surface applies.

## Adversarial tests

Catch:

- source displayed but never executed;
- a shell region highlighted as Rust, TypeScript, or Python because global
  language incorrectly overrides `isBash`;
- a normalized JSON outcome rendered without JSON grammar or copied from MDX;
- one code group retaining a stale language after the page-wide switch;
- a scenario language missing while declared supported;
- code importing from a sibling checkout;
- the wrong npm tarball, wheel, crate, fixture, or reference image;
- replay accidentally completing;
- mutation producing the same commitment;
- provider-unknown mapped to denied or completed;
- recovery example calling execute again instead of resume;
- nondeterministic ordering hidden by the normalizer;
- random or sensitive fields compared or rendered;
- display markers escaping the declared source file;
- an example opening an undeclared network destination;
- output exceeding its bound or containing a secret-like value; and
- Windows path/newline differences changing semantic results.

## Validation commands

Define:

```text
npm run examples:prepare -- --bundle <path-or-digest>
npm run examples:run
npm run examples:compare
npm run examples:render-check
npm run test:examples
```

The final job starts from empty Cargo/npm/Python consumer directories and
retains only bounded normalized evidence.

## Exit gate

This epic is complete when every launch scenario executes from installed
artifacts in Rust, TypeScript, and Python where supported; normalized meanings
match Rust-owned fixtures; displayed code and results use the shared typed
components and are the exact bounded run artifacts; the page-wide selector is
semantically synchronized; and a signature, import, semantic, packaging,
language, or outcome drift fails before the docs can render it.
