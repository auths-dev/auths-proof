# Content Epic 4 — Outcome Quickstarts and Tested Projects

> **Status revoked by rendered-site audit.** Requalify through Content Epics
> 10–19; existing checked tasks record prior implementation, not completion.

**Depends on:** [Content Epic 0](./epic_0.md), Content Epics 2–3, and Platform
Epic P7.

**Ownership:** This epic owns quickstart sequencing, explanation, and reader
transitions. P7 owns executable source, commands, fixtures, and normalized
results. Public MDX selects scenario identities and never copies their code.

## Outcome

Every recommended Auths path has a runnable, downloadable, cross-language
project that produces one observable success and demonstrates fail-closed
behavior.

## Current problem

The current site renders representative snippets and labels scenarios as
tested, but the documentation repository does not yet install and execute every
displayed Rust, TypeScript, and Python project. Static snippets cannot prove a
reader can reproduce the workflow.

Stripe's interactive quickstarts synchronize language/framework choices,
numbered steps, working samples, downloads, and text alternatives.
[Research evidence](./STRIPE_CONTENT_RESEARCH.md#batch-3--product-choice-interactive-quickstarts-and-lifecycle-concepts)

## Launch quickstarts

| Stable scenario | Route | Success | Required failure |
|---|---|---|---|
| `auths.scenario.local-rest-effect/1` | `/quickstarts/local-rest-effect` | One exact REST-shaped effect completes | Mutated bytes denied |
| `auths.scenario.runtime-effect/1` | `/quickstarts/runtime-effect` | Open runtime returns a completed receipt | Exact replay denied |
| `auths.scenario.agent-delegation/1` | `/quickstarts/agent-delegation` | Agent calls one delegated tool | Widening rejected |
| `auths.scenario.approved-plan/1` | `/quickstarts/approved-plan` | Exact approved plan completes in order | Substituted plan rejected |
| `auths.scenario.offline-verification/1` | `/quickstarts/offline-verification` | Proof and receipt verify offline | Wrong context denied |
| `auths.scenario.recovery/1` | `/quickstarts/recovery` | Recoverable execution resumes once | Fresh retry prohibited |
| `auths.scenario.identity-swap/1` | `/quickstarts/identity-swap` | Same workflow passes with two suites | Mislabelled suite rejected |

## Project structure

```text
examples/<scenario>/
├── scenario.json
├── rust/
│   ├── Cargo.toml
│   └── src/main.rs
├── typescript/
│   ├── package.json
│   └── src/main.ts
├── python/
│   ├── pyproject.toml
│   └── main.py
├── expected/
│   ├── completed.json
│   └── failure.json
└── README.md
```

Every runner installs immutable release candidates in an empty consumer. It
captures bounded normalized output, redacts environment-specific fields, and
compares semantic outcomes across languages.

## Quickstart UX

```text
+----------------------+---------------------------+---------------------------+
| Steps                | Meaning                   | Tested source / result    |
| 1 Install            | What this step changes    | Rust | TypeScript | Python|
| 2 Compose            | Security boundary         | source                    |
| 3 Create             | Expected state            |---------------------------|
| 4 Execute            |                           | normalized result         |
| 5 Break safely       |                           |                           |
+----------------------+---------------------------+---------------------------+
```

Required controls:

- global language selection;
- optional application framework selection only when the project truly differs;
- numbered progress and deep links;
- copy, open canonical Markdown, download exact project, and source-at-release;
- tested release identity and fixture digest;
- expected duration and prerequisites;
- text-only alternative with identical semantic steps; and
- next steps into tours, operations, and reference.

## Implementation steps

- [x] Select the seven required scenario identities from P7 and report missing
  scenarios as platform dependencies.
- [x] Author each quickstart's outcome, prerequisites, transitions, explanation,
  failure path, and next steps.
- [x] Assemble displayed steps exclusively with P7 scenario components.
- [x] Keep Rust, TypeScript, and Python at the same semantic step while allowing
  idiomatic explanation around each projection.
- [x] Link deterministic archives and source-at-release provenance produced by
  P7.
- [x] Review normalized results for plain-language comprehensibility without
  copying result payloads into MDX.
- [x] Prohibit executable MDX fences and copied examples.
- [x] Record missing failure coverage against the owning P7 scenario rather
  than patching code in the content lane.

## Acceptance criteria

- Every displayed executable line comes from a project that ran successfully.
- Each language produces the same normalized semantic outcome.
- Failure demonstrations fail for the intended stable reason.
- A clean machine can download and run each project using documented commands.
- Switching language never changes step meaning or skips a security boundary.
- Quickstart HTML, text view, Markdown, and archive name the same release and
  scenario digest.

## Validation

```text
npm run examples:prepare -- --bundle <immutable-bundle>
npm run examples:run
npm run examples:compare
npm run test:quickstarts
npm run test:downloads
npm run test:markdown
npm run build
```
