# 01 — Current complexity baseline

**Status:** implemented
**Milestone:** A — Evidence foundation
**Design dependencies:** none

## Current issue

Auths has qualitative evidence that its SDK experience is complex, but no
versioned measurement of where that complexity appears. Without a baseline,
an API reduction can accidentally move complexity rather than remove it, and
future additions can quietly recreate the same problem.

The current TypeScript package exposes numerous root symbols and many package
subpaths. Python exposes dozens of lazily loaded workflow types at `auths` plus
additional modules for profiles, runtime, receipts, identity, inspection, and
diagnostics. The full effect journey spans authoring, authorization, a native
command, state reservation, credentials, gateway entry, outcome handling, and
receipt persistence.

## Components of the problem

- public export count and import-path count;
- number of core security concepts, profile/domain concepts, setup decisions,
  and API mechanics required before the first effect, reported separately;
- number of objects and callbacks a developer must construct;
- number of explicit workflow transitions coordinated by application code;
- error families that require documentation lookup to determine retry safety;
- duplicated or purpose-overlapping APIs;
- differences between TypeScript and Python for the same customer journey;
- install-time tools, files, and implicit environment assumptions;
- documentation paths that begin with architecture instead of an outcome.

## Product decision

Create a generated, reviewable SDK complexity summary by aggregating the
repository's existing authoritative evidence. It is a measurement view, not a
new source of truth or a permanent compatibility promise. The summary must
describe the current release and fail CI when its declared budgets drift.

The baseline must measure customer journeys, not only symbol counts.

## Authoritative inputs

The command must read, rather than replace or duplicate:

- TypeScript `api/public-api.txt` and package export metadata;
- Python API snapshots, explicit module `__all__` values, and wheel inventory;
- binding capability and ABI metadata;
- the maintained customer-journey matrix and executable recipe metadata;
- existing TypeScript, Python, WASM, and native performance artifacts; and
- semantic-freeze and cross-language fixture inventories.

The generated summary contains:

- schema and contract version;
- TypeScript package entry points and public symbols by entry point;
- Python public modules and public symbols by module;
- primary-journey concept counts and required configuration counts;
- clean-install requirements and artifact sizes;
- maintained recipe count and executable status;
- parity status for each customer journey;
- approved budgets and explicit exceptions.

Add an aggregator/checker under `xtask` rather than maintaining another
committed inventory by hand:

```text
cargo xtask sdk-experience [--update]
```

By default the command emits an ephemeral JSON/Markdown report for CI and pull
request summaries. `--update` updates only an existing authoritative input
whose declared budget or metadata is intentionally changing; it must not write
a second complete API snapshot. The checker must not infer security meaning
from source text.

## Journey inventory

Measure these journeys separately:

1. exchange and authenticate identity bytes;
2. verify an existing proof without executing;
3. execute one exact protected action;
4. delegate narrower authority and execute;
5. authorize and execute an ordered plan;
6. verify a signed receipt offline;
7. define and qualify an application-owned effect vertical;
8. implement and certify a cross-domain mechanism adapter.

For each journey, record:

- imports;
- core Auths security nouns introduced;
- profile/domain concepts introduced;
- SDK setup decisions and API mechanics;
- required application-supplied components;
- executable statements in the maintained example;
- explicit security transitions coordinated by application code;
- possible terminal outcomes;
- TypeScript/Python availability;
- whether Rust is required at consumer install or runtime.

## Implementation steps

- [x] Inventory all TypeScript exports from `package.json`, declaration output,
  and `api/public-api.txt`.
- [x] Inventory Python exports from `auths.__all__`, module `__all__` values,
  native ABI declarations, and the wheel API snapshot.
- [x] Tag each public item as `product`, `component`, `profile`, `integration`,
  `framework`, `testkit`, or `internal-leak` using Spec 04's ownership model.
- [x] Reconcile the eight customer journeys with the existing journey matrix
  and attach missing machine-readable metadata to maintained examples.
- [x] Implement `cargo xtask sdk-experience` as an aggregator over existing
  authoritative snapshots and drift checks.
- [x] Record cold install, package/wheel size, import time, and initialization
  baselines on supported representative platforms.
- [x] Extend the existing performance artifacts with WASM-boundary and
  PyO3-boundary serialization latency for representative small, medium, and
  maximum-bounded inputs.
- [x] Add the checker to authoritative CI and release qualification.
- [x] Link every later simplification PR to before/after inventory output.

## Initial budgets

These are target budgets for the completed program, not a reason to hide types
that applications genuinely need:

| Measure | Budget |
| --- | ---: |
| Primary stateful root operations | 3 |
| Core security concepts in Recipe 3 | 3 (`Authority`, `Action`, `Receipt`) |
| Profile/domain concepts in Recipe 3 | 2 (MCP action family, typed handler/provider) |
| Setup-mode decisions in Recipe 3 | 1 (`development`) |
| Explicit application-orchestrated security transitions | 0 |
| Required Recipe 3 inputs | 3 (bounded authority, action, typed handler/provider) |
| Purpose-labelled public layers | 4 |
| Maintained golden-path recipes per language | 5 |
| New-developer Recipe 3 completion | at least 4 of 5 unaided in 15 minutes |
| Rust toolchain required by installed consumers | 0 |
| Journeys with TypeScript/Python semantic parity | 100% |

## Acceptance criteria

- Repeated `cargo xtask sdk-experience` runs over unchanged authoritative inputs
  produce byte-identical summaries.
- The command creates no competing committed API or capability inventory.
- Removing, adding, or moving a public symbol changes the inventory.
- Breaking one maintained journey changes its executable-status field and
  fails the gate.
- The summary reports TypeScript and Python separately and provides a parity
  summary without pretending syntactic identity.
- The summary never combines security nouns, profile/domain concepts, setup
  decisions, and ordinary language mechanics into one ambiguous count.
- CI displays a concise before/after complexity summary on pull requests.
- The summary includes the latest moderated Recipe 3 cohort size, clean-machine
  definition, individual completion/time, interventions, and anonymized
  blockers; missing evidence cannot be reported as passing.

## Non-goals

- Assigning value to an API solely because it has fewer exported types.
- Freezing a prelaunch public API for backward compatibility.
- Replacing semantic freeze, ABI inventories, package tests, or performance
  baselines.
- Committing a second comprehensive SDK surface manifest that can drift from
  existing authoritative inputs.
