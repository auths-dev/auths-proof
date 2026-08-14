# Content Epic 5 — Developer Resources and Generated Reference

**Depends on:** [Content Epic 0](./epic_0.md) and Platform Epics P4 and P8.

**Ownership:** This epic owns developer landing curation and explanatory
introductions. P8 exclusively owns generated reference pages, signatures,
endpoint inventories, errors, versions, and fact templates.

## Outcome

Developers can move from ecosystem orientation to exact Rust, TypeScript,
Python, Runtime API, CLI, schema, error, and evidence contracts without
encountering hand-maintained drift.

## Current problem

The current SDK and Runtime API pages prove the intended visual layout, but
their content models are still partly hard-coded in the docs repository. The
CLI, error catalog, schema reference, version policy, source links, and complete
cross-language SDK journey are absent or shallow.

Stripe separates Developer Resources, SDK catalogs, API catalogs, cross-language
SDK guides, CLI reference, errors, and versioning.
[Research evidence](./STRIPE_CONTENT_RESEARCH.md#batch-5--sdks-cli-agents-failures-and-assurance)

## Developer landing

`/developers` groups:

- install and local environment;
- Rust, TypeScript, and Python SDKs;
- Runtime API;
- CLI;
- agent and MCP tooling;
- testing and deterministic fixtures;
- errors and closed outcomes;
- integrations and extension kits;
- versioning, changelog, and release support;
- assurance and source code.

## Reference hierarchy

```text
/reference
├── /sdk
│   ├── /rust
│   ├── /typescript
│   └── /python
├── /runtime-api
├── /cli
├── /profiles
├── /errors
├── /schemas
├── /evidence
└── /manifest.json
```

## Cross-language SDK guide

The main SDK guide synchronizes language across:

1. installation and supported runtime;
2. explicit integration composition;
3. `create`;
4. `delegate`;
5. `execute`;
6. `resume`;
7. `verify`;
8. outcome and receipt inspection;
9. error handling;
10. testing;
11. advanced/profile-specific entry points; and
12. source and release provenance.

Rust may expose lower-level native components where the product facade differs,
but the page must label that distinction and preserve semantic equivalence.

## Generated fact ownership

| Fact | Sole owner |
|---|---|
| Rust signatures/docs | installed Rustdoc/bounded export |
| TypeScript exports/signatures/docs | installed declarations and API snapshot |
| Python signatures/docs | installed wheel, stubs, runtime metadata |
| Runtime endpoints/limits/content types | compiled Rust runtime export |
| CLI commands/flags/defaults | compiled CLI command graph |
| Profiles and stable errors | frozen Rust registries |
| Schemas and fields | release schemas |
| Evidence/claim status | release evidence graph |

Authored content may explain a fact but cannot restate its signature, version,
default, or inventory as source truth.

## Implementation steps

- [x] Audit P4/P8 bundle coverage for every fact-owner row and report extractor
  gaps to the platform lane.
- [x] Remove hard-coded SDK operations and Runtime endpoints from authored
  content.
- [x] Author the developer landing and curate its generated reference catalogs.
- [x] Author the cross-language SDK orientation and link each operation by
  stable identity.
- [x] Curate explanatory introductions and related journeys for Runtime API,
  CLI, errors, profiles, schemas, and evidence.
- [x] Author compatibility, preview-channel, and prelaunch policy explanation
  around generated support facts.
- [x] Review P8's three-column SDK and Runtime API renderings for reader
  comprehension without editing generated pages.
- [x] Resolve every authored dependency reported by P8's contract diff; never
  suppress stale or missing projections with copied prose.

## Acceptance criteria

- Changing a public argument or endpoint in `auths-proof` updates the correct
  page or fails the source PR with an exact dependency report.
- No maintained public symbol is missing its generated reference projection.
- SDK and Runtime API pages share navigation, section actions, sticky code,
  outcome rendering, responsive behavior, and Markdown parity.
- CLI reference is exhaustive and generated from executable command metadata.
- Error pages distinguish denied, indeterminate, recoverable, provider-unknown,
  invalid input, and internal failures without collapsing them into exceptions.
- A fresh docs build does not mutate source files.

## Validation

```text
npm run reference:build -- --bundle <verified-bundle>
npm run reference:check
npm run test:contract-diff
npm run test:reference
npm run test:markdown
npm run test:search
npm run build
```
