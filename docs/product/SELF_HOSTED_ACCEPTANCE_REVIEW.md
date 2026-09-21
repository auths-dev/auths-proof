# Self-hosted SDK acceptance review — 2026-09-21

This is a review of the public developer surface and the acceptance clauses in
AP-SPEC-051, -052, -054, and -055 for PR #123. It does not promote an
application-owned provider adapter to an Auths-qualified integration. The
review covers source and prior hosted evidence; the final PR revision still
needs hosted CI and the field-lab workflows before a freeze claim.

## Public-surface and claim-metadata read-through

| Surface | Finding |
| --- | --- |
| Python exports | `bindings/python/api/public-api.txt:64-103` separates attempt storage, execution, and exact command projection; `:185-199` exposes the development conformance kit under `auths.testkit`, not a production gateway. No application-owned provider request or credential is represented as a qualified receipt. |
| TypeScript exports | `bindings/typescript/api/public-api.txt:52-92` exposes the corresponding self-hosted contracts and runner; `:153-161` keeps synthetic conformance in `./testkit`. There is no generic arbitrary HTTP executor in this surface. |
| Installed command | `bindings/python/pyproject.toml:27-28` and `bindings/typescript/package.json:6-8` both install `auths-profile`; neither shadows the Rust `auths` command. |
| SDK metadata | `bindings/python/sdk-capability.json:25-26` and `bindings/typescript/sdk-capability.json:26-27` explicitly describe application-owned credentials and unqualified effects. Publication and promotion remain blocked in those metadata files. |
| User-facing boundary | `bindings/python/README.md:77-82`, `bindings/typescript/README.md:52-57`, and `docs/product/SELF_HOSTED_CLAIM_LEDGER.md:12-23` say that app-held tokens can bypass the voluntarily called runner. `bindings/python/python/auths/execution.py:1-5` attributes provider outcomes and observations to the application. |

No new public SDK symbol was introduced by the acceptance corrections after
`8aa1bed`; the two inventories and capability files need no symbol additions.
This is a manual source-level read-through by the implementation agent, not a
human owner approval or a substitute for the generated-artifact check on the
final commit.

## Acceptance by spec

| Clause | Evidence and disposition |
| --- | --- |
| 0051 packaged CLI, bounded schema, and consumer path | Python and TypeScript profile generators, public inventories, the shared profile vectors, and packed-consumer tests exist. The previous SDK revision passed [Python package](https://github.com/auths-dev/auths-proof/actions/runs/35650010520), [TypeScript package](https://github.com/auths-dev/auths-proof/actions/runs/35650010653), and [installed-artifact recipes](https://github.com/auths-dev/auths-proof/actions/runs/35650010580). Final-revision qualification remains open. |
| 0051 exact-action and bypass claims | `bindings/python/python/auths/execution.py:86-150` orders verification, claim, credential, provider, and observation; `bindings/typescript/src/self-hosted.ts:294-357` does likewise. `bindings/python/tests/test_self_hosted_execution.py` and `bindings/typescript/test/integration/self-hosted.test.js` include the negative demonstration that app-held credentials can bypass those functions. Hosted results for the new tests are pending. |
| 0052 Epics 1–3 | Packaged generation, explicit authority inputs, and conservative attempt/recovery behavior have existing package and local field-lab evidence. The [Airtable record](https://airtable.com/appQD3Qf0YFBCW9bV/tblHscC7D9Kp7hiRw/viw8KMXQZw8bd3XXJ/recc20fysorU22tQT) and [Todoist task](https://app.todoist.com/app/task/6hXqwHHp55rHV23m) were each written once through the demo and independently read back on 2026-09-21. Local live proof does not replace hosted CI. |
| 0052 Epic 4 / 0054 Epic 5 | An independent zero-context agent completed a third-adapter packaged-wheel trial against a local fake inventory provider and reran from a fresh consumer workspace on the corrected hosted wheel. The [redacted report](SELF_HOSTED_THIRD_ADAPTER_TRIAL.md) records the intervention, exact write/read-back, denial, replay, and claim limits. This meets the 0054 engineering trial clause, not a human market-adoption result; 0052's final hosted field-lab gate remains open. |
| 0054 Epic 1 | Nested fields, arrays, bytes, closed enums, lock/version checks, cross-language vectors, and packed-consumer typing are represented in the shared fixtures and package tests. The exact final candidate must pass hosted Python, TypeScript, and native corpus checks. |
| 0054 Epic 2 | The generated adapter keeps `credential`, `invoke`, and `observe` application-owned; Airtable and Todoist retain distinct provider modules. Denial/replay tests establish no runner credential or provider entry. The new token-bypass regression preserves the documented limit. |
| 0054 Epic 3 | `bindings/fixtures/self-hosted-profile/adapter-scenarios-v1.json` owns fourteen mandatory scenario identities. Python and TypeScript kits now check claim/finish failures, restart replay, post-entry interruption, and read-only reconciliation; the CLI rejects missing or duplicate mandatory cases. Deliberately broken adapters are expected to fail. All newly added checks await hosted CI. |
| 0054 Epic 4 | Both CLIs emit stage-specific JSON diagnostics, require versioned schema changes, and distinguish the first unsealed profile from unchanged fields. Python/TypeScript first-run tests cover missing signer, grant, and trust; package tests cover stale generation and typing. The final error matrix is conditional on hosted checks. |
| 0055 enum node | The enum fixture, hostile cases, public inventories, and native projection change landed together in `8aa1bed`; the previous packaged SDK and authoritative CI passed. The spec status is now **Implemented**, with no provider-qualification implication. |

## Remaining gates before PR #123 is ready

1. Pass authoritative and both packaged SDK workflows on one final PR #123
   commit, including the new conformance and diagnostic cases.
2. Pin field-lab to that exact SDK commit and obtain green Airtable and Todoist
   hosted workflows. The private field-lab repository's current payment/
   spending-limit annotation prevents jobs from starting; local live success
   does not close this gate.
3. Have a human owner review the public API inventories and claim metadata;
   this agent read-through does not supply human approval.
4. Update AP-SPEC-051, -052, and -054 tracking/status and the claim ledger
   only to the level established by those artifacts. No part of AP-SPEC-053
   or -056 implementation is a PR #123 prerequisite.
