# Customer journey matrix

The machine-readable source is
`bindings/customer-journey-matrix-v1.json`. Rust owns operation and security
meaning; Python and TypeScript project the same local-agent and generated
profile contracts.

| Journey | Semantic owner | TypeScript evidence | Python evidence |
| --- | --- | --- | --- |
| Connect an observed workload without an application token | Local agent/session runtime | `test/contract/profile-runtime.ts` | `tests/test_profile_runtime_v1.py` |
| Execute one typed provider operation | Concrete profile vertical plus generated client | generated Stripe client and launch example | generated Stripe client and launch example |
| Share one session across domains | Local session protocol plus each concrete vertical | generated Stripe, PostgreSQL, and OpenTofu packages | generated Stripe, PostgreSQL, and OpenTofu packages |
| Recover a possible effect without blind retry | Durable journal plus concrete reconciliation | profile-runtime contract and exhaustive outcomes | profile-runtime recovery test and sealed outcomes |
| Verify existing evidence without an effect | Rust verifier | `@auths-dev/sdk/verify` | `auths.verify` |
| Extend the generated package ecosystem | Manifest, generator, and public profile-runtime ABI | `@auths-dev/sdk/profile-runtime` | `auths.profile_runtime` |
| Install one coherent release | Runtime contract, topology, API inventory, and package tests | packed npm consumer | wheel-content and public-API checks |

Provider credentials, arbitrary provider requests, domain policy, and dynamic
runtime callbacks are not application journeys. Provider onboarding uses the
separate privileged administration surface and is documented in the
[local-agent quickstart](../../../docs/product/LOCAL_AGENT_SDK_QUICKSTART.md).

The exact evidence paths, experience budgets, and current qualification state
remain in the machine-readable matrix; repository-local passing checks do not
imply publication or independent review.
