# Customer journey matrix

The machine-readable source is
`bindings/customer-journey-matrix-v1.json`. Rust owns operation and security
meaning; Python and TypeScript project the same gateway, self-hosted, and
verification contracts.

| Journey | Semantic owner | TypeScript evidence | Python evidence |
| --- | --- | --- | --- |
| Submit one exact authorized write without an app provider credential | Gateway engine | `test/unit/gateway-client.test.js` | `tests/test_gateway_client.py` |
| Verify a gateway-signed outcome and refuse a retired schema | Gateway outcome signer plus Rust verifier | `test/integration/gateway-outcome-v2.test.js` | `tests/test_gateway_outcome_v2.py` |
| Require a threshold of named approvers for one exact action | Approval-quorum authoring and the Rust verifier | `test/integration/approval-quorum.test.js` | `tests/test_approval_quorum.py` |
| Run one application-owned exact MCP operation | MCP profile plus self-hosted runner | `test/integration/self-hosted.test.js` | `tests/test_self_hosted_execution.py` |
| Verify existing evidence without an effect | Rust verifier | `@auths-dev/sdk/verify` | `auths.verify` |
| Install one coherent release | Runtime contract, topology, API inventory, and package tests | packed npm consumer | wheel-content and public-API checks |

Provider credentials, arbitrary provider requests, domain policy, and dynamic
runtime callbacks are not application journeys. Provider credentials are
bound to gateway connections by the operator.

The exact evidence paths, experience budgets, and current qualification state
remain in the machine-readable matrix; repository-local passing checks do not
imply publication or independent review.
