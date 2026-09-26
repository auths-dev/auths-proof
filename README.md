# Auths

Auths lets an AI agent act only with authority you can check. An action goes
through only if it matches exactly what the right people approved and stays
within the agent's own limits. A gateway holds the provider credential, so the
agent never sees it. Afterwards, an auditor can re-verify each action offline.

This repository is prelaunch and has not had an independent security review.
See [Status](#status).

## See it work

Your agent may refund a Stripe payment only when two of your three managers
approve that exact refund, and only up to 50.00 per refund and two refunds a
day. The Stripe key lives only in the gateway, and an auditor checks every
refund offline. You need Python 3.9+, Rust, and a checkout of this repository.

```sh
cd examples/stripe-refund-approval
python3 -m venv .venv && . .venv/bin/activate
pip install maturin
maturin build --profile python-extension --manifest-path ../../bindings/python/Cargo.toml --out dist
pip install dist/auths-*.whl
cargo install --locked --path ../../product/runtime/auths-gateway --features loopback-provider
python journey.py --gateway "$(command -v auths-gateway)"
```

The first build takes a few minutes. The journey then runs in a few seconds
against a local Stripe double, and never calls Stripe. It checks each of these:

| Attempt | Result | Stripe calls |
| --- | --- | --- |
| A 15.00 refund approved by managers A and B, and a 40.00 refund approved by B and C | submitted | 2 |
| A 90.00 refund, above the agent's 50.00 limit | refused | 0 |
| A refund only manager A approved | refused | 0 |
| A third refund on the same day | refused | 0 |
| Four tampered audit bundles: a flipped proof byte, a swapped action, a replayed outcome, and replaced trust | the offline audit flags each | none |

Each refusal happens before the gateway touches the Stripe key. CI runs the
same journey from the packaged wheel.

[The example's README](examples/stripe-refund-approval/README.md) walks through
the run in 10 steps, and shows how to run it against Stripe test mode with your
own test key.

## What you get

- **Approval of the exact action.** Approvers sign the exact request (this
  refund, this amount, this payment), not a permission scope. A plan can
  require K of N approvers.
- **Limits per agent.** The agent's grant carries its limits, such as a maximum
  refund and a number per day, and the gateway enforces them. Delegation can
  narrow authority but never widen it.
- **The credential stays in the gateway.** The gateway verifies the proof and
  checks the limits before it uses the provider credential. The agent never
  holds the credential.
- **Offline audit.** `auths-gateway audit` re-verifies each action in an
  exported bundle, with no network, and flags tampering. It cannot show that no
  action was left out of the bundle.
- **Checked independently.** A Rust verifier and independent Go and TypeScript
  verifiers agree on a shared corpus of test vectors. Lean proofs cover the
  delegation ordering and the K-of-N approval algebra, not the whole verifier.

## What it does not claim yet

- The example uses development keys and a Stripe double. No provider route is
  qualified for production; the Stripe test-mode run is one you do yourself.
- No independent security review has been done.
- The gateway's default store is single-host. A PostgreSQL store lets several
  gateways share state, but its production review is not finished.

The [claim ledger](docs/product/SELF_HOSTED_CLAIM_LEDGER.md) states what each
part establishes and what it does not.

## Other ways in

| To… | Start with |
| --- | --- |
| Require approvals from K of N people | [Approval quorum](docs/product/APPROVAL_QUORUM.md) |
| Verify a proof or authenticate an identity from Python or TypeScript | [Recipes](docs/product/recipes/README.md) |
| Put another HTTP API behind the gateway | The example's [`recipe.json`](examples/stripe-refund-approval/recipe.json) and the [gateway specification](docs/specs/0053-declarative-credential-isolated-gateway.md) |
| Derive gateway operations from an OpenAPI document | [OpenAPI-derived operations](docs/specs/0056-openapi-derived-operation-contracts.md) |
| Protect one action in your own application, without a gateway | [Application-owned adapter](docs/product/SELF_HOSTED_PROFILE_QUICKSTART.md) |
| Write a profile for a new provider | [Profile authoring](docs/product/PROFILE_AUTHORING.md) |
| Use the typed application SDK through a local agent (no live provider route is promoted yet) | [SDK contract](docs/product/PRODUCTION_SDK_QUICKSTART.md), then the [local-agent guide](docs/product/LOCAL_AGENT_SDK_QUICKSTART.md) |
| Sign Git commits under any principal method, or run the gateway with production trust | [Git object signing](docs/specs/0058-git-object-signing-under-any-principal-method.md) and the [trust and signing runbook](docs/operations/GATEWAY_TRUST_AND_GIT_SIGNING_RUNBOOK.md) |

Package documentation: [Python](bindings/python/README.md) and
[TypeScript](bindings/typescript/README.md).

## How it fits together

This is one monorepo in five layers. A layer may depend only on itself and the
layers above it in this table; [`architecture.toml`](architecture.toml)
enforces that.

| Layer | Holds |
| --- | --- |
| `core/` | The offline verification kernel: protocol model, canonical encoding, signatures, delegation, verification, and the canonical test corpus |
| `exchange/` | Moving proofs between parties: formats and transports |
| `product/` | The gateway, SDK runtimes, stores, custody, and provider integrations |
| `bindings/` | Python, TypeScript, WASM, and Go surfaces, and the independent verifiers |
| `demos/` | Demos, test kits, and benchmarks |

The kernel checks a proof in fixed stages, and `VerifiedAction` has no public
constructor:

```text
untrusted bytes
  -> DecodedProof
  -> ResolvedProof
  -> ControlVerifiedProof
  -> VerifiedAuthority
  -> VerifiedAction
```

The language-neutral entry point is
`verify_v1(proof_cbor, canonical_action_cbor, trusted_context_cbor) -> verification_result_cbor`.
The kernel reads no clock, environment variable, network, filesystem, or key.
Every trust anchor, evaluation time, status snapshot, policy, and limit is an
explicit input. To try it, run `cargo run -p auths-proof-offline-example`.

Identity packets and Iroh transport also work without any authorization layer:
run `cargo run -p auths-identity-iroh-demo`, then open `http://localhost:8080`.

## Develop

Read [`AGENTS.md`](AGENTS.md), the repository contract, before changing code,
then [`CONTRIBUTING.md`](CONTRIBUTING.md). The
[program board](docs/PROGRAM_BOARD.md) shows current status and what is next.

```sh
cargo xtask arch          # layer and dependency rules
cargo xtask wire          # the canonical corpus is byte-stable
cargo xtask conformance
cargo xtask fuzz-smoke
cargo xtask ci            # the authoritative gate
```

Canonical `.cbor` fixtures change only through `cargo xtask wire --update`, for
an intentional, reviewed protocol change.

## Status

Prelaunch: there are no external users yet, and no independent security review
has been done. Passing the corpus, fuzz, and WASM-equivalence checks is not
such a review. Report suspected vulnerabilities privately, as described in
[`SECURITY.md`](SECURITY.md).

## License

[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
