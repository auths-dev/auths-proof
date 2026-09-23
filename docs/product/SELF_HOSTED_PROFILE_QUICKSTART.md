# Build an application-owned adapter

This path lets your application protect one exact MCP-shaped provider action
without waiting for an Auths-maintained profile. Your application still owns
the provider token, request mapping, effect classification, and read-back. It
can bypass its own local Auths check; this is not a credential-isolated gateway
or an Auths-qualified provider integration.

| Claim | Owner |
| --- | --- |
| Canonical action, scoped proof verification, exact typed projection | Auths SDK/native verifier |
| One local attempt claim before credential access when using `run_once`/`runOnce` | Auths runner plus your durable `AttemptStore` |
| Provider URL, request body, idempotency key, response and observation meaning | Your adapter |
| Signed grant, custody key, independent trusted context, rotation | Your operator |
| Provider token and its storage | Your application |

## Python quickstart

Install the Python wheel and initialize a profile in your application repo:

```sh
auths-profile init --language python --name create-task --directory src/create_task
```

Edit `src/create_task/profile.toml`. The closed `[arguments]` schema supports
bounded UTF-8 strings, safe integers, booleans, base64url bytes, bounded
arrays, nested objects, nullable fields, and ordered closed string enums. For
example, `type = "enum"` with `variants = ["open", "closed"]` generates a
Python `Literal` or TypeScript literal union; changing the variant list or
its order changes the schema digest. It does not accept arbitrary
JSON or caller-supplied provider URLs. Then run:

```sh
auths-profile diff src/create_task/profile.toml
auths-profile generate src/create_task/profile.toml
auths-profile check src/create_task/profile.toml
```

`generated.py` is the typed command and `CONTRACT`; `adapter.py` is an
application-owned starter for `credential`, `invoke`, and `observe`; `run.py`
calls the verifier and one-use runner; `conformance.py` is a deliberately
unwired fake-provider starter. `init` does not seal `profile.lock.json`:
the first `generate` creates it after your template edit. Every later schema
or identity change requires a version bump. Implement the adapter port, then wire a fake
provider to it in `conformance.py`. Its `run()` function can be invoked with:

```sh
auths-profile test src/create_task/profile.toml --suite create_task.conformance:run
```

The suite checks local ordering, denial, replay, uncertain effects, and
read-only observation without a provider token. It does not qualify live
provider semantics. The CLI finds a suite module in the profile's adjacent
Python package without a `PYTHONPATH` workaround. The [Airtable and Todoist demos](https://github.com/auths-dev/auths-field-lab)
show complete Python adapters and the same conformance kit.

For real use, construct the generated command and obtain **three independent
Auths inputs**: a custody signer, a scoped signed grant chain, and a trusted
context provisioned outside the application. Pass those to
`auths.authoring.author_mcp_proof`; use the resulting proof and action with
the operator's trusted context in generated `run.execute`. Supply an
application-owned durable `AttemptStore`, unique logical operation key, and
adapter that loads the provider credential only from `credential()`. A
provider PAT is not an Auths grant or trust anchor. `auths.testkit` can create
disposable self-trusting fixtures for local learning only.

The runner returns separate authorization, provider outcome, and observation
fields. A timeout, ambiguous response, or crash after possible provider
entry is `unknown`: observe or reconcile read-only, never blindly retry.
`ProviderRejected` means the adapter can establish that no effect occurred.
`ProviderAccepted` does not by itself mean the effect was observed.

## TypeScript quickstart

With `@auths-dev/sdk` installed in a Node/TypeScript application:

```sh
auths-profile init --language typescript --name create-task --directory src/create-task
auths-profile diff src/create-task/profile.toml
auths-profile generate src/create-task/profile.toml
auths-profile check src/create-task/profile.toml
```

The generated `generated.ts` exports a `CommandOf` type and exact `CONTRACT`.
Implement `ApplicationAdapter` in `adapter.ts`; `run.ts` calls `runOnce` with
the proof, action, operator trusted context, attempt store, logical operation
key, and adapter. Author proof bytes with `authorMcpProof` using an existing
`CustodySigner`, signed grants, and trusted-context template. The provider
token stays in your adapter and is not read by Auths verification. Wire a
synthetic provider in `conformance.ts`, compile it, then run:

```sh
auths-profile test src/create-task/profile.toml --suite dist/create-task/conformance.js
```

The TypeScript kit takes explicit local proof/action/context artifacts; the
starter leaves those values empty until you supply a valid local fixture. An
empty or unwired starter must fail. Neither language's `init` or `doctor`
creates production authority or authenticates to the provider.

## Version changes and diagnostics

`profile.lock.json` records the normalized schema, digest, version, and
versioned tool name. `profile diff` identifies changed field paths and whether
the action identity changes. A schema or identity edit at the same version is
rejected by `generate`; increment `profile.version`, review the diff, then
regenerate and review the new proof identity. This is a direct prelaunch
cutover, not a compatibility shim.

Every profile command accepts `--json` for a bounded
`auths.profile-diagnostic/1` result with `code`, `stage`, `message`, and
`next_action`. Common codes:

| Code | Meaning / next action |
| --- | --- |
| `profile.contract.schema-invalid` | Correct the closed bounded schema. |
| `self-hosted.enum-variant-undeclared` | The selected value is not an exact declared variant; change the command or versioned schema. |
| `profile.contract.version-required` | Bump the version before regenerating a changed identity/schema. |
| `profile.generated.stale` | Review the source/version, then regenerate. |
| `profile.authority.signer-missing` | Supply a custody signer adapter; a provider token is unrelated. |
| `profile.authority.grant-missing` | Supply the signed grant chain. |
| `profile.trust.context-missing` | Supply independently provisioned trust. |
| `profile.provider.adapter-test-failed` | Wire and inspect the fake-provider adapter tests. |
| `profile.contract.derived-edited` | A file written by `derive` no longer matches `derivation.json`; re-derive, or delete `derivation.json` to own the files by hand. |
| `contract.derive.*` | `derive` rejected the document or a flag; the message names the JSON pointer and the flag that resolves it, if one exists. |

`auths-profile doctor --production` checks the signer identifier and bounded,
distinct local authority files. Python parses the grant and trusted-context
bytes; TypeScript checks file presence and bounds but does not parse their
bytes. Neither can infer trust provenance, signer connectivity, provider-token
validity, or live provider behavior. The CLI does not silently fall back to
testkit authority.

## Deriving a gateway operation from OpenAPI

For the credential-isolated gateway path, `auths-profile derive` can write the
contract and its request recipe from one operation in a local OpenAPI 3.0 or
3.1 JSON document. It reads no network and no credential:

```text
auths-profile derive --openapi ./vendor/api.json --operation create_task \
  --service todoist-gateway-demo --name todoist-task-create \
  --operator-namespace todoist-demo --security-scheme bearer --closed . \
  --max-bytes content=256 --omit description --directory ./todoist
auths-profile generate ./todoist/profile.toml
auths gateway recipe check --recipe ./todoist/recipe.json --profile-lock ./todoist/profile.lock.json
```

It writes `profile.toml`, `recipe.json`, and `derivation.json`, the last of
which records the document digest and every flag used. Any construct the
restricted schema or the recipe compiler cannot express is rejected. Each
rejection gives a JSON pointer and the flag that resolves it, if one exists.
The command never guesses a bound, server, or credential scheme. `profile
check` reports a derived file that was edited by hand. Changing the document
or a flag requires a `--version` bump. The derived recipe claims only the
request shape; provider effect remains unqualified. The Python and TypeScript
commands call the same native mapper and write identical bytes.
