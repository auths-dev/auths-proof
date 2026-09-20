# Self-hosted exact MCP operation

This path is for an application that already has a provider credential and
will implement its own provider request. Auths verifies and projects one exact
`auths.mcp/v2` action under an independently supplied trusted context. It does
**not** hold the provider token, sandbox the application, qualify the HTTP
adapter, or attest that the provider accepted the effect. Application code
holding the token can bypass this local gate; a credential-owning qualified
Auths vertical is required for non-bypassable enforcement.

The signer, signed grant chain, and trusted context are separate operator
inputs. Neither SDK silently creates production authority. The `auths.testkit`
fixture helper is only for disposable local demonstrations where the test
process trusts a key it created itself.

## Python: define and verify a closed command

```python
from dataclasses import dataclass

from auths.self_hosted import (
    AuthorizedCommand,
    ExactMcpTool,
    StringField,
    verify_command,
)


@dataclass(frozen=True)
class CreateTask:
    content: str
    command_uuid: str


TOOL = ExactMcpTool(
    service="todoist",
    name="create_task",
    command_type=CreateTask,
    fields={
        "content": StringField(min_length=1, max_length=120),
        "command_uuid": StringField(min_length=36, max_length=36),
    },
)

# These bytes are supplied by an operator, not inferred from the Todoist PAT.
verdict = verify_command(
    contract=TOOL,
    proof=operator_proof,
    action=operator_action,
    trusted_context=operator_trusted_context,
)
if not isinstance(verdict, AuthorizedCommand):
    raise PermissionError(f"{verdict.kind}: {verdict.code}")

command: CreateTask = verdict.command
```

For production authoring, use `auths.authoring.author_mcp_proof` with a
`GrantEvidence` chain, an operator-provisioned trusted-context template, and
an `auths.adapters.custody.CustodySigner`. It previews the native canonical
action before asking the signer, assembles portable proof bytes, and checks
the result against the bound context. A provider credential is not a signing
grant or trust anchor.

The SDK's `FileAttemptStore` is a POSIX, local-filesystem, single-host
reference mechanism. Claim the verified action commitment and logical
operation key **before** loading a credential or entering the provider:

```python
from pathlib import Path

from auths.attempts import FileAttemptStore

attempts = FileAttemptStore(Path("./private-attempts"))
if not attempts.claim_once(verdict.action_commitment, command.command_uuid):
    raise RuntimeError("operation already claimed; do not retry the write")

try:
    # Application-owned: load the provider token and construct the exact call.
    result = await create_task_with_your_todoist_adapter(command)
except KnownProviderRejection:
    attempts.finish(verdict.action_commitment, "rejected")
except Exception:
    attempts.finish(verdict.action_commitment, "unknown")
    raise  # Observe/reconcile; do not blindly send the write again.
else:
    attempts.finish(verdict.action_commitment, "confirmed")
```

An unfinished `attempting` record after a crash is not permission to retry.
After the original process has stopped, `recover(commitment)` marks it
`unknown`. The file store is not suitable for NFS or multiple hosts. Even a
`confirmed` local record means only that the application classified the
provider response; it is not an Auths execution receipt.

## TypeScript: the same separation

```ts
import {
  authorMcpProof,
  exactMcpTool,
  stringField,
  verifyCommand,
} from "@auths-dev/sdk/self-hosted";

const tool = exactMcpTool({
  service: "todoist",
  name: "create_task",
  fields: {
    content: stringField({ minBytes: 1, maxBytes: 120 }),
    command_uuid: stringField({ minBytes: 36, maxBytes: 36 }),
  },
});

const authored = await authorMcpProof({
  contract: tool,
  command: { content: "Review budget", command_uuid: runId },
  grants: operatorGrants,
  trustedContextTemplate: operatorContextTemplate,
  signer: operatorCustodySigner,
  challenge,
  evaluationTime: BigInt(Math.floor(Date.now() / 1000)),
});

const result = await verifyCommand({
  contract: tool,
  proof: authored.proof,
  action: authored.action,
  trustedContext: authored.trustedContext,
});
if (result.kind !== "authorized") throw new Error(`${result.kind}: ${result.code}`);

// The application owns its AttemptStore, credential access, provider mapping,
// response classification, and observation. No SDK method performs the call.
```

The Python and TypeScript test suites use the same Rust-owned MCP action and
verifier semantics. The [Airtable and Todoist field-lab
demos](https://github.com/auths-dev/auths-field-lab) are local-only consumer
examples; their provider mappings and observations are application claims,
not qualified Auths effects.
