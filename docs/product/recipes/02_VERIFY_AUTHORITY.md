# 02 — Verify existing authority

## Outcome

Verify existing proof, action, and trust bytes without gaining an execution capability.

## Before you start

Use a supported Node.js or CPython runtime and install the single Auths package. The executable source below is run against the packed npm artifact and wheel in CI.

This recipe reads a signed proof, its exact action and verification settings describing which signing identities you accept. Put them in one directory as `workflow.proof.cbor`, `workflow.action.cbor` and `workflow.context.cbor`, and set `AUTHS_RECIPE_FIXTURE` to that directory.

For a disposable example, run this with the installed Python package. It generates its own in-memory signing key and public test artifacts; it needs no checkout, provider credential or downloaded fixture. The generated context trusts that disposable key only and is not production trust.

```python
from pathlib import Path
from auths.testkit import development_mcp_artifacts

artifacts = development_mcp_artifacts(
    service="recipe-demo", name="publish_report", arguments={"report": "weekly"}
)
directory = Path("auths-demo-evidence")
directory.mkdir(exist_ok=True)
for name, data in [
    ("proof", artifacts.proof),
    ("action", artifacts.action),
    ("context", artifacts.trusted_context),
]:
    (directory / ("workflow." + name + ".cbor")).write_bytes(data)
```

Save the verification program below as `verify_authority.py` or compile the TypeScript program, then run:

```sh
AUTHS_RECIPE_FIXTURE="$PWD/auths-demo-evidence" python verify_authority.py
AUTHS_RECIPE_FIXTURE="$PWD/auths-demo-evidence" node verify_authority.js
```

## TypeScript

Source: `typescript/02-verify-authority.ts`

```typescript
import { readFile } from "node:fs/promises";
import { createVerifier } from "@auths-dev/sdk/verify";

const fixture = process.env.AUTHS_RECIPE_FIXTURE;
if (fixture === undefined) throw new Error("Set AUTHS_RECIPE_FIXTURE to the directory containing workflow.proof.cbor, workflow.action.cbor and workflow.context.cbor; see the recipe setup instructions.");
const [proof, action, trustedContext] = await Promise.all([
  readFile(`${fixture}/workflow.proof.cbor`),
  readFile(`${fixture}/workflow.action.cbor`),
  readFile(`${fixture}/workflow.context.cbor`),
]);
const verifier = await createVerifier();
const result = verifier.verify({ proof: new Uint8Array(proof), action: new Uint8Array(action), trustedContext: new Uint8Array(trustedContext) });
if (result.kind !== "authorized") throw new Error(result.code);
console.log(JSON.stringify({ recipe: "02-verify-authority", outcome: result.kind }));
```

## Python

Source: `python/02_verify_authority.py`

```python
from __future__ import annotations

import json
import os
from pathlib import Path

from auths.verify import VerificationInput, verify


fixture = os.environ.get("AUTHS_RECIPE_FIXTURE")
if not fixture:
    raise SystemExit(
        "Set AUTHS_RECIPE_FIXTURE to the directory containing workflow.proof.cbor, "
        "workflow.action.cbor and workflow.context.cbor; "
        "see docs/product/recipes/02_VERIFY_AUTHORITY.md for a disposable example."
    )
root = Path(fixture)
proof = (root / "workflow.proof.cbor").read_bytes()
action = (root / "workflow.action.cbor").read_bytes()
context = (root / "workflow.context.cbor").read_bytes()
verified = verify(
    VerificationInput(proof=proof, action=action, trusted_context=context)
)
if verified.kind != "authorized":
    raise RuntimeError(f"unexpected verdict: {verified.kind}")
changed = bytearray(action)
changed[-1] ^= 1
try:
    changed_rejected = verify(
        VerificationInput(
            proof=proof, action=bytes(changed), trusted_context=context
        )
    ).kind != "authorized"
except (TypeError, ValueError):
    changed_rejected = True
if not changed_rejected:
    raise RuntimeError("mutated action remained authorized")
print(
    json.dumps(
        {
            "recipe": "02-verify-authority",
            "outcome": verified.kind,
            "changedRejected": changed_rejected,
        }
    )
)
```

## What Auths protected

The native Rust verifier checks the supplied proof against the exact action and your explicit verification settings. An authorized result is an offline verification result; it acquires no credential and performs no provider write.

## Break it safely

The Python example changes one action byte and requires authorization to fail. The trust context is an explicit input; do not replace governed production trust with a self-trusting test context.

## Take it to production

Load the verification context from your governed trust source and retain the exact profile/semantic versions used by issued evidence.
