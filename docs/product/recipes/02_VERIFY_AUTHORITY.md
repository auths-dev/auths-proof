# 02 — Verify existing authority

## Outcome

Verify existing proof, action, and trust bytes without gaining an execution capability.

## Before you start

Use a supported Node.js or CPython runtime and install the single Auths package. The executable source below is run against the packed npm artifact and wheel in CI.

## TypeScript

Source: `typescript/02-verify-authority.ts`

```typescript
import { readFile } from "node:fs/promises";
import { loadVerifier } from "@auths-dev/sdk/verify";

const fixture = process.env.AUTHS_RECIPE_FIXTURE;
if (fixture === undefined) throw new Error("AUTHS_RECIPE_FIXTURE is required");
const [proof, action, context] = await Promise.all([
  readFile(`${fixture}/workflow.proof.cbor`),
  readFile(`${fixture}/workflow.action.cbor`),
  readFile(`${fixture}/workflow.context.cbor`),
]);
const verifier = await loadVerifier();
const verified = verifier.verify(proof, action, context);
if (verified.kind !== "authorized") throw new Error(`unexpected verdict: ${verified.kind}`);
const changed = action.slice();
changed[changed.length - 1] ^= 1;
let changedRejected = false;
try {
  changedRejected = verifier.verify(proof, changed, context).kind !== "authorized";
} catch {
  changedRejected = true;
}
if (!changedRejected) throw new Error("mutated action remained authorized");
console.log(JSON.stringify({ recipe: "02-verify-authority", outcome: verified.kind, changedRejected }));
```

## Python

Source: `python/02_verify_authority.py`

```python
from __future__ import annotations

import json
import os
from pathlib import Path

from auths.verify import verify


root = Path(os.environ["AUTHS_RECIPE_FIXTURE"])
proof = (root / "workflow.proof.cbor").read_bytes()
action = (root / "workflow.action.cbor").read_bytes()
context = (root / "workflow.context.cbor").read_bytes()
verified = verify(proof, action, context)
if verified.kind != "authorized":
    raise RuntimeError(f"unexpected verdict: {verified.kind}")
changed = bytearray(action)
changed[-1] ^= 1
try:
    changed_rejected = verify(proof, bytes(changed), context).kind != "authorized"
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

The recipe uses Rust-owned canonicalization, commitments, authorization, and receipt/recovery semantics. TypeScript and Python coordinate bounded I/O but cannot mint an effect-capable authorization object.

## Break it safely

The executable includes its failure exercise and asserts that no unauthorized or duplicate provider entry occurs. CI fails if the adversarial result changes.

## Take it to production

Load trusted context from your governed trust source and retain the exact profile/semantic versions used by issued evidence.
