# 01 — Authenticate an identity

## Outcome

Authenticate exact bytes without creating authority or approval state.

## Before you start

Use a supported Node.js or CPython runtime and install the single Auths package. The executable source below is run against the packed npm artifact and wheel in CI.

## TypeScript

Source: `typescript/01-authenticate-identity.ts`

```typescript
import { createRawKeyEd25519IdentityClient } from "@auths-dev/sdk/identity";
import { createRawKeyEd25519Identity, prepareIdentityMessage } from "@auths-dev/sdk/identity/authoring";

const keys = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
const identity = await createRawKeyEd25519Identity(publicKey);
const message = new TextEncoder().encode("publish weekly report");
const prepared = await prepareIdentityMessage({ identity, message });
const signingBytes = prepared.signingPreimage.slice().buffer as ArrayBuffer;
const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", keys.privateKey, signingBytes));
const client = await createRawKeyEd25519IdentityClient();
try {
  const result = await client.authenticate({ identity, message, signature });
  if (result.kind !== "ok") throw new Error(result.issue.code);
  console.log(JSON.stringify({ recipe: "01-authenticate-identity", outcome: "authenticated" }));
} finally {
  await client.close();
}
```

## Python

Source: `python/01_authenticate_identity.py`

```python
from __future__ import annotations

import asyncio
import json

from auths.identity import IdentityOk, raw_key_ed25519
from auths.identity.authoring import (
    create_raw_key_ed25519_identity,
    prepare_identity_message,
)
from auths.testkit import development_ed25519_identity_key


async def main() -> None:
    key = development_ed25519_identity_key()
    identity = create_raw_key_ed25519_identity(key.public_key)
    message = b"publish weekly report"
    prepared = prepare_identity_message(identity, message=message)
    signature = key.sign(prepared.signing_preimage)
    async with raw_key_ed25519() as client:
        authenticated = await client.authenticate(
            identity, message=message, signature=signature
        )
        changed = await client.authenticate(
            identity, message=b"delete weekly report", signature=signature
        )
    if not isinstance(authenticated, IdentityOk):
        raise RuntimeError(authenticated.issue.code)
    changed_rejected = not isinstance(changed, IdentityOk)
    if not changed_rejected:
        raise RuntimeError("changed message authenticated")
    print(
        json.dumps(
            {
                "recipe": "01-authenticate-identity",
                "outcome": "authenticated",
                "changedRejected": changed_rejected,
            }
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
```

## What Auths protected

The recipe uses Rust-owned canonicalization, commitments, authorization, and receipt/recovery semantics. TypeScript and Python coordinate bounded I/O but cannot mint an effect-capable authorization object.

## Break it safely

The executable includes its failure exercise and asserts that no unauthorized or duplicate provider entry occurs. CI fails if the adversarial result changes.

## Take it to production

Replace the development/test identity adapters with maintained method resolution and custody for your selected signature suite.
