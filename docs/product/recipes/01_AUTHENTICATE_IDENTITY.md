# 01 — Authenticate an identity

## Outcome

Authenticate exact bytes without creating authority or approval state.

## Before you start

Use a supported Node.js or CPython runtime and install the single Auths package. The executable source below is run against the packed npm artifact and wheel in CI.

## TypeScript

Source: `typescript/01-authenticate-identity.ts`

```typescript
import {
  loadEd25519RawKeyAuthentication,
  loadIdentity,
  loadRawKeyIdentityAdapter,
} from "@auths-dev/sdk/identity";

const message = new TextEncoder().encode("publish weekly report");
const keys = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
const identity = await loadIdentity();
const method = await loadRawKeyIdentityAdapter();
const suite = await loadEd25519RawKeyAuthentication();
const sent = method.create("ed25519-v1", publicKey);
const received = identity.parseIdentity(identity.decodePublicIdentity(sent.packet), method);
const preimage = identity.signingPreimage(received, message);
const signingBytes = new Uint8Array(preimage.length);
signingBytes.set(preimage);
const signature = new Uint8Array(await crypto.subtle.sign(
  "Ed25519",
  keys.privateKey,
  signingBytes.buffer,
));
const authenticated = identity.authenticate(
  identity.decodeSignedMessage(identity.encodeSignedMessage(received, message, signature)),
  received,
  suite,
);
let changedRejected = false;
try {
  const changed = new TextEncoder().encode("delete weekly report");
  identity.authenticate(
    identity.decodeSignedMessage(identity.encodeSignedMessage(received, changed, signature)),
    received,
    suite,
  );
} catch {
  changedRejected = true;
}
if (!changedRejected) throw new Error("changed message authenticated");
console.log(JSON.stringify({ recipe: "01-authenticate-identity", outcome: "authenticated", changedRejected }));
```

## Python

Source: `python/01_authenticate_identity.py`

```python
from __future__ import annotations

import asyncio
import json

from auths.identity import (
    IdentityRegistry,
    VerificationMaterial,
    VerificationRelationship,
    decode_identity,
    encode_identity,
)
from auths.testkit import DevelopmentIdentityMethod, DevelopmentSignatureSuite


async def main() -> None:
    relationship = VerificationRelationship(
        "default-signing",
        "authentication",
        "auths.test-signature",
        (VerificationMaterial("credential", b"public-development-material"),),
    )
    packet = encode_identity(
        "auths.test-identity",
        "identity:example:alice",
        relationships=(relationship,),
    )
    registry = IdentityRegistry(
        methods=[DevelopmentIdentityMethod()],
        suites=[DevelopmentSignatureSuite()],
    )
    validated = await decode_identity(packet).validate(registry)
    await validated.authenticate(
        b"publish weekly report", b"auths-development-signature", registry
    )
    changed_rejected = False
    try:
        await validated.authenticate(
            b"delete weekly report", b"changed-signature", registry
        )
    except ValueError:
        changed_rejected = True
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
