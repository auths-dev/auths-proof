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
