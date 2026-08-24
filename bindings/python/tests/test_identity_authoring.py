from __future__ import annotations

import asyncio

from auths.identity import IdentityOk, raw_key_ed25519
from auths.identity.authoring import (
    create_raw_key_ed25519_identity,
    prepare_identity_message,
)
from auths.testkit import development_ed25519_identity_key


def test_authored_raw_key_identity_uses_the_canonical_descriptor_preimage() -> None:
    async def scenario() -> None:
        key = development_ed25519_identity_key()
        identity = create_raw_key_ed25519_identity(key.public_key)
        assert identity.method_id == "raw-key-v2"
        assert identity.identity_id.startswith("key:sha256-v2:")
        message = b"canonical identity authoring"
        prepared = prepare_identity_message(identity, message=message)
        signature = key.sign(prepared.signing_preimage)

        async with raw_key_ed25519() as client:
            authenticated = await client.authenticate(
                identity,
                message=message,
                signature=signature,
            )
            changed = await client.authenticate(
                identity,
                message=b"changed identity authoring",
                signature=signature,
            )

        assert isinstance(authenticated, IdentityOk)
        assert not isinstance(changed, IdentityOk)

    asyncio.run(scenario())
