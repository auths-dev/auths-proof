from __future__ import annotations

import asyncio

import pytest

from auths.identity import IdentityOk, authenticate_message, raw_key_ed25519
from auths.identity.authoring import (
    create_raw_key_ed25519_identity,
    prepare_identity_message,
)
from auths.testkit import development_ed25519_identity_key


@pytest.mark.parametrize("seed", [None, bytes([31]) * 32])
def test_authored_raw_key_identity_uses_the_canonical_descriptor_preimage(
    seed: bytes | None,
) -> None:
    async def scenario() -> None:
        key = development_ed25519_identity_key(seed)
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
        packet_result = await authenticate_message(
            identity.to_bytes(), message=message, signature=signature,
        )
        assert isinstance(packet_result, IdentityOk)
        assert packet_result.value.identity.identity_id == identity.identity_id

    asyncio.run(scenario())


@pytest.mark.parametrize("seed", [b"", bytes(31), bytes(33), bytearray(32), "x" * 32])
def test_development_recipient_seed_refuses_invalid_import(seed: object) -> None:
    with pytest.raises(ValueError, match="must be 32 bytes"):
        development_ed25519_identity_key(seed)  # type: ignore[arg-type]
