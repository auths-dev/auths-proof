from __future__ import annotations

import asyncio

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
    authenticated = await validated.authenticate(
        b"publish report",
        b"auths-development-signature",
        registry,
    )
    print(authenticated.identity_id)


if __name__ == "__main__":
    asyncio.run(main())
