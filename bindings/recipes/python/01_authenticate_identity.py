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
