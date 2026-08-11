from __future__ import annotations

from auths import PrincipalDescriptor, SigningRequest, SigningResponse
from auths.testkit import DevelopmentEd25519Signer


class ProcessEd25519Signer:
    kind = "auths-incident-process-ed25519"
    lifecycle = "durable"

    def __init__(self) -> None:
        self._signer = DevelopmentEd25519Signer()

    async def public_identity(self) -> PrincipalDescriptor:
        return await self._signer.public_identity()

    async def sign(self, request: SigningRequest) -> SigningResponse:
        return await self._signer.sign(request)

    async def aclose(self) -> None:
        return None


__all__ = ["ProcessEd25519Signer"]
