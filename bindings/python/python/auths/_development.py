from __future__ import annotations

from typing import Optional

from . import _native as native
from .custody import (
    ControlEvidence,
    PrincipalDescriptor,
    Signer,
    SignerLifecycle,
    SigningRequest,
    SigningResponse,
)
from .receipts import ReceiptSigner


class DevelopmentEd25519Signer(Signer):
    kind = "auths-development-ed25519"
    lifecycle: SignerLifecycle = "ephemeral"

    def __init__(self, seed: Optional[bytes] = None) -> None:
        self._key = (
            native.DevelopmentEd25519Key.generate()
            if seed is None
            else native.DevelopmentEd25519Key.from_seed(bytes(seed))
        )
        principal = native.Principal(self._key.principal)
        self._descriptor = PrincipalDescriptor(
            principal,
            self._key.principal_method,
            self._key.verification_method,
            self._key.suite,
        )
        self.closed = False

    async def public_identity(self) -> PrincipalDescriptor:
        self._assert_active()
        return self._descriptor

    async def sign(self, request: SigningRequest) -> SigningResponse:
        self._assert_active()
        return SigningResponse(
            request.request_id,
            request.principal,
            request.transaction_digest,
            bytes(self._key.sign(request.signing_preimage)),
            (
                ControlEvidence(
                    self._key.evidence_type,
                    self._key.media_type,
                    bytes(self._key.evidence),
                ),
            ),
        )

    async def aclose(self) -> None:
        self.closed = True

    def _assert_active(self) -> None:
        if self.closed:
            raise RuntimeError("development signer is closed")


class DevelopmentReceiptAttestor:
    def __init__(self) -> None:
        self._key = native.DevelopmentEd25519Key.generate()
        self.signer = ReceiptSigner(
            self._key.principal,
            self._key.verification_method,
            self._key.suite,
            bytes(self._key.evidence),
        )

    async def sign(self, preimage: bytes) -> bytes:
        return bytes(self._key.sign(preimage))


__all__ = ["DevelopmentEd25519Signer", "DevelopmentReceiptAttestor"]
