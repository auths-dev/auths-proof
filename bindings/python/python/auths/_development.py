from __future__ import annotations

from typing import Optional

from . import _native as native
from ._custody import (
    ControlEvidence,
    PrincipalDescriptor,
    Signer,
    SignerLifecycle,
    SigningRequest,
    SigningResponse,
)
from ._receipts import ReceiptSigner


class DevelopmentEd25519Signer(Signer):
    kind = "auths-development-ed25519"
    lifecycle: SignerLifecycle = "ephemeral"

    def __init__(self, seed: Optional[bytes] = None) -> None:
        key = (
            native.DevelopmentEd25519Key.generate()
            if seed is None
            else native.DevelopmentEd25519Key.from_seed(bytes(seed))
        )
        self._key: Optional[native.DevelopmentEd25519Key] = key
        principal = native.Principal(key.principal)
        self._descriptor = PrincipalDescriptor(
            principal,
            key.principal_method,
            key.verification_method,
            key.suite,
        )
        self.closed = False

    async def public_identity(self) -> PrincipalDescriptor:
        self._assert_active()
        return self._descriptor

    async def sign(self, request: SigningRequest) -> SigningResponse:
        key = self._active_key()
        return SigningResponse(
            request.request_id,
            request.principal,
            request.transaction_digest,
            bytes(key.sign(request.signing_preimage)),
            (
                ControlEvidence(
                    key.evidence_type,
                    key.media_type,
                    bytes(key.evidence),
                ),
            ),
        )

    async def aclose(self) -> None:
        self._key = None
        self.closed = True

    def _active_key(self) -> native.DevelopmentEd25519Key:
        if self._key is None:
            raise RuntimeError("development signer is closed")
        return self._key

    def _assert_active(self) -> None:
        self._active_key()


class DevelopmentReceiptAttestor:
    def __init__(self, seed: Optional[bytes] = None) -> None:
        key = (
            native.DevelopmentEd25519Key.generate()
            if seed is None
            else native.DevelopmentEd25519Key.from_seed(bytes(seed))
        )
        self._key: Optional[native.DevelopmentEd25519Key] = key
        self.signer = ReceiptSigner(
            key.principal,
            key.verification_method,
            key.suite,
            bytes(key.evidence),
        )

    async def sign(self, preimage: bytes) -> bytes:
        if self._key is None:
            raise RuntimeError("development receipt attestor is closed")
        return bytes(self._key.sign(preimage))

    async def aclose(self) -> None:
        self._key = None


__all__ = ["DevelopmentEd25519Signer", "DevelopmentReceiptAttestor"]
