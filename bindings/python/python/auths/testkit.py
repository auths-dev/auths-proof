"""Deterministic development adapters and executable port checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable, Generic, TypeVar

from . import _native as native
from .approvals import (
    ApprovalDecision,
    ApprovalProvider,
    ApprovalRequest,
    ApprovalResponse,
)
from .custody import (
    ControlEvidence,
    PrincipalDescriptor,
    Signer,
    SignerLifecycle,
    SigningRequest,
    SigningResponse,
)
from .identity import (
    DecodedIdentity,
    IdentityMethod,
    ResolutionEvidence,
    ResolvedIdentity,
    ResolvedIdentityRecord,
    VerificationMaterial,
)
from .observability import AuthsEvent
from .receipts import ReceiptSigner

ADAPTER_CONTRACT_VERSION = 1


class DevelopmentApproval(ApprovalProvider):
    def __init__(self, decision: ApprovalDecision = "approved") -> None:
        self.decision: ApprovalDecision = decision
        self.requests: list[ApprovalRequest] = []

    async def approve(self, request: ApprovalRequest) -> ApprovalResponse:
        self.requests.append(request)
        return ApprovalResponse(
            request.request_id,
            request.transaction_digest,
            request.policy,
            self.decision,
        )


class DevelopmentSigner(Signer):
    kind = "auths.testkit.development-signer"
    lifecycle: SignerLifecycle = "durable"

    def __init__(
        self, principal: PrincipalDescriptor, *, signature_byte: int = 7
    ) -> None:
        if not 0 <= signature_byte <= 255:
            raise ValueError("signature byte must fit in one byte")
        self._principal = principal
        self._signature_byte = signature_byte
        self.requests: list[SigningRequest] = []
        self.closed = False

    async def public_identity(self) -> PrincipalDescriptor:
        if self.closed:
            raise RuntimeError("development signer is closed")
        return self._principal

    async def sign(self, request: SigningRequest) -> SigningResponse:
        if self.closed:
            raise RuntimeError("development signer is closed")
        self.requests.append(request)
        return SigningResponse(
            request.request_id,
            request.principal,
            request.transaction_digest,
            bytes([self._signature_byte]) * 64,
        )

    async def aclose(self) -> None:
        self.closed = True


class DevelopmentEd25519Signer(Signer):
    kind = "auths-development-ed25519"
    lifecycle: SignerLifecycle = "ephemeral"

    def __init__(self) -> None:
        self._key = native.DevelopmentEd25519Key.generate()
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


@dataclass
class FixedClock:
    value: int

    def now(self) -> int:
        return self.value

    def advance(self, seconds: int) -> None:
        if seconds < 0:
            raise ValueError("clock cannot move backwards")
        self.value += seconds


class RecordingTelemetry:
    def __init__(self) -> None:
        self.events: list[AuthsEvent] = []

    def emit(self, event: AuthsEvent) -> None:
        self.events.append(event)


class DevelopmentIdentityMethod:
    def __init__(self, method_id: str = "auths.test-identity") -> None:
        self.method_id = method_id
        self.version = 1

    async def resolve(self, identity: DecodedIdentity) -> ResolvedIdentityRecord:
        return ResolvedIdentityRecord(
            identity.method_id,
            identity.identity_id,
            identity.method_material,
            identity.relationships,
            ResolutionEvidence("development", 0, (1 << 64) - 1, ("testkit",)),
        )

    async def validate(self, identity: ResolvedIdentity) -> None:
        if identity.record.method_id != self.method_id:
            raise ValueError("development identity method mismatch")


class DevelopmentSignatureSuite:
    def __init__(
        self,
        suite_id: str = "auths.test-signature",
        *,
        signature: bytes = b"auths-development-signature",
    ) -> None:
        self.suite_id = suite_id
        self.version = 1
        self._signature = bytes(signature)

    async def verify(
        self,
        material: tuple[VerificationMaterial, ...],
        preimage: bytes,
        signature: bytes,
    ) -> None:
        if not material or not preimage or signature != self._signature:
            raise ValueError("development signature rejected")


InputT = TypeVar("InputT")
OutputT = TypeVar("OutputT")


class MemoryGateway(Generic[InputT, OutputT]):
    def __init__(self, result: Callable[[InputT], Awaitable[OutputT]]) -> None:
        self._result = result
        self.calls: list[InputT] = []

    async def __call__(self, value: InputT) -> OutputT:
        self.calls.append(value)
        return await self._result(value)


async def check_signer(signer: Signer) -> PrincipalDescriptor:
    first = await signer.public_identity()
    second = await signer.public_identity()
    if not first.matches(second):
        raise AssertionError("signer identity changed between reads")
    return first


async def check_approval_provider(
    provider: ApprovalProvider, request: ApprovalRequest
) -> ApprovalResponse:
    result = await provider.approve(request)
    if type(result) is not ApprovalResponse:
        raise AssertionError("approval provider returned the wrong type")
    if result.request_id != request.request_id:
        raise AssertionError("approval provider changed the request identity")
    return result


async def check_identity_method(
    method: IdentityMethod, identity: DecodedIdentity
) -> ResolvedIdentityRecord:
    result = await method.resolve(identity)
    if type(result) is not ResolvedIdentityRecord:
        raise AssertionError("identity method returned the wrong resolved type")
    if (
        result.method_id != method.method_id
        or result.identity_id != identity.identity_id
    ):
        raise AssertionError("identity method changed the requested identity")
    await method.validate(ResolvedIdentity(identity, result))
    return result


def check_telemetry(telemetry: RecordingTelemetry) -> AuthsEvent:
    event = AuthsEvent(
        "auths.testkit",
        "conformance",
        "telemetry",
        "succeeded",
        0,
        (("contract_version", ADAPTER_CONTRACT_VERSION),),
    )
    telemetry.emit(event)
    if telemetry.events != [event]:
        raise AssertionError("telemetry adapter changed the event")
    return event


__all__ = [
    "ADAPTER_CONTRACT_VERSION",
    "DevelopmentApproval",
    "DevelopmentEd25519Signer",
    "DevelopmentReceiptAttestor",
    "DevelopmentIdentityMethod",
    "DevelopmentSignatureSuite",
    "DevelopmentSigner",
    "FixedClock",
    "MemoryGateway",
    "RecordingTelemetry",
    "check_approval_provider",
    "check_identity_method",
    "check_signer",
    "check_telemetry",
]
