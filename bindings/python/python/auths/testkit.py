"""Deterministic development adapters and executable port checks."""

from __future__ import annotations

from dataclasses import dataclass
from inspect import isawaitable
from types import MappingProxyType
from typing import Any, Awaitable, Callable, Generic, Mapping, TypeVar, Union

from ._development import (
    DevelopmentEd25519Signer,
    DevelopmentReceiptAttestor,
)
from .approvals import (
    ApprovalDecision,
    ApprovalProvider,
    ApprovalRequest,
    ApprovalResponse,
)
from .custody import (
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
from .conformance import (
    CONFORMANCE_CATALOG,
    AtomicReservationRecord,
    AtomicReservationStoreCandidate,
    ByteTransportCandidate,
    ConformanceCaseResult,
    ConformanceMetadata,
    ConformanceReport,
    certify_atomic_store,
    certify_byte_transport,
    certify_mcp_provider,
    certify_signer,
)

ADAPTER_CONTRACT_VERSION = 1


@dataclass(frozen=True)
class ProductWaistExpected:
    boundary: str
    code: str


@dataclass(frozen=True)
class ProductWaistConformanceReport:
    schema: str
    manifest_schema: str
    fixture_projection: str
    passed: tuple[str, ...]


async def product_waist_conformance(
    manifest_input: object,
    cases: Mapping[
        str,
        Callable[[ProductWaistExpected], Union[object, Awaitable[object]]],
    ],
) -> ProductWaistConformanceReport:
    manifest = _product_waist_manifest(manifest_input)
    required = tuple(item["id"] for item in manifest["cases"])
    supplied = tuple(cases)
    if len(supplied) != len(set(supplied)) or set(supplied) != set(required):
        missing = sorted(set(required) - set(supplied))
        unexpected = sorted(set(supplied) - set(required))
        raise TypeError(
            "product-waist case mismatch; "
            f"missing={','.join(missing)}; unexpected={','.join(unexpected)}"
        )
    for item in manifest["cases"]:
        result = cases[item["id"]](
            ProductWaistExpected(item["boundary"], item["expected"])
        )
        if isawaitable(result):
            await result
    return ProductWaistConformanceReport(
        "auths.simplified-product-waist-conformance-result/1",
        manifest["schema"],
        manifest["fixtureProjection"],
        required,
    )


def _product_waist_manifest(value: object) -> Mapping[str, Any]:
    if type(value) is not dict:
        raise TypeError("product-waist manifest must be an object")
    schema = _manifest_text(value.get("schema"), "schema")
    owner = _manifest_text(value.get("semanticOwner"), "semanticOwner")
    projection = _manifest_text(value.get("fixtureProjection"), "fixtureProjection")
    raw_cases = value.get("cases")
    if (
        schema != "auths.simplified-product-waist-conformance/1"
        or owner != "Rust"
        or type(raw_cases) is not list
    ):
        raise TypeError("unsupported product-waist manifest")
    seen: set[str] = set()
    parsed: list[Mapping[str, str]] = []
    for candidate in raw_cases:
        if type(candidate) is not dict:
            raise TypeError("product-waist case must be an object")
        identifier = _manifest_text(candidate.get("id"), "case id")
        boundary = _manifest_text(candidate.get("boundary"), "case boundary")
        expected = _manifest_text(candidate.get("expected"), "case expected code")
        parts = identifier.split("/")
        if (
            len(parts) != 2
            or any(not part or not part.replace("-", "").isalnum() for part in parts)
            or identifier.lower() != identifier
            or identifier in seen
        ):
            raise TypeError(f"invalid or duplicate product-waist case: {identifier}")
        seen.add(identifier)
        parsed.append(
            MappingProxyType(
                {"id": identifier, "boundary": boundary, "expected": expected}
            )
        )
    return MappingProxyType(
        {
            "schema": schema,
            "semanticOwner": owner,
            "fixtureProjection": projection,
            "cases": tuple(parsed),
        }
    )


def _manifest_text(value: object, name: str) -> str:
    if type(value) is not str or not value or len(value) > 512:
        raise TypeError(f"product-waist {name} is invalid")
    return value


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
    "ProductWaistConformanceReport",
    "ProductWaistExpected",
    "RecordingTelemetry",
    "check_approval_provider",
    "check_identity_method",
    "check_signer",
    "check_telemetry",
    "product_waist_conformance",
    "AtomicReservationRecord",
    "AtomicReservationStoreCandidate",
    "ByteTransportCandidate",
    "CONFORMANCE_CATALOG",
    "ConformanceCaseResult",
    "ConformanceMetadata",
    "ConformanceReport",
    "certify_atomic_store",
    "certify_byte_transport",
    "certify_mcp_provider",
    "certify_signer",
]
