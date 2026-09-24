from __future__ import annotations

import datetime as _datetime
import hashlib as _hashlib
import time as _time
from dataclasses import dataclass as _dataclass
from typing import (
    Callable as _Callable,
    Literal as _Literal,
    Mapping as _Mapping,
    Optional as _Optional,
    Tuple as _Tuple,
)

from . import _native as _native
from ._native import DevelopmentEd25519Key as _DevelopmentEd25519Key
from ._mechanism_conformance_v2 import CONFORMANCE_CATALOG_V2 as _CONFORMANCE_CATALOG_V2
from ._public import runtime_info as _runtime_info
from .adapters.custody import (
    CustodyDescriptor,
    CustodyKeyState,
    CustodyKind,
    CustodyLifecycle,
    CustodySignatureDescriptor,
    CustodySigned,
    PublicControlEvidence,
    CustodySigner,
    SigningObjectKind,
    SigningRequest,
    SigningResponse,
)
from .adapters.reservations import ReservationRecord, ReservationStore
from .protocol import BoundedTransport, TransportRequest
from .verify import VerificationInput
from ._adapter_conformance import ScriptedProvider, run_self_hosted_adapter_conformance


@_dataclass(frozen=True)
class ConformanceCase:
    id: str
    status: _Literal["passed", "failed"]
    detail_code: _Optional[
        _Literal[
            "contract-mismatch",
            "unexpected-exception",
            "timeout",
            "resource-leak",
            "redaction-failed",
        ]
    ]
    summary: _Optional[str]


@_dataclass(frozen=True)
class ConformanceMetadata:
    suite: str
    contract_version: str
    sdk_version: str
    generated_at: str
    assurance: _Literal["test-results-only-not-security-certification"]


@_dataclass(frozen=True)
class ConformanceReport:
    metadata: ConformanceMetadata
    passed: bool
    cases: _Tuple[ConformanceCase, ...]


@_dataclass(frozen=True)
class DevelopmentMcpArtifacts:
    """Disposable local-only proof, action, and operator context bytes."""

    proof: bytes
    action: bytes
    trusted_context: bytes


def development_mcp_artifacts(
    *,
    service: str,
    name: str,
    arguments: _Mapping[str, object],
    now: int | None = None,
) -> DevelopmentMcpArtifacts:
    """Create a self-trusting fixture for local tests, never production trust.

    The ephemeral signing key is not returned or serialized. Production users
    must provision their signer and trusted context independently.
    """
    from .self_hosted import _canonical_arguments

    current = int(_time.time()) if now is None else now
    if not 60 <= current < 2**64 - 600:
        raise ValueError("development evaluation time is outside bounds")
    encoded = _canonical_arguments(arguments)
    call = _native.mcp_call(service, name, encoded)
    audience = f"mcp://{service}"
    resource = f"{audience}/tools/{name}"
    key = _DevelopmentEd25519Key.generate()
    actor = _native.Principal(key.principal)
    request = _native.GrantRequest(
        actor,
        "auths.mcp",
        2,
        [("tools/call", resource)],
        current - 60,
        current + 600,
        [audience],
        None,
        None,
        0,
        None,
        "raw-key-baseline",
        [],
    )
    grant_unsigned = _native.root_grant(actor, request)
    grant_request = _native.prepare_signing(
        grant_unsigned, key.principal_method, key.verification_method, key.suite
    )
    grant = grant_request.complete(key.sign(grant_request.signing_preimage))
    challenge = _native.generate_challenge_v1()
    prepared = _native.prepare_mcp_call_action(
        call, actor, grant, challenge, current, 30
    )
    action_request = _native.prepare_signing(
        prepared.unsigned, key.principal_method, key.verification_method, key.suite
    )
    signed_action = action_request.complete(key.sign(action_request.signing_preimage))
    assurance = _native.AssurancePolicy(
        "raw-key-baseline",
        [
            ("root", "every", "self-certifying-identifier", None),
            ("actor", "every", "self-certifying-identifier", None),
            ("actor", "every", "offline-verifiable", None),
        ],
    )
    anchor = _native.TrustAnchor(
        actor.value,
        actor,
        [key.principal_method],
        [("auths.mcp", 2)],
        [("tools/call", resource)],
        [audience],
        [audience],
        current - 60,
        current + 600,
        None,
        1,
        "raw-key-baseline",
        None,
    )
    template = _native.compile_trusted_context(
        _native.self_contained_configuration(),
        None,
        1,
        1,
        1,
        [anchor],
        assurance,
        None,
        None,
        "none-v1",
        [key.evidence_type],
        [],
    )
    context = template.bind_request(audience, challenge, current)
    evidence = (key.evidence_type, key.media_type, key.evidence)
    proof, action, trusted_context = _native.assemble_mcp_proof(
        prepared,
        signed_action,
        [grant],
        [[evidence]],
        [evidence],
        context,
    )
    verdict = _native.verify_v1(proof, action, trusted_context)
    if verdict.kind != "authorized":
        raise RuntimeError(f"development fixture was not authorized: {verdict.code}")
    return DevelopmentMcpArtifacts(bytes(proof), bytes(action), bytes(trusted_context))


def _report(
    suite: str, cases: list[ConformanceCase], contract_version: str = "2"
) -> ConformanceReport:
    metadata = ConformanceMetadata(
        suite,
        contract_version,
        _runtime_info().sdk_version,
        _datetime.datetime.now(_datetime.timezone.utc).isoformat(),
        "test-results-only-not-security-certification",
    )
    return ConformanceReport(
        metadata, all(value.status == "passed" for value in cases), tuple(cases)
    )


def _failed(identifier: str, error: BaseException) -> ConformanceCase:
    return ConformanceCase(
        identifier, "failed", "unexpected-exception", type(error).__name__[:256]
    )


def _case_ids(suite: str) -> _Tuple[str, ...]:
    for candidate in _CONFORMANCE_CATALOG_V2["suites"]:
        if candidate["id"] == suite:
            return tuple(value["id"] for value in candidate["cases"])
    raise ValueError("unknown Auths conformance suite")


async def run_custody_signer_conformance(
    factory: _Callable[[], CustodySigner], /
) -> ConformanceReport:
    identifiers = _case_ids("signer-custody/2")
    cases: list[ConformanceCase] = []
    signer = factory()
    try:
        descriptor = signer.descriptor
        if descriptor.contract != "signer-custody/2":
            raise ValueError("contract")
        digest = b"\x01" * 32
        request = SigningRequest(
            "test-request",
            SigningObjectKind.ACTION,
            b"\x02" * 32,
            descriptor,
            digest,
            b"auths-test",
            2**31,
            (),
        )
        result = await signer.sign(request)
        if (
            not isinstance(result, CustodySigned)
            or result.response.request_id != request.request_id
            or result.response.transaction_digest != digest
        ):
            raise ValueError("response binding")
        cases.extend(
            ConformanceCase(identifier, "passed", None, None)
            for identifier in identifiers[:-1]
        )
    except BaseException as error:
        cases.append(_failed(identifiers[0], error))
    finally:
        try:
            await signer.aclose()
            cases.append(ConformanceCase(identifiers[-1], "passed", None, None))
        except BaseException as error:
            cases.append(_failed(identifiers[-1], error))
    return _report("signer-custody/2", cases)


async def run_reservation_store_conformance(
    factory: _Callable[[str], ReservationStore], /
) -> ConformanceReport:
    identifiers = _case_ids("atomic-reservation-store/2")
    cases: list[ConformanceCase] = []
    name = (
        "auths-conformance-"
        + _hashlib.sha256(_datetime.datetime.now().isoformat().encode()).hexdigest()[
            :12
        ]
    )
    store = factory(name)
    try:
        if store.contract != "atomic-reservation-store/2":
            raise ValueError("contract")
        record = ReservationRecord("one", b"x" * 32, b"value")
        if (
            await store.reserve(record) != "acquired"
            or await store.reserve(record) != "exact-replay"
        ):
            raise ValueError("atomic replay")
        if (
            await store.reserve(ReservationRecord("one", b"y" * 32, b"other"))
            != "conflict"
        ):
            raise ValueError("conflict")
        await store.aclose()
        reopened = factory(name)
        if (
            store.durability == "single-machine-durable"
            and await reopened.reserve(record) != "exact-replay"
        ):
            raise ValueError("durability claim")
        await reopened.aclose()
        isolated = factory(name + ".isolated")
        if await isolated.reserve(record) != "acquired":
            raise ValueError("isolation claim")
        await isolated.aclose()
        cases.extend(
            ConformanceCase(identifier, "passed", None, None)
            for identifier in identifiers
        )
    except BaseException as error:
        cases.append(_failed(identifiers[0], error))
    return _report("atomic-reservation-store/2", cases)


async def run_bounded_transport_conformance(
    factory: _Callable[[], BoundedTransport], /
) -> ConformanceReport:
    identifiers = _case_ids("bounded-byte-transport/2")
    transport = factory()
    cases: list[ConformanceCase] = []
    try:
        if transport.contract != "bounded-byte-transport/2":
            raise ValueError("contract")
        request = TransportRequest(
            "https://example.invalid/v2/verification/authorize",
            "POST",
            "application/vnd.auths.remote-verification.v1+cbor",
            "application/vnd.auths.remote-verification.v1+cbor",
            b"\xa1\x00\x01",
            2**53 - 1,
            1024,
        )
        response = await transport.send(request)
        if len(response.body) > request.maximum_response_bytes:
            raise ValueError("response bound")
        cases.extend(
            ConformanceCase(identifier, "passed", None, None)
            for identifier in identifiers[:-1]
        )
    except BaseException as error:
        cases.append(_failed(identifiers[0], error))
    finally:
        try:
            await transport.aclose()
            cases.append(ConformanceCase(identifiers[-1], "passed", None, None))
        except BaseException as error:
            cases.append(_failed(identifiers[-1], error))
    return _report("bounded-byte-transport/2", cases)


class _EphemeralSigner:
    def __init__(self) -> None:
        self._key = _DevelopmentEd25519Key.generate()
        self._closed = False
        self._descriptor = CustodyDescriptor(
            "signer-custody/2",
            CustodyKind.WORKLOAD,
            "auths.testkit.ephemeral-ed25519",
            self._key.principal,
            CustodySignatureDescriptor(
                self._key.principal_method,
                self._key.verification_method,
                self._key.suite,
            ),
            "ephemeral-1",
            CustodyKeyState.ACTIVE_CURRENT,
            CustodyLifecycle.EPHEMERAL,
        )

    @property
    def descriptor(self) -> CustodyDescriptor:
        return self._descriptor

    async def sign(self, request: SigningRequest) -> CustodySigned:
        if self._closed:
            raise RuntimeError("signer is closed")
        response = SigningResponse(
            request.request_id,
            request.object_id,
            self._descriptor.principal,
            self._descriptor.signature,
            self._descriptor.key_version,
            request.transaction_digest,
            self._key.sign(request.signing_preimage),
            (
                PublicControlEvidence(
                    self._key.evidence_type, self._key.media_type, self._key.evidence
                ),
            ),
        )
        return CustodySigned("signed", response)

    async def aclose(self) -> None:
        self._closed = True


def ephemeral_ed25519_signer() -> object:
    return _EphemeralSigner()


class DevelopmentEd25519IdentityKey:
    """Ephemeral test-only key for identity examples and conformance fixtures."""

    def __init__(self) -> None:
        self._key = _DevelopmentEd25519Key.generate()

    @property
    def public_key(self) -> bytes:
        return bytes(self._key.public_key)

    def sign(self, preimage: bytes, /) -> bytes:
        return bytes(self._key.sign(bytes(preimage)))


def development_ed25519_identity_key() -> DevelopmentEd25519IdentityKey:
    return DevelopmentEd25519IdentityKey()


class fixtures:
    def __new__(cls) -> "fixtures":
        raise TypeError("fixtures is a namespace")

    @staticmethod
    def authorized_verification() -> VerificationInput:
        return VerificationInput(
            proof=b"auths-fixture-authorized",
            action=b"auths-fixture-action",
            trusted_context=b"auths-fixture-context",
        )

    @staticmethod
    def denied_verification() -> VerificationInput:
        return VerificationInput(
            proof=b"invalid", action=b"invalid", trusted_context=b"invalid"
        )

    @staticmethod
    def github_denied_candidate(
        reason: _Literal["protected-path", "base-mismatch"],
    ) -> bytes:
        return ("auths.github.fixture/2:" + reason).encode()


__all__ = [
    "ConformanceCase",
    "ConformanceMetadata",
    "ConformanceReport",
    "DevelopmentEd25519IdentityKey",
    "DevelopmentMcpArtifacts",
    "ScriptedProvider",
    "run_custody_signer_conformance",
    "run_reservation_store_conformance",
    "run_bounded_transport_conformance",
    "development_ed25519_identity_key",
    "development_mcp_artifacts",
    "run_self_hosted_adapter_conformance",
    "ephemeral_ed25519_signer",
    "fixtures",
]
