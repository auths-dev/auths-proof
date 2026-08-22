from __future__ import annotations

import datetime as _datetime
import hashlib as _hashlib
from dataclasses import dataclass as _dataclass
from typing import Callable as _Callable, Literal as _Literal, Optional as _Optional, Tuple as _Tuple

from ._native import DevelopmentEd25519Key as _DevelopmentEd25519Key
from ._mechanism_conformance_v2 import CONFORMANCE_CATALOG_V2 as _CONFORMANCE_CATALOG_V2
from ._public import runtime_info as _runtime_info
from .adapters.custody import (
    CustodyDescriptor, CustodyKeyState, CustodyKind, CustodyLifecycle,
    CustodySignatureDescriptor, CustodySigned, PublicControlEvidence,
    CustodySigner, SigningObjectKind, SigningRequest, SigningResponse,
)
from .adapters.reservations import ReservationRecord, ReservationStore
from .protocol import BoundedTransport, TransportRequest
from .verify import VerificationInput


@_dataclass(frozen=True)
class ConformanceCase:
    id: str
    status: _Literal["passed", "failed"]
    detail_code: _Optional[_Literal["contract-mismatch", "unexpected-exception", "timeout", "resource-leak", "redaction-failed"]]
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


def _report(suite: str, cases: list[ConformanceCase]) -> ConformanceReport:
    metadata = ConformanceMetadata(suite, "2", _runtime_info().sdk_version, _datetime.datetime.now(_datetime.timezone.utc).isoformat(), "test-results-only-not-security-certification")
    return ConformanceReport(metadata, all(value.status == "passed" for value in cases), tuple(cases))


def _failed(identifier: str, error: BaseException) -> ConformanceCase:
    return ConformanceCase(identifier, "failed", "unexpected-exception", type(error).__name__[:256])


def _case_ids(suite: str) -> _Tuple[str, ...]:
    for candidate in _CONFORMANCE_CATALOG_V2["suites"]:
        if candidate["id"] == suite:
            return tuple(value["id"] for value in candidate["cases"])
    raise ValueError("unknown Auths conformance suite")


async def run_custody_signer_conformance(factory: _Callable[[], CustodySigner], /) -> ConformanceReport:
    identifiers = _case_ids("signer-custody/2")
    cases: list[ConformanceCase] = []; signer = factory()
    try:
        descriptor = signer.descriptor
        if descriptor.contract != "signer-custody/2": raise ValueError("contract")
        digest = b"\x01" * 32
        request = SigningRequest("test-request", SigningObjectKind.ACTION, b"\x02" * 32, descriptor, digest, b"auths-test", 2**31, ())
        result = await signer.sign(request)
        if not isinstance(result, CustodySigned) or result.response.request_id != request.request_id or result.response.transaction_digest != digest: raise ValueError("response binding")
        cases.extend(ConformanceCase(identifier, "passed", None, None) for identifier in identifiers[:-1])
    except BaseException as error: cases.append(_failed(identifiers[0], error))
    finally:
        try: await signer.aclose(); cases.append(ConformanceCase(identifiers[-1], "passed", None, None))
        except BaseException as error: cases.append(_failed(identifiers[-1], error))
    return _report("signer-custody/2", cases)


async def run_reservation_store_conformance(factory: _Callable[[str], ReservationStore], /) -> ConformanceReport:
    identifiers = _case_ids("atomic-reservation-store/2")
    cases: list[ConformanceCase] = []
    name = "auths-conformance-" + _hashlib.sha256(_datetime.datetime.now().isoformat().encode()).hexdigest()[:12]
    store = factory(name)
    try:
        if store.contract != "atomic-reservation-store/2": raise ValueError("contract")
        record = ReservationRecord("one", b"x" * 32, b"value")
        if await store.reserve(record) != "acquired" or await store.reserve(record) != "exact-replay": raise ValueError("atomic replay")
        if await store.reserve(ReservationRecord("one", b"y" * 32, b"other")) != "conflict": raise ValueError("conflict")
        await store.aclose(); reopened = factory(name)
        if store.durability == "single-machine-durable" and await reopened.reserve(record) != "exact-replay": raise ValueError("durability claim")
        await reopened.aclose()
        isolated = factory(name + ".isolated")
        if await isolated.reserve(record) != "acquired": raise ValueError("isolation claim")
        await isolated.aclose()
        cases.extend(ConformanceCase(identifier, "passed", None, None) for identifier in identifiers)
    except BaseException as error: cases.append(_failed(identifiers[0], error))
    return _report("atomic-reservation-store/2", cases)


async def run_bounded_transport_conformance(factory: _Callable[[], BoundedTransport], /) -> ConformanceReport:
    identifiers = _case_ids("bounded-byte-transport/2")
    transport = factory(); cases: list[ConformanceCase] = []
    try:
        if transport.contract != "bounded-byte-transport/2": raise ValueError("contract")
        request = TransportRequest("https://example.invalid/v2/verification/authorize", "POST", "application/vnd.auths.remote-verification.v1+cbor", "application/vnd.auths.remote-verification.v1+cbor", b"\xa1\x00\x01", 2**53 - 1, 1024)
        response = await transport.send(request)
        if len(response.body) > request.maximum_response_bytes: raise ValueError("response bound")
        cases.extend(ConformanceCase(identifier, "passed", None, None) for identifier in identifiers[:-1])
    except BaseException as error: cases.append(_failed(identifiers[0], error))
    finally:
        try: await transport.aclose(); cases.append(ConformanceCase(identifiers[-1], "passed", None, None))
        except BaseException as error: cases.append(_failed(identifiers[-1], error))
    return _report("bounded-byte-transport/2", cases)


class _EphemeralSigner:
    def __init__(self) -> None:
        self._key = _DevelopmentEd25519Key.generate(); self._closed = False
        self._descriptor = CustodyDescriptor("signer-custody/2", CustodyKind.WORKLOAD, "auths.testkit.ephemeral-ed25519", self._key.principal, CustodySignatureDescriptor(self._key.principal_method, self._key.verification_method, self._key.suite), "ephemeral-1", CustodyKeyState.ACTIVE_CURRENT, CustodyLifecycle.EPHEMERAL)
    @property
    def descriptor(self) -> CustodyDescriptor: return self._descriptor
    async def sign(self, request: SigningRequest) -> CustodySigned:
        if self._closed: raise RuntimeError("signer is closed")
        response = SigningResponse(request.request_id, request.object_id, self._descriptor.principal, self._descriptor.signature, self._descriptor.key_version, request.transaction_digest, self._key.sign(request.signing_preimage), (PublicControlEvidence(self._key.evidence_type, self._key.media_type, self._key.evidence),))
        return CustodySigned("signed", response)
    async def aclose(self) -> None: self._closed = True


def ephemeral_ed25519_signer() -> object: return _EphemeralSigner()


class fixtures:
    def __new__(cls) -> "fixtures": raise TypeError("fixtures is a namespace")
    @staticmethod
    def authorized_verification() -> VerificationInput: return VerificationInput(proof=b"auths-fixture-authorized", action=b"auths-fixture-action", trusted_context=b"auths-fixture-context")
    @staticmethod
    def denied_verification() -> VerificationInput: return VerificationInput(proof=b"invalid", action=b"invalid", trusted_context=b"invalid")
    @staticmethod
    def github_denied_candidate(reason: _Literal["protected-path", "base-mismatch"]) -> bytes: return ("auths.github.fixture/2:" + reason).encode()


__all__ = ["ConformanceCase", "ConformanceMetadata", "ConformanceReport", "run_custody_signer_conformance", "run_reservation_store_conformance", "run_bounded_transport_conformance", "ephemeral_ed25519_signer", "fixtures"]
