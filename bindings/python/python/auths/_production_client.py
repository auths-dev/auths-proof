from __future__ import annotations

import asyncio
import base64
import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, Mapping, Optional, Protocol, Union, cast, runtime_checkable
from urllib.parse import urlparse

from ._native import (
    decode_production_response_v1,
    encode_production_delegation_v1,
    encode_production_request_v1,
    production_client_contract_version_v1,
)
from .profiles import ProductionProfile

_CONTENT_TYPE = "application/auths+cbor"
_MAX_RESPONSE_BYTES = 1_048_576
_DEFAULT_TIMEOUT_SECONDS = 15.0
_AUTHORITY_TOKEN = object()
_RECEIPT_TOKEN = object()
_REFERENCE_TOKEN = object()

ProductStep = Literal["create", "delegate", "execute", "resume", "verify"]
RetryClass = Literal["never", "backoff", "resume", "reconcile"]


@dataclass(frozen=True)
class ProductionTransportRequest:
    url: str
    body: bytes
    content_type: Literal["application/auths+cbor"]
    timeout_seconds: float


@dataclass(frozen=True)
class ProductionTransportResponse:
    status: int
    content_type: str
    body: bytes


@runtime_checkable
class ProductionTransport(Protocol):
    async def send(
        self, request: ProductionTransportRequest
    ) -> ProductionTransportResponse: ...


class ProductionAuthority:
    __slots__ = ("_bytes",)
    kind: Literal["authority"] = "authority"

    def __init__(self, token: object, value: bytes) -> None:
        if token is not _AUTHORITY_TOKEN or not value:
            raise TypeError("sealed Auths authority")
        self._bytes = bytes(value)

    def __reduce__(self) -> None:
        raise TypeError("Auths authority is opaque")


class ProductionReceipt:
    __slots__ = ("_bytes",)
    kind: Literal["receipt"] = "receipt"

    def __init__(self, token: object, value: bytes) -> None:
        if token is not _RECEIPT_TOKEN or not value:
            raise TypeError("sealed Auths receipt")
        self._bytes = bytes(value)

    def __reduce__(self) -> None:
        raise TypeError("Auths receipt bytes require an explicit disclosure operation")


class ProductionRecoveryReference:
    __slots__ = ("_value",)
    kind: Literal["recovery-reference"] = "recovery-reference"

    def __init__(self, token: object, value: str) -> None:
        if token is not _REFERENCE_TOKEN or not _is_recovery_reference(value):
            raise TypeError("sealed Auths recovery reference")
        self._value = value

    def __reduce__(self) -> None:
        raise TypeError("Auths recovery references are opaque")


@dataclass(frozen=True)
class ProductionDenied:
    kind: Literal["denied"]
    step: ProductStep
    code: str
    retry: Literal["never"]


@dataclass(frozen=True)
class ProductionIndeterminate:
    kind: Literal["indeterminate"]
    step: ProductStep
    code: str
    retry: Literal["backoff", "reconcile"]


@dataclass(frozen=True)
class ProductionRecoverable:
    kind: Literal["recoverable"]
    step: Literal["execute", "resume"]
    code: str
    retry: Literal["resume"]
    reference: ProductionRecoveryReference


@dataclass(frozen=True)
class ProductionCompleted:
    kind: Literal["completed"]
    step: Literal["execute", "resume"]
    value: Optional[bytes]
    receipt: ProductionReceipt


@dataclass(frozen=True)
class ProductionVerified:
    kind: Literal["verified"]
    step: Literal["verify"]
    value: Optional[bytes]


@dataclass(frozen=True)
class ProductionRejected:
    kind: Literal["rejected"]
    step: Literal["verify"]
    code: str
    retry: Literal["never"]


ProductionAuthorityResult = Union[
    ProductionAuthority, ProductionDenied, ProductionIndeterminate
]
ProductionExecutionResult = Union[
    ProductionCompleted,
    ProductionDenied,
    ProductionIndeterminate,
    ProductionRecoverable,
]
ProductionVerificationResult = Union[
    ProductionVerified, ProductionRejected, ProductionIndeterminate
]


class ProductionAuths:
    def __init__(
        self,
        *,
        endpoint: str,
        identity: bytes,
        profile: ProductionProfile,
        transport: Optional[ProductionTransport] = None,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._endpoint = _parse_endpoint(endpoint)
        self._identity = _bounded_bytes(identity, 65_536, "identity")
        if type(profile) is not ProductionProfile or profile.id not in _PROFILE_IDS:
            raise TypeError("Auths production profile is unsupported")
        if (
            type(timeout_seconds) not in (int, float)
            or timeout_seconds < 0.1
            or timeout_seconds > 120
        ):
            raise ValueError("Auths production timeout is outside bounds")
        if transport is not None and not isinstance(transport, ProductionTransport):
            raise TypeError("Auths production transport is invalid")
        self._profile = profile
        self._transport = transport or _UrlLibProductionTransport()
        self._timeout_seconds = float(timeout_seconds)

    async def create(self, request: bytes) -> ProductionAuthorityResult:
        projection = await self._call("create", body=request)
        if projection["kind"] == "completed":
            return ProductionAuthority(_AUTHORITY_TOKEN, _required_value(projection))
        return _authority_failure("create", projection)

    async def delegate(
        self,
        authority: ProductionAuthority,
        subject: bytes,
        attenuation: bytes = b"\x80",
    ) -> ProductionAuthorityResult:
        body = bytes(
            encode_production_delegation_v1(
                _bounded_bytes(subject, 65_536, "subject"),
                _bounded_bytes(attenuation, 65_536, "attenuation"),
            )
        )
        projection = await self._call(
            "delegate", authority=_authority_bytes(authority), body=body
        )
        if projection["kind"] == "completed":
            return ProductionAuthority(_AUTHORITY_TOKEN, _required_value(projection))
        return _authority_failure("delegate", projection)

    async def execute(
        self, authority: ProductionAuthority, action: bytes
    ) -> ProductionExecutionResult:
        return _execution_result(
            "execute",
            await self._call(
                "execute", authority=_authority_bytes(authority), body=action
            ),
        )

    async def resume(
        self, reference: ProductionRecoveryReference
    ) -> ProductionExecutionResult:
        if type(reference) is not ProductionRecoveryReference:
            raise TypeError("forged Auths recovery reference")
        return _execution_result(
            "resume",
            await self._call("resume", recovery_reference=reference._value),
        )

    async def verify(
        self, value: Union[ProductionAuthority, ProductionReceipt, bytes]
    ) -> ProductionVerificationResult:
        if type(value) is ProductionAuthority:
            body = value._bytes
        elif type(value) is ProductionReceipt:
            body = value._bytes
        else:
            body = _bounded_bytes(value, _MAX_RESPONSE_BYTES, "verification input")
        projection = await self._call("verify", body=body)
        if projection["kind"] == "verified":
            return ProductionVerified("verified", "verify", _optional_bytes(projection["value"]))
        if projection["kind"] == "rejected":
            return ProductionRejected(
                "rejected", "verify", _required_code(projection), "never"
            )
        if projection["kind"] == "indeterminate":
            return _indeterminate("verify", projection)
        raise TypeError("native response outcome does not match verify")

    async def _call(
        self,
        step: ProductStep,
        *,
        authority: Optional[bytes] = None,
        body: Optional[bytes] = None,
        recovery_reference: Optional[str] = None,
    ) -> Mapping[str, object]:
        request_body = bytes(
            encode_production_request_v1(
                step,
                self._profile.id,
                self._identity,
                authority,
                None if body is None else _bounded_bytes(body, _MAX_RESPONSE_BYTES, "body"),
                recovery_reference,
            )
        )
        request = ProductionTransportRequest(
            self._endpoint + _endpoint_path(step, self._profile.id),
            request_body,
            _CONTENT_TYPE,
            self._timeout_seconds,
        )
        try:
            response = await self._transport.send(request)
        except Exception:
            return MappingProxyType(
                {
                    "contractVersion": 1,
                    "kind": "indeterminate",
                    "code": "core.runtime-unavailable",
                    "retry": "backoff",
                    "recoveryReference": None,
                    "value": None,
                    "receipt": None,
                }
            )
        if (
            not 200 <= response.status < 300
            or response.content_type.split(";", 1)[0].strip().lower() != _CONTENT_TYPE
            or not response.body
            or len(response.body) > _MAX_RESPONSE_BYTES
        ):
            return MappingProxyType(
                {
                    "contractVersion": 1,
                    "kind": "indeterminate",
                    "code": "core.malformed-input",
                    "retry": "backoff",
                    "recoveryReference": None,
                    "value": None,
                    "receipt": None,
                }
            )
        return _projection(decode_production_response_v1(response.body))


def create_auths(
    *,
    endpoint: str,
    identity: bytes,
    profile: ProductionProfile,
    transport: Optional[ProductionTransport] = None,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> ProductionAuths:
    if production_client_contract_version_v1() != 1:
        raise RuntimeError("Auths production client contract mismatch")
    return ProductionAuths(
        endpoint=endpoint,
        identity=identity,
        profile=profile,
        transport=transport,
        timeout_seconds=timeout_seconds,
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request: object, *args: object, **kwargs: object) -> None:
        return None


class _UrlLibProductionTransport:
    async def send(
        self, request: ProductionTransportRequest
    ) -> ProductionTransportResponse:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _send_sync, request)


def _send_sync(request: ProductionTransportRequest) -> ProductionTransportResponse:
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), _NoRedirect()
    )
    value = urllib.request.Request(
        request.url,
        data=request.body,
        headers={"Content-Type": request.content_type, "Accept": request.content_type},
        method="POST",
    )
    try:
        response = opener.open(value, timeout=request.timeout_seconds)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        declared = response.headers.get("Content-Length")
        if declared is not None and int(declared) > _MAX_RESPONSE_BYTES:
            raise ValueError("Auths production response is outside bounds")
        body = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(body) > _MAX_RESPONSE_BYTES:
            raise ValueError("Auths production response is outside bounds")
        return ProductionTransportResponse(
            response.status, response.headers.get("Content-Type", ""), body
        )


_PROFILE_IDS = (
    "auths.opentofu.saved-plan-apply/1",
    "auths.postgresql.bounded-update/1",
    "auths.github.issue-address/1",
)


def _parse_endpoint(value: str) -> str:
    if type(value) is not str:
        raise TypeError("Auths production endpoint must be an HTTPS origin")
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Auths production endpoint must be an HTTPS origin")
    return value.rstrip("/")


def _endpoint_path(step: ProductStep, profile: str) -> str:
    if step == "create":
        return "/v1/authority/create"
    if step == "delegate":
        return "/v1/authority/delegate"
    if step == "resume":
        return "/v1/workflows/resume"
    if step == "verify":
        return "/v1/authority/verify"
    return {
        _PROFILE_IDS[0]: "/v1/profiles/opentofu/saved-plan-apply/execute",
        _PROFILE_IDS[1]: "/v1/profiles/postgresql/bounded-update/execute",
        _PROFILE_IDS[2]: "/v1/profiles/github/issue-address/execute",
    }[profile]


def _projection(value: str) -> Mapping[str, object]:
    parsed = json.loads(value)
    if (
        type(parsed) is not dict
        or parsed.get("contractVersion") != 1
        or parsed.get("kind")
        not in (
            "completed",
            "denied",
            "indeterminate",
            "recoverable",
            "verified",
            "rejected",
        )
        or parsed.get("retry") not in ("never", "backoff", "resume", "reconcile")
    ):
        raise TypeError("native response projection is invalid")
    return MappingProxyType(parsed)


def _authority_failure(
    step: Literal["create", "delegate"], projection: Mapping[str, object]
) -> Union[ProductionDenied, ProductionIndeterminate]:
    if projection["kind"] == "denied":
        return ProductionDenied("denied", step, _required_code(projection), "never")
    if projection["kind"] == "indeterminate":
        return _indeterminate(step, projection)
    raise TypeError("native response outcome does not match " + step)


def _execution_result(
    step: Literal["execute", "resume"], projection: Mapping[str, object]
) -> ProductionExecutionResult:
    if projection["kind"] == "completed":
        receipt = _optional_bytes(projection["receipt"])
        if receipt is None:
            raise TypeError("native response omitted receipt bytes")
        return ProductionCompleted(
            "completed",
            step,
            _optional_bytes(projection["value"]),
            ProductionReceipt(_RECEIPT_TOKEN, receipt),
        )
    if projection["kind"] == "denied":
        return ProductionDenied("denied", step, _required_code(projection), "never")
    if projection["kind"] == "indeterminate":
        return _indeterminate(step, projection)
    reference = projection.get("recoveryReference")
    if projection["kind"] == "recoverable" and type(reference) is str:
        return ProductionRecoverable(
            "recoverable",
            step,
            _required_code(projection),
            "resume",
            ProductionRecoveryReference(_REFERENCE_TOKEN, reference),
        )
    raise TypeError("native response outcome does not match " + step)


def _indeterminate(
    step: ProductStep, projection: Mapping[str, object]
) -> ProductionIndeterminate:
    retry = projection["retry"]
    if retry not in ("backoff", "reconcile"):
        raise TypeError("native indeterminate result has invalid retry class")
    return ProductionIndeterminate(
        "indeterminate",
        step,
        _required_code(projection),
        cast(Literal["backoff", "reconcile"], retry),
    )


def _required_code(projection: Mapping[str, object]) -> str:
    value = projection.get("code")
    if type(value) is not str:
        raise TypeError("native response omitted stable error code")
    return value


def _required_value(projection: Mapping[str, object]) -> bytes:
    value = _optional_bytes(projection.get("value"))
    if value is None:
        raise TypeError("native response omitted value bytes")
    return value


def _optional_bytes(value: object) -> Optional[bytes]:
    if value is None:
        return None
    if type(value) is not str:
        raise TypeError("native response encoding is invalid")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError:
        raise TypeError("native response encoding is invalid") from None


def _bounded_bytes(value: object, maximum: int, name: str) -> bytes:
    if type(value) is not bytes or not value or len(value) > maximum:
        raise ValueError("Auths " + name + " bytes are outside bounds")
    return value


def _authority_bytes(value: ProductionAuthority) -> bytes:
    if type(value) is not ProductionAuthority:
        raise TypeError("forged Auths authority")
    return value._bytes


def _is_recovery_reference(value: str) -> bool:
    if type(value) is not str or len(value) != 43:
        return False
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except ValueError:
        return False
    return len(decoded) == 32 and decoded != bytes(32)


__all__ = [
    "ProductStep",
    "ProductionAuths",
    "ProductionAuthority",
    "ProductionAuthorityResult",
    "ProductionCompleted",
    "ProductionDenied",
    "ProductionExecutionResult",
    "ProductionIndeterminate",
    "ProductionReceipt",
    "ProductionRecoverable",
    "ProductionRecoveryReference",
    "ProductionRejected",
    "ProductionTransport",
    "ProductionTransportRequest",
    "ProductionTransportResponse",
    "ProductionVerificationResult",
    "ProductionVerified",
    "RetryClass",
    "create_auths",
]
