from __future__ import annotations

import asyncio
import base64
import http.client
import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from types import MappingProxyType
from typing import IO, Final, Literal, Mapping, NoReturn, Optional, Protocol, Union, cast, runtime_checkable
from urllib.parse import urlparse

from ._native import (
    decode_production_response_v1,
    encode_production_delegation_v1,
    encode_production_request_v1,
    production_client_contract_version_v1,
)
from ._product_errors import (
    AuthsErrorCode,
    ProductVerb,
    EffectState,
    RecommendedAction,
    RetryClass,
    classify,
)
from .profiles import ServiceProfile

_CONTENT_TYPE: Literal["application/auths+cbor"] = "application/auths+cbor"
_MAX_RESPONSE_BYTES = 1_048_576
_DEFAULT_TIMEOUT_SECONDS = 15.0
_AUTHORITY_TOKEN = object()
_RECEIPT_TOKEN = object()
_REFERENCE_TOKEN = object()

NextCall = Literal["never", "backoff", "resume", "reconcile"]
"""`auths_production_client::NextCall` -- *what should I call next?*

This is not `RetryClass`. `auths.RetryClass` answers *may I retry?* and has
the members never|safe|conditional|unknown. The two questions must never
share an identifier again (contract 4.1).
"""


@dataclass(frozen=True)
class ServiceTransportRequest:
    url: str
    body: bytes
    content_type: Literal["application/auths+cbor"]
    timeout_seconds: float


@dataclass(frozen=True)
class ServiceTransportResponse:
    status: int
    content_type: str
    body: bytes


@runtime_checkable
class ServiceTransport(Protocol):
    async def send(
        self, request: ServiceTransportRequest
    ) -> ServiceTransportResponse: ...


class ServiceAuthority:
    __slots__ = ("_bytes",)
    kind: Literal["authority"] = "authority"

    def __init__(self, token: object, value: bytes) -> None:
        if token is not _AUTHORITY_TOKEN or not value:
            raise TypeError("sealed Auths authority")
        self._bytes = bytes(value)

    def __reduce__(self) -> NoReturn:
        raise TypeError("Auths authority is opaque")


class ServiceReceipt:
    __slots__ = ("_bytes",)
    kind: Literal["receipt"] = "receipt"

    def __init__(self, token: object, value: bytes) -> None:
        if token is not _RECEIPT_TOKEN or not value:
            raise TypeError("sealed Auths receipt")
        self._bytes = bytes(value)

    def __reduce__(self) -> NoReturn:
        raise TypeError("Auths receipt bytes require an explicit disclosure operation")


class ServiceRecoveryReference:
    __slots__ = ("_value",)
    kind: Literal["recovery-reference"] = "recovery-reference"

    def __init__(self, token: object, value: str) -> None:
        if token is not _REFERENCE_TOKEN or not _is_recovery_reference(value):
            raise TypeError("sealed Auths recovery reference")
        self._value = value

    def __reduce__(self) -> NoReturn:
        raise TypeError("Auths recovery references are opaque")


@dataclass(frozen=True)
class ServiceDenied:
    kind: Literal["denied"]
    verb: ProductVerb
    code: AuthsErrorCode
    next_call: Literal["never"]
    effect: EffectState
    retry: RetryClass
    recommended_action: RecommendedAction


@dataclass(frozen=True)
class ServiceIndeterminate:
    kind: Literal["indeterminate"]
    verb: ProductVerb
    code: AuthsErrorCode
    next_call: Literal["backoff", "reconcile"]
    effect: EffectState
    retry: RetryClass
    recommended_action: RecommendedAction


@dataclass(frozen=True)
class ServiceRecoverable:
    kind: Literal["recoverable"]
    verb: Literal["execute", "resume"]
    code: AuthsErrorCode
    next_call: Literal["resume"]
    effect: EffectState
    retry: RetryClass
    recommended_action: RecommendedAction
    reference: ServiceRecoveryReference


@dataclass(frozen=True)
class ServiceCompleted:
    kind: Literal["completed"]
    verb: Literal["execute", "resume"]
    value: Optional[bytes]
    receipt: ServiceReceipt


@dataclass(frozen=True)
class ServiceVerified:
    kind: Literal["verified"]
    verb: Literal["verify"]
    value: Optional[bytes]


@dataclass(frozen=True)
class ServiceRejected:
    kind: Literal["rejected"]
    verb: Literal["verify"]
    code: AuthsErrorCode
    next_call: Literal["never"]
    effect: EffectState
    retry: RetryClass
    recommended_action: RecommendedAction


ServiceAuthorityResult = Union[
    ServiceAuthority, ServiceDenied, ServiceIndeterminate
]
ServiceExecutionResult = Union[
    ServiceCompleted,
    ServiceDenied,
    ServiceIndeterminate,
    ServiceRecoverable,
]
ServiceVerificationResult = Union[
    ServiceVerified, ServiceRejected, ServiceIndeterminate
]


class ServiceAuths:
    def __init__(
        self,
        *,
        endpoint: str,
        identity: bytes,
        profile: ServiceProfile,
        transport: Optional[ServiceTransport] = None,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._endpoint = _parse_endpoint(endpoint)
        self._identity = _bounded_bytes(identity, 65_536, "identity")
        if type(profile) is not ServiceProfile or profile.id not in _PROFILE_IDS:
            raise TypeError("Auths production profile is unsupported")
        if (
            type(timeout_seconds) not in (int, float)
            or timeout_seconds < 0.1
            or timeout_seconds > 120
        ):
            raise ValueError("Auths production timeout is outside bounds")
        if transport is not None and not isinstance(transport, ServiceTransport):
            raise TypeError("Auths production transport is invalid")
        self._profile = profile
        self._transport = transport or _UrlLibServiceTransport()
        self._timeout_seconds = float(timeout_seconds)

    async def create(self, request: bytes) -> ServiceAuthorityResult:
        projection = await self._call("create", body=request)
        if projection["kind"] == "completed":
            return ServiceAuthority(_AUTHORITY_TOKEN, _required_value(projection))
        return _authority_failure("create", projection)

    async def delegate(
        self,
        authority: ServiceAuthority,
        subject: bytes,
        attenuation: bytes = b"\x80",
    ) -> ServiceAuthorityResult:
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
            return ServiceAuthority(_AUTHORITY_TOKEN, _required_value(projection))
        return _authority_failure("delegate", projection)

    async def execute(
        self, authority: ServiceAuthority, action: bytes
    ) -> ServiceExecutionResult:
        return _execution_result(
            "execute",
            await self._call(
                "execute", authority=_authority_bytes(authority), body=action
            ),
        )

    async def resume(
        self, reference: ServiceRecoveryReference
    ) -> ServiceExecutionResult:
        if type(reference) is not ServiceRecoveryReference:
            raise TypeError("forged Auths recovery reference")
        return _execution_result(
            "resume",
            await self._call("resume", recovery_reference=reference._value),
        )

    async def verify(
        self, value: Union[ServiceAuthority, ServiceReceipt, bytes]
    ) -> ServiceVerificationResult:
        if type(value) is ServiceAuthority:
            body = value._bytes
        elif type(value) is ServiceReceipt:
            body = value._bytes
        else:
            body = _bounded_bytes(value, _MAX_RESPONSE_BYTES, "verification input")
        projection = await self._call("verify", body=body)
        if projection["kind"] == "verified":
            return ServiceVerified("verified", "verify", _optional_bytes(projection["value"]))
        if projection["kind"] == "rejected":
            code = _required_code(projection)
            return ServiceRejected(
                "rejected", "verify", code, "never", *_axis(code)
            )
        if projection["kind"] == "indeterminate":
            return _indeterminate("verify", projection)
        raise TypeError("native response outcome does not match verify")

    async def _call(
        self,
        verb: ProductVerb,
        *,
        authority: Optional[bytes] = None,
        body: Optional[bytes] = None,
        recovery_reference: Optional[str] = None,
    ) -> Mapping[str, object]:
        request_body = bytes(
            encode_production_request_v1(
                verb,
                self._profile.id,
                self._identity,
                authority,
                None if body is None else _bounded_bytes(body, _MAX_RESPONSE_BYTES, "body"),
                recovery_reference,
            )
        )
        request = ServiceTransportRequest(
            self._endpoint + _endpoint_path(verb, self._profile.id),
            request_body,
            _CONTENT_TYPE,
            self._timeout_seconds,
        )
        try:
            response = await self._transport.send(request)
        except Exception:
            # The request left this process. The server may have applied the
            # effect and lost the response, so the effect is `possible`, never
            # `not-applied`: `core.runtime-unavailable` would tell a caller a
            # possibly-applied write is safe to blindly retry (contract 5.3).
            return _unreachable_projection()
        if (
            not 200 <= response.status < 300
            or response.content_type.split(";", 1)[0].strip().lower() != _CONTENT_TYPE
            or not response.body
            or len(response.body) > _MAX_RESPONSE_BYTES
        ):
            # A response this client cannot read is not evidence that nothing
            # happened. Same rule as an unreachable server.
            return _unreachable_projection()
        return _projection(decode_production_response_v1(response.body))


_UNREACHABLE_CODE: Final = "core.outcome-unknown"


def _unreachable_projection() -> Mapping[str, object]:
    return MappingProxyType(
        {
            "contractVersion": 1,
            "kind": "indeterminate",
            "code": _UNREACHABLE_CODE,
            "retry": "reconcile",
            "recoveryReference": None,
            "value": None,
            "receipt": None,
        }
    )


def _axis(code: str) -> tuple[EffectState, RetryClass, RecommendedAction]:
    """Reads Rust's classification of `code`, failing closed for unknown ones."""
    classification = classify(code)
    return (
        classification.effect,
        classification.retry,
        classification.recommended_action,
    )


def create_auths(
    *,
    endpoint: str,
    identity: bytes,
    profile: ServiceProfile,
    transport: Optional[ServiceTransport] = None,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> ServiceAuths:
    if production_client_contract_version_v1() != 1:
        raise RuntimeError("Auths production client contract mismatch")
    return ServiceAuths(
        endpoint=endpoint,
        identity=identity,
        profile=profile,
        transport=transport,
        timeout_seconds=timeout_seconds,
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: http.client.HTTPMessage,
        newurl: str,
    ) -> None:
        return None


class _UrlLibServiceTransport:
    async def send(
        self, request: ServiceTransportRequest
    ) -> ServiceTransportResponse:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _send_sync, request)


def _send_sync(request: ServiceTransportRequest) -> ServiceTransportResponse:
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
        status = response.status
        if type(status) is not int:
            raise TypeError("Auths production response has no HTTP status")
        return ServiceTransportResponse(
            status, response.headers.get("Content-Type", ""), body
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


def _endpoint_path(verb: ProductVerb, profile: str) -> str:
    if verb == "create":
        return "/v1/authority/create"
    if verb == "delegate":
        return "/v1/authority/delegate"
    if verb == "resume":
        return "/v1/workflows/resume"
    if verb == "verify":
        return "/v1/authority/verify"
    return {
        _PROFILE_IDS[0]: "/v1/profiles/opentofu/saved-plan-apply/execute",
        _PROFILE_IDS[1]: "/v1/profiles/postgresql/bounded-update/execute",
        _PROFILE_IDS[2]: "/v1/profiles/github/issue-address/execute",
    }[profile]


def _projection(value: str) -> Mapping[str, object]:
    parsed: object = json.loads(value)
    if type(parsed) is not dict:
        raise TypeError("native response projection is invalid")
    projection = cast("dict[str, object]", parsed)
    if (
        projection.get("contractVersion") != 1
        or projection.get("kind")
        not in (
            "completed",
            "denied",
            "indeterminate",
            "recoverable",
            "verified",
            "rejected",
        )
        or projection.get("retry") not in ("never", "backoff", "resume", "reconcile")
    ):
        raise TypeError("native response projection is invalid")
    return MappingProxyType(projection)


def _authority_failure(
    verb: Literal["create", "delegate"], projection: Mapping[str, object]
) -> Union[ServiceDenied, ServiceIndeterminate]:
    if projection["kind"] == "denied":
        code = _required_code(projection)
        return ServiceDenied("denied", verb, code, "never", *_axis(code))
    if projection["kind"] == "indeterminate":
        return _indeterminate(verb, projection)
    raise TypeError("native response outcome does not match " + verb)


def _execution_result(
    verb: Literal["execute", "resume"], projection: Mapping[str, object]
) -> ServiceExecutionResult:
    if projection["kind"] == "completed":
        receipt = _optional_bytes(projection["receipt"])
        if receipt is None:
            raise TypeError("native response omitted receipt bytes")
        return ServiceCompleted(
            "completed",
            verb,
            _optional_bytes(projection["value"]),
            ServiceReceipt(_RECEIPT_TOKEN, receipt),
        )
    if projection["kind"] == "denied":
        code = _required_code(projection)
        return ServiceDenied("denied", verb, code, "never", *_axis(code))
    if projection["kind"] == "indeterminate":
        return _indeterminate(verb, projection)
    reference = projection.get("recoveryReference")
    if projection["kind"] == "recoverable" and type(reference) is str:
        code = _required_code(projection)
        return ServiceRecoverable(
            "recoverable",
            verb,
            code,
            "resume",
            *_axis(code),
            ServiceRecoveryReference(_REFERENCE_TOKEN, reference),
        )
    raise TypeError("native response outcome does not match " + verb)


def _indeterminate(
    verb: ProductVerb, projection: Mapping[str, object]
) -> ServiceIndeterminate:
    next_call = projection["retry"]
    if next_call not in ("backoff", "reconcile"):
        raise TypeError("native indeterminate result has an invalid next call")
    code = _required_code(projection)
    return ServiceIndeterminate(
        "indeterminate",
        verb,
        code,
        cast(Literal["backoff", "reconcile"], next_call),
        *_axis(code),
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


def _authority_bytes(value: ServiceAuthority) -> bytes:
    if type(value) is not ServiceAuthority:
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
    "NextCall",
    "ServiceAuths",
    "ServiceAuthority",
    "ServiceAuthorityResult",
    "ServiceCompleted",
    "ServiceDenied",
    "ServiceExecutionResult",
    "ServiceIndeterminate",
    "ServiceReceipt",
    "ServiceRecoverable",
    "ServiceRecoveryReference",
    "ServiceRejected",
    "ServiceTransport",
    "ServiceTransportRequest",
    "ServiceTransportResponse",
    "ServiceVerificationResult",
    "ServiceVerified",
    "create_auths",
]
