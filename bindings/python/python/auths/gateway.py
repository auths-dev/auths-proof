"""Proof/action-only client for a separately operated Auths gateway.

This client does not accept a provider URL, method, body, header, or credential.
It does not establish deployment isolation: that is an operator property.
Besides submission, it can ask the gateway for one signed observation (a
read-back of the recipe's observed field, or the stored outcome of a logical
operation) to attach to a later action; an observation request never writes.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, Mapping, Optional, Union, cast

_REQUEST_SCHEMA = "auths.gateway-submit/1"
_OBSERVE_SCHEMA = "auths.gateway-observe/1"
_READ_BACK_SCHEMA: Final = "auths.gateway-readback/1"
_OUTCOME_SCHEMA: Final = "auths.gateway-outcome/1"
_OBSERVATION_MEDIA_TYPE = "application/vnd.auths.observation.v1+cbor"
_MAX_OBSERVATION_BYTES = 4_096
_MAX_SUBJECT_BYTES = 1_024
_MAX_READ_BACK_ARGUMENTS = 16
_MAX_ARGUMENT_BYTES = 128
_MAX_PROOF_BYTES = 4 * 1024 * 1024
_MAX_ACTION_BYTES = 64 * 1024
_MAX_RESPONSE_BYTES = 8 * 1024
_ECHO = re.compile(r"auths-e1-[0-9a-f]{64}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_FIELD_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_OPERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_BASE64URL = re.compile(r"[A-Za-z0-9_-]*")
_MAX_U64 = 2**64 - 1


class GatewayProtocolError(RuntimeError):
    """The gateway socket or its bounded response was unavailable or malformed."""


@dataclass(frozen=True)
class GatewayEndpoint:
    """Absolute path to an operator-provisioned local application socket."""

    path: Path

    def __post_init__(self) -> None:
        if (
            not isinstance(self.path, Path)
            or not self.path.is_absolute()
            or "\x00" in str(self.path)
        ):
            raise ValueError("gateway endpoint must be an absolute Unix socket path")
        if len(str(self.path).encode()) > 100:
            raise ValueError("gateway socket path is too long")


@dataclass(frozen=True)
class GatewayDenied:
    """Native proof verification denied the exact action."""

    code: str
    outcome: Literal["denied"] = "denied"


@dataclass(frozen=True)
class GatewayIndeterminate:
    """Native proof verification could not authorize the action."""

    code: str
    outcome: Literal["indeterminate"] = "indeterminate"


@dataclass(frozen=True)
class GatewayNotEntered:
    """The gateway refused provider entry after proof verification."""

    code: str
    outcome: Literal["not-entered"] = "not-entered"


@dataclass(frozen=True)
class GatewayUnknown:
    """Provider entry or effect is ambiguous; do not automatically retry."""

    outcome: Literal["unknown"] = "unknown"


@dataclass(frozen=True)
class GatewayResponseRecorded:
    """A complete HTTP response was recorded; effect is not established."""

    status: int
    outcome: Literal["response-recorded"] = "response-recorded"


@dataclass(frozen=True)
class GatewayObserved:
    """Separate read-back matched or differed; match is not causation."""

    status: int
    matched: bool
    outcome: Literal["observed"] = "observed"


@dataclass(frozen=True)
class GatewayProviderEvidence:
    """Secret-free summary of provider-held read-back evidence.

    The response bytes and observation locator stay in the operator's attempt
    store. ``observed_at`` is gateway wall-clock seconds and is not
    authenticated.
    """

    channel: Literal["read-back"]
    echo: str
    evidence_digest: str
    observed_at: int


@dataclass(frozen=True)
class GatewayObservedByProvider:
    """Read-back returned this attempt's echo token and the verified value.

    The token is derived from the authorized action, but anyone who knows the
    namespace, operation ID, and action commitment can compute it: the link
    holds only while no other party with write access to that provider field
    wrote the same token. ``status`` is ``None`` when the write was unknown.
    """

    status: Optional[int]
    evidence: GatewayProviderEvidence
    outcome: Literal["observed-by-provider"] = "observed-by-provider"


GatewayResult = Union[
    GatewayDenied,
    GatewayIndeterminate,
    GatewayNotEntered,
    GatewayUnknown,
    GatewayResponseRecorded,
    GatewayObserved,
    GatewayObservedByProvider,
]


def _valid_status(status: object) -> bool:
    return (
        isinstance(status, int)
        and not isinstance(status, bool)
        and 100 <= status <= 599
    )


def _parse_evidence(value: object) -> GatewayProviderEvidence:
    if not isinstance(value, dict):
        raise GatewayProtocolError("gateway returned invalid evidence")
    evidence = cast(Mapping[str, object], value)
    channel = evidence.get("channel")
    echo = evidence.get("echo")
    digest = evidence.get("evidence_digest")
    observed_at = evidence.get("observed_at")
    if (
        set(evidence) != {"channel", "echo", "evidence_digest", "observed_at"}
        or channel != "read-back"
        or not isinstance(echo, str)
        or _ECHO.fullmatch(echo) is None
        or not isinstance(digest, str)
        or _DIGEST.fullmatch(digest) is None
        or not isinstance(observed_at, int)
        or isinstance(observed_at, bool)
        or not 0 <= observed_at <= _MAX_U64
    ):
        raise GatewayProtocolError("gateway returned invalid evidence")
    return GatewayProviderEvidence("read-back", echo, digest, observed_at)


def _parse_result(raw: bytes) -> GatewayResult:
    try:
        decoded: object = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as error:
        raise GatewayProtocolError("gateway returned invalid JSON") from error
    if not isinstance(decoded, dict):
        raise GatewayProtocolError("gateway returned invalid result")
    value = cast(Mapping[str, object], decoded)
    outcome = value.get("outcome")
    if outcome in {"denied", "indeterminate", "not-entered"}:
        code = value.get("code")
        if set(value) != {"outcome", "code"} or not isinstance(code, str):
            raise GatewayProtocolError("gateway returned invalid refusal")
        if not 1 <= len(code) <= 128:
            raise GatewayProtocolError("gateway returned invalid code")
        if outcome == "denied":
            return GatewayDenied(code)
        if outcome == "indeterminate":
            return GatewayIndeterminate(code)
        return GatewayNotEntered(code)
    if outcome == "unknown" and set(value) == {"outcome"}:
        return GatewayUnknown()
    if outcome == "observed-by-provider":
        status = value.get("status")
        if set(value) != {"outcome", "status", "evidence"} or not (
            status is None or _valid_status(status)
        ):
            raise GatewayProtocolError("gateway returned invalid provider observation")
        return GatewayObservedByProvider(
            cast(Optional[int], status), _parse_evidence(value.get("evidence"))
        )
    if outcome in {"response-recorded", "observed"}:
        expected = (
            {"outcome", "status"}
            if outcome == "response-recorded"
            else {"outcome", "status", "matched"}
        )
        status = value.get("status")
        if set(value) != expected or not _valid_status(status):
            raise GatewayProtocolError("gateway returned invalid response stage")
        status = cast(int, status)
        if outcome == "response-recorded":
            return GatewayResponseRecorded(status)
        matched = value.get("matched")
        if not isinstance(matched, bool):
            raise GatewayProtocolError("gateway returned invalid observation")
        return GatewayObserved(status, matched)
    raise GatewayProtocolError("gateway returned unknown result stage")


@dataclass(frozen=True)
class GatewaySignedObservation:
    """One canonical gateway-signed observation to attach to a later action.

    ``observation`` is the exact signed CBOR; attach it unmodified as a
    detached attachment whose descriptor media type is ``media_type``. The
    observation asserts only what the gateway saw at ``observed_at`` (gateway
    wall-clock seconds, covered by the signature); it is not a write receipt
    and does not prove the fact still holds. ``schema`` is
    ``auths.gateway-readback/1`` for a read-back and ``auths.gateway-outcome/1``
    for an operation outcome.
    """

    schema: Literal["auths.gateway-readback/1", "auths.gateway-outcome/1"]
    subject: str
    observed_at: int
    media_type: Literal["application/vnd.auths.observation.v1+cbor"]
    observation: bytes
    outcome: Literal["signed"] = "signed"


@dataclass(frozen=True)
class GatewayObservationRefused:
    """The gateway signed nothing; ``code`` is its stable refusal code."""

    code: str
    outcome: Literal["refused"] = "refused"


GatewayObserveResult = Union[GatewaySignedObservation, GatewayObservationRefused]


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_base64url(text: str, maximum: int) -> bytes:
    """Decode canonical unpadded base64url, rejecting any other spelling."""
    if (
        len(text) > (maximum * 4 + 2) // 3
        or _BASE64URL.fullmatch(text) is None
        or len(text) % 4 == 1
    ):
        raise GatewayProtocolError("gateway returned invalid observation encoding")
    decoded = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if not 1 <= len(decoded) <= maximum or _encode_base64url(decoded) != text:
        raise GatewayProtocolError("gateway returned invalid observation encoding")
    return decoded


def _parse_observe_result(
    raw: bytes, schema: Literal["auths.gateway-readback/1", "auths.gateway-outcome/1"]
) -> GatewayObserveResult:
    try:
        decoded: object = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as error:
        raise GatewayProtocolError("gateway returned invalid JSON") from error
    if not isinstance(decoded, dict):
        raise GatewayProtocolError("gateway returned invalid observation result")
    value = cast(Mapping[str, object], decoded)
    outcome = value.get("outcome")
    if outcome == "refused":
        code = value.get("code")
        if (
            set(value) != {"outcome", "code"}
            or not isinstance(code, str)
            or not 1 <= len(code) <= 128
        ):
            raise GatewayProtocolError("gateway returned invalid refusal")
        return GatewayObservationRefused(code)
    if outcome != "signed":
        raise GatewayProtocolError("gateway returned unknown observation result")
    subject = value.get("subject")
    observed_at = value.get("observed_at")
    encoded = value.get("observation_b64")
    if (
        set(value)
        != {
            "outcome",
            "schema",
            "subject",
            "observed_at",
            "media_type",
            "observation_b64",
        }
        or value.get("schema") != schema
        or value.get("media_type") != _OBSERVATION_MEDIA_TYPE
        or not isinstance(subject, str)
        or not 1 <= len(subject.encode("utf-8", "surrogatepass")) <= _MAX_SUBJECT_BYTES
        or not isinstance(observed_at, int)
        or isinstance(observed_at, bool)
        or not 0 <= observed_at <= _MAX_U64
        or not isinstance(encoded, str)
    ):
        raise GatewayProtocolError("gateway returned invalid signed observation")
    return GatewaySignedObservation(
        schema,
        subject,
        observed_at,
        "application/vnd.auths.observation.v1+cbor",
        _decode_base64url(encoded, _MAX_OBSERVATION_BYTES),
    )


def _read_back_request(arguments: Mapping[str, str]) -> dict[str, object]:
    if not isinstance(arguments, Mapping) or not (
        1 <= len(arguments) <= _MAX_READ_BACK_ARGUMENTS
    ):
        raise ValueError("read-back arguments must be a bounded mapping")
    checked: dict[str, str] = {}
    for name, value in cast(Mapping[object, object], arguments).items():
        if not isinstance(name, str) or _FIELD_NAME.fullmatch(name) is None:
            raise ValueError("read-back argument names must be recipe field names")
        if (
            not isinstance(value, str)
            or "\x00" in value
            or not 1
            <= len(value.encode("utf-8", "surrogatepass"))
            <= _MAX_ARGUMENT_BYTES
        ):
            raise ValueError("read-back argument values must be bounded strings")
        checked[name] = value
    return {"kind": "read-back", "arguments": checked}


class GatewayClient:
    """Submit only canonical proof and action bytes over the local app socket,
    or request one read-only gateway-signed observation."""

    def __init__(self, endpoint: GatewayEndpoint) -> None:
        if not isinstance(endpoint, GatewayEndpoint):
            raise TypeError("endpoint must be a GatewayEndpoint")
        self._endpoint = endpoint

    async def submit(self, *, proof: bytes, action: bytes) -> GatewayResult:
        """Return proof/transport stage without implying provider effect.

        An IPC failure is not a retry signal: the gateway may have entered the
        provider before the client lost its response.
        """
        if not isinstance(proof, bytes) or not 1 <= len(proof) <= _MAX_PROOF_BYTES:
            raise ValueError("proof must be bounded bytes")
        if not isinstance(action, bytes) or not 1 <= len(action) <= _MAX_ACTION_BYTES:
            raise ValueError("action must be bounded bytes")
        payload = json.dumps(
            {
                "schema": _REQUEST_SCHEMA,
                "proof_b64": _encode_base64url(proof),
                "action_b64": _encode_base64url(action),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        return _parse_result(
            await self._exchange(
                payload, "gateway exchange unavailable; outcome may be unknown"
            )
        )

    async def observe_read_back(
        self, arguments: Mapping[str, str]
    ) -> GatewayObserveResult:
        """Ask the gateway to read the recipe's observed field now and sign it.

        ``arguments`` names exactly the recipe observation path's fields (for
        example ``{"record_id": "rec..."}``); the gateway derives the URL,
        subject, and time itself. The application learns the observed value.

        Raises ``ValueError`` for unbounded or non-string arguments and
        ``GatewayProtocolError`` when the socket or bounded response is
        unavailable or malformed. A refusal is a result, not an exception.
        """
        request = _read_back_request(arguments)
        return await self._observe(request, _READ_BACK_SCHEMA)

    async def observe_outcome(self, operation_id: str) -> GatewayObserveResult:
        """Ask the gateway to sign the stored outcome of one logical operation.

        The gateway reads only its own attempt store; no provider is contacted.
        ``operation_id`` is the 1-128-byte canonical ASCII token used when the
        operation was submitted.

        Raises ``ValueError`` for a noncanonical operation ID and
        ``GatewayProtocolError`` for an unavailable or malformed exchange.
        """
        if (
            not isinstance(operation_id, str)
            or _OPERATION_ID.fullmatch(operation_id) is None
        ):
            raise ValueError("operation ID must be a canonical 1-128-byte token")
        return await self._observe(
            {"kind": "outcome", "operation_id": operation_id}, _OUTCOME_SCHEMA
        )

    async def _observe(
        self,
        request: Mapping[str, object],
        schema: Literal["auths.gateway-readback/1", "auths.gateway-outcome/1"],
    ) -> GatewayObserveResult:
        payload = json.dumps(
            {"schema": _OBSERVE_SCHEMA, "request": request},
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return _parse_observe_result(
            await self._exchange(payload, "gateway observation exchange unavailable"),
            schema,
        )

    async def _exchange(self, payload: bytes, failure: str) -> bytes:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(str(self._endpoint.path)), timeout=5
            )
            try:
                writer.write(struct.pack(">I", len(payload)) + payload)
                await asyncio.wait_for(writer.drain(), timeout=5)
                length = struct.unpack(
                    ">I", await asyncio.wait_for(reader.readexactly(4), timeout=45)
                )[0]
                if not 1 <= length <= _MAX_RESPONSE_BYTES:
                    raise GatewayProtocolError("gateway response exceeded the bound")
                response = await asyncio.wait_for(reader.readexactly(length), timeout=5)
            finally:
                writer.close()
                await writer.wait_closed()
        except (OSError, asyncio.IncompleteReadError, TimeoutError) as error:
            raise GatewayProtocolError(failure) from error
        return response


__all__ = [
    "GatewayClient",
    "GatewayDenied",
    "GatewayEndpoint",
    "GatewayIndeterminate",
    "GatewayNotEntered",
    "GatewayObservationRefused",
    "GatewayObserveResult",
    "GatewayObserved",
    "GatewayObservedByProvider",
    "GatewayProtocolError",
    "GatewayProviderEvidence",
    "GatewayResponseRecorded",
    "GatewayResult",
    "GatewaySignedObservation",
    "GatewayUnknown",
]
