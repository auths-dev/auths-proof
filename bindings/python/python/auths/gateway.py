"""Proof/action-only client for a separately operated Auths gateway.

This client does not accept a provider URL, method, body, header, or credential.
It does not establish deployment isolation: that is an operator property.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Mapping, Optional, Union, cast

_REQUEST_SCHEMA = "auths.gateway-submit/1"
_MAX_PROOF_BYTES = 4 * 1024 * 1024
_MAX_ACTION_BYTES = 64 * 1024
_MAX_RESPONSE_BYTES = 8 * 1024
_ECHO = re.compile(r"auths-e1-[0-9a-f]{64}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
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


class GatewayClient:
    """Submit only canonical proof and action bytes over the local app socket."""

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
                "proof_b64": base64.urlsafe_b64encode(proof)
                .rstrip(b"=")
                .decode("ascii"),
                "action_b64": base64.urlsafe_b64encode(action)
                .rstrip(b"=")
                .decode("ascii"),
            },
            separators=(",", ":"),
        ).encode("utf-8")
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
            raise GatewayProtocolError(
                "gateway exchange unavailable; outcome may be unknown"
            ) from error
        return _parse_result(response)


__all__ = [
    "GatewayClient",
    "GatewayDenied",
    "GatewayEndpoint",
    "GatewayIndeterminate",
    "GatewayNotEntered",
    "GatewayObserved",
    "GatewayObservedByProvider",
    "GatewayProtocolError",
    "GatewayProviderEvidence",
    "GatewayResponseRecorded",
    "GatewayResult",
    "GatewayUnknown",
]
