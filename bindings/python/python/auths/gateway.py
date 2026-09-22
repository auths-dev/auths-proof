"""Proof/action-only client for a separately operated Auths gateway.

This client does not accept a provider URL, method, body, header, or credential.
It does not establish deployment isolation: that is an operator property.
"""

from __future__ import annotations

import asyncio
import base64
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Union

_REQUEST_SCHEMA = "auths.gateway-submit/1"
_MAX_PROOF_BYTES = 4 * 1024 * 1024
_MAX_ACTION_BYTES = 64 * 1024
_MAX_RESPONSE_BYTES = 8 * 1024


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


GatewayResult = Union[
    GatewayDenied,
    GatewayIndeterminate,
    GatewayNotEntered,
    GatewayUnknown,
    GatewayResponseRecorded,
    GatewayObserved,
]


def _parse_result(raw: bytes) -> GatewayResult:
    try:
        decoded = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as error:
        raise GatewayProtocolError("gateway returned invalid JSON") from error
    if not isinstance(decoded, dict):
        raise GatewayProtocolError("gateway returned invalid result")
    outcome = decoded.get("outcome")
    if outcome in {"denied", "indeterminate", "not-entered"}:
        if set(decoded) != {"outcome", "code"} or not isinstance(decoded["code"], str):
            raise GatewayProtocolError("gateway returned invalid refusal")
        if not 1 <= len(decoded["code"]) <= 128:
            raise GatewayProtocolError("gateway returned invalid code")
        if outcome == "denied":
            return GatewayDenied(decoded["code"])
        if outcome == "indeterminate":
            return GatewayIndeterminate(decoded["code"])
        return GatewayNotEntered(decoded["code"])
    if outcome == "unknown" and set(decoded) == {"outcome"}:
        return GatewayUnknown()
    if outcome in {"response-recorded", "observed"}:
        expected = (
            {"outcome", "status"}
            if outcome == "response-recorded"
            else {"outcome", "status", "matched"}
        )
        status = decoded.get("status")
        if (
            set(decoded) != expected
            or type(status) is not int
            or not 100 <= status <= 599
        ):
            raise GatewayProtocolError("gateway returned invalid response stage")
        if outcome == "response-recorded":
            return GatewayResponseRecorded(status)
        if type(decoded.get("matched")) is not bool:
            raise GatewayProtocolError("gateway returned invalid observation")
        return GatewayObserved(status, decoded["matched"])
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
    "GatewayProtocolError",
    "GatewayResponseRecorded",
    "GatewayResult",
    "GatewayUnknown",
]
