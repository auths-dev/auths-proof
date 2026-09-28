"""Signed outcome `/2` conformance: the Python SDK accepts every vector the
gateway signs, refuses the retired schema, and its native verifier reaches
the gateway's decision on a grant that requires the outcome's stage."""

from __future__ import annotations

import asyncio
import base64
import json
import struct
import sys
from pathlib import Path
from typing import Any

import pytest
from auths import _native
from auths.gateway import (
    GatewayClient,
    GatewayEndpoint,
    GatewayProtocolError,
    GatewaySignedObservation,
)

FIXTURE: dict[str, Any] = json.loads(
    (Path(__file__).parents[2] / "fixtures" / "gateway" / "outcome-v2.json").read_text()
)
MEDIA_TYPE = "application/vnd.auths.observation.v1+cbor"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _observation(entry: dict[str, Any]) -> bytes:
    return base64.b64decode(entry["observation_b64"])


def _operation(entry: dict[str, Any]) -> str:
    return str(entry["subject"]).rsplit("/", 1)[1]


async def _observe_outcome(socket: Path, entry: dict[str, Any], schema: str) -> object:
    reply = json.dumps(
        {
            "outcome": "signed",
            "schema": schema,
            "subject": entry["subject"],
            "observed_at": FIXTURE["observed_at"],
            "media_type": MEDIA_TYPE,
            "observation_b64": _b64url(_observation(entry)),
        }
    ).encode()

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        length = struct.unpack(">I", await reader.readexactly(4))[0]
        await reader.readexactly(length)
        writer.write(struct.pack(">I", len(reply)) + reply)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_unix_server(handle, path=str(socket))
    async with server:
        return await GatewayClient(GatewayEndpoint(socket)).observe_outcome(
            _operation(entry)
        )


def test_fixture_names_outcome_v2() -> None:
    assert FIXTURE["outcome_schema"] == "auths.gateway-outcome/2"
    assert FIXTURE["accepted"] and FIXTURE["refused"] and FIXTURE["verdicts"]


@pytest.mark.skipif(
    sys.platform == "win32", reason="first gateway deployment is Unix-only"
)
@pytest.mark.parametrize("entry", FIXTURE["accepted"], ids=lambda entry: entry["id"])
def test_python_client_accepts_every_signed_outcome(
    entry: dict[str, Any], tmp_path: Path
) -> None:
    result = asyncio.run(
        _observe_outcome(tmp_path / "gateway.sock", entry, "auths.gateway-outcome/2")
    )
    assert result == GatewaySignedObservation(
        "auths.gateway-outcome/2",
        entry["subject"],
        FIXTURE["observed_at"],
        MEDIA_TYPE,
        _observation(entry),
    )


@pytest.mark.skipif(
    sys.platform == "win32", reason="first gateway deployment is Unix-only"
)
def test_python_client_refuses_the_retired_outcome_schema(tmp_path: Path) -> None:
    retired = next(
        entry for entry in FIXTURE["refused"] if entry["id"] == "outcome-v1-schema"
    )
    with pytest.raises(GatewayProtocolError):
        asyncio.run(
            _observe_outcome(
                tmp_path / "gateway.sock", retired, "auths.gateway-outcome/1"
            )
        )


@pytest.mark.parametrize("case", FIXTURE["verdicts"], ids=lambda case: case["id"])
def test_python_verifier_reaches_the_gateway_verdict(case: dict[str, Any]) -> None:
    verdict = _native.verify_v1(
        _unb64url(case["proof_b64"]),
        _unb64url(case["action_b64"]),
        _unb64url(FIXTURE["verdict_trusted_context_b64"]),
    )
    assert verdict.kind == case["decision"]
    assert verdict.code == case["code"]
