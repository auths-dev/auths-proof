"""Proof/action-only application socket behavior with no provider credential."""

from __future__ import annotations

import asyncio
import base64
import json
import struct
import sys
from pathlib import Path
from typing import Optional

import pytest

from auths.gateway import (
    GatewayClient,
    GatewayEndpoint,
    GatewayObservationRefused,
    GatewayObserved,
    GatewayObservedByProvider,
    GatewayProtocolError,
    GatewayProviderEvidence,
    GatewaySignedObservation,
    GatewayUnknown,
)

_ECHO = "auths-e1-" + "ab" * 32
_DIGEST = "cd" * 32


def _provider_result(status: object = 200, **evidence: object) -> bytes:
    body = {
        "channel": "read-back",
        "echo": _ECHO,
        "evidence_digest": _DIGEST,
        "observed_at": 1_790_000_000,
    }
    body.update(evidence)
    return json.dumps(
        {"outcome": "observed-by-provider", "status": status, "evidence": body}
    ).encode()


@pytest.mark.skipif(
    sys.platform == "win32", reason="first gateway deployment is Unix-only"
)
def test_client_sends_only_proof_and_action(tmp_path) -> None:
    async def scenario() -> None:
        socket = tmp_path / "gateway.sock"
        seen: list[dict[str, str]] = []

        async def handle(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            length = struct.unpack(">I", await reader.readexactly(4))[0]
            seen.append(json.loads(await reader.readexactly(length)))
            result = b'{"outcome":"observed","status":200,"matched":true}'
            writer.write(struct.pack(">I", len(result)) + result)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_unix_server(handle, path=str(socket))
        async with server:
            result = await GatewayClient(GatewayEndpoint(socket)).submit(
                proof=b"proof", action=b"action"
            )
        assert result == GatewayObserved(status=200, matched=True)
        assert seen == [
            {
                "schema": "auths.gateway-submit/1",
                "proof_b64": "cHJvb2Y",
                "action_b64": "YWN0aW9u",
            }
        ]

    asyncio.run(scenario())


def test_client_rejects_invalid_endpoint_and_oversized_input(tmp_path) -> None:
    with pytest.raises(ValueError):
        GatewayEndpoint(tmp_path.name)  # type: ignore[arg-type]
    client = GatewayClient(GatewayEndpoint(tmp_path / "gateway.sock"))
    with pytest.raises(ValueError):
        asyncio.run(client.submit(proof=b"", action=b"action"))


def test_result_parser_does_not_infer_effect() -> None:
    from auths.gateway import _parse_result

    assert _parse_result(b'{"outcome":"unknown"}') == GatewayUnknown()
    for hostile in [
        b'{"outcome":"observed","status":200,"matched":"yes"}',
        b'{"outcome":"response-recorded","status":200,"provider_success":true}',
        b'{"outcome":"success"}',
    ]:
        with pytest.raises(GatewayProtocolError):
            _parse_result(hostile)


def test_result_parser_exposes_observed_by_provider_without_evidence_bytes() -> None:
    from auths.gateway import _parse_result

    evidence = GatewayProviderEvidence("read-back", _ECHO, _DIGEST, 1_790_000_000)
    assert _parse_result(_provider_result()) == GatewayObservedByProvider(200, evidence)
    assert _parse_result(_provider_result(None)) == GatewayObservedByProvider(
        None, evidence
    )
    for hostile in [
        _provider_result(True),
        _provider_result(99),
        _provider_result(channel="webhook"),
        _provider_result(echo="auths-e1-app-supplied"),
        _provider_result(echo=_ECHO.upper()),
        _provider_result(evidence_digest="00"),
        _provider_result(observed_at=-1),
        _provider_result(observed_at=True),
        _provider_result(evidence_b64="e30"),
        b'{"outcome":"observed-by-provider","status":200}',
        b'{"outcome":"observed-by-provider","status":200,"evidence":[],"confirmed":true}',
    ]:
        with pytest.raises(GatewayProtocolError):
            _parse_result(hostile)


_MEDIA_TYPE = "application/vnd.auths.observation.v1+cbor"
_OBSERVATION = bytes(range(256)) * 2
_SUBJECT = "https://api.airtable.com/v0/app/tbl/rec#/fields/DemoStatus"


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _signed(**overrides: object) -> bytes:
    body: dict[str, object] = {
        "outcome": "signed",
        "schema": "auths.gateway-readback/1",
        "subject": _SUBJECT,
        "observed_at": 1_790_000_000,
        "media_type": _MEDIA_TYPE,
        "observation_b64": _b64(_OBSERVATION),
    }
    body.update(overrides)
    return json.dumps(body).encode()


async def _serve_once(
    socket: Path, reply: bytes, seen: list[dict[str, object]]
) -> asyncio.AbstractServer:
    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        length = struct.unpack(">I", await reader.readexactly(4))[0]
        seen.append(json.loads(await reader.readexactly(length)))
        writer.write(struct.pack(">I", len(reply)) + reply)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    return await asyncio.start_unix_server(handle, path=str(socket))


@pytest.mark.skipif(
    sys.platform == "win32", reason="first gateway deployment is Unix-only"
)
def test_client_requests_read_back_and_returns_signed_bytes(tmp_path) -> None:
    async def scenario() -> None:
        seen: list[dict[str, object]] = []
        server = await _serve_once(tmp_path / "gateway.sock", _signed(), seen)
        async with server:
            client = GatewayClient(GatewayEndpoint(tmp_path / "gateway.sock"))
            result = await client.observe_read_back({"record_id": "recTEST0000000001"})
        assert result == GatewaySignedObservation(
            "auths.gateway-readback/1",
            _SUBJECT,
            1_790_000_000,
            _MEDIA_TYPE,
            _OBSERVATION,
        )
        assert seen == [
            {
                "schema": "auths.gateway-observe/1",
                "request": {
                    "kind": "read-back",
                    "arguments": {"record_id": "recTEST0000000001"},
                },
            }
        ]

    asyncio.run(scenario())


@pytest.mark.skipif(
    sys.platform == "win32", reason="first gateway deployment is Unix-only"
)
def test_client_requests_outcome_and_surfaces_refusal(tmp_path) -> None:
    async def scenario(reply: bytes) -> tuple[object, list[dict[str, object]]]:
        seen: list[dict[str, object]] = []
        server = await _serve_once(tmp_path / "gateway.sock", reply, seen)
        async with server:
            client = GatewayClient(GatewayEndpoint(tmp_path / "gateway.sock"))
            return await client.observe_outcome("step-1"), seen

    subject = "auths-gateway://ns/operations/step-1"
    signed, seen = asyncio.run(
        scenario(_signed(schema="auths.gateway-outcome/1", subject=subject))
    )
    assert signed == GatewaySignedObservation(
        "auths.gateway-outcome/1", subject, 1_790_000_000, _MEDIA_TYPE, _OBSERVATION
    )
    assert seen == [
        {
            "schema": "auths.gateway-observe/1",
            "request": {"kind": "outcome", "operation_id": "step-1"},
        }
    ]
    refused, _ = asyncio.run(
        scenario(b'{"outcome":"refused","code":"gateway.observer.not-provisioned"}')
    )
    assert refused == GatewayObservationRefused("gateway.observer.not-provisioned")


@pytest.mark.skipif(
    sys.platform == "win32", reason="first gateway deployment is Unix-only"
)
def test_client_rejects_malformed_observation_frames(tmp_path) -> None:
    async def scenario(reply: bytes, outcome: Optional[str] = None) -> object:
        server = await _serve_once(tmp_path / "gateway.sock", reply, [])
        async with server:
            client = GatewayClient(GatewayEndpoint(tmp_path / "gateway.sock"))
            if outcome is not None:
                return await client.observe_outcome(outcome)
            return await client.observe_read_back({"record_id": "rec1"})

    # A signed read-back is not accepted as the answer to an outcome request.
    with pytest.raises(GatewayProtocolError):
        asyncio.run(scenario(_signed(), "step-1"))
    for hostile in [
        _signed(schema="auths.gateway-outcome/1"),
        _signed(media_type="application/cbor"),
        _signed(subject=""),
        _signed(subject="s" * 1_025),
        _signed(observed_at=-1),
        _signed(observed_at=True),
        _signed(observed_at="1790000000"),
        _signed(observation_b64=""),
        _signed(observation_b64=_b64(_OBSERVATION) + "="),
        _signed(observation_b64=base64.b64encode(b"\xfb\xff").decode()),
        _signed(observation_b64="AB"),
        _signed(observation_b64="A"),
        _signed(observation_b64="QUJD RA"),
        _signed(observation_b64=_b64(b"x" * 4_097)),
        _signed(confirmed=True),
        _signed(observation=_b64(_OBSERVATION)),
        b'{"outcome":"refused"}',
        b'{"outcome":"refused","code":""}',
        b'{"outcome":"refused","code":"x","reason":"y"}',
        b'{"outcome":"observed","status":200,"matched":true}',
        b'{"outcome":"signed"}',
        b"[]",
        b"not json",
    ]:
        with pytest.raises(GatewayProtocolError):
            asyncio.run(scenario(hostile))


def test_client_rejects_unbounded_observation_requests(tmp_path) -> None:
    client = GatewayClient(GatewayEndpoint(tmp_path / "gateway.sock"))
    for arguments in [
        {},
        {"record_id": ""},
        {"record_id": "x" * 129},
        {"record_id": "a\x00b"},
        {"record_id": 7},
        {"-record": "rec1"},
        {f"field{index}": "v" for index in range(17)},
    ]:
        with pytest.raises(ValueError):
            asyncio.run(client.observe_read_back(arguments))  # type: ignore[arg-type]
    for operation in ["", "-step", "step 1", "s" * 129, "stép"]:
        with pytest.raises(ValueError):
            asyncio.run(client.observe_outcome(operation))
