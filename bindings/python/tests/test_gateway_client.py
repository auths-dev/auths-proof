"""Proof/action-only application socket behavior with no provider credential."""

from __future__ import annotations

import asyncio
import base64
import errno
import json
import os
import shutil
import socket
import struct
import sys
import tempfile
from pathlib import Path
from typing import Iterator, Optional

import pytest

from auths.gateway import (
    GatewayClient,
    GatewayEndpoint,
    GatewayObservationRefused,
    GatewayNotEntered,
    GatewayObserved,
    GatewayObservedByProvider,
    GatewayPreEntryObservations,
    GatewayProtocolError,
    GatewayProviderEvidence,
    GatewaySignedObservation,
    GatewayUnknown,
)

_ECHO = "auths-e1-" + "ab" * 32
_DIGEST = "cd" * 32
_SOCKET_PATH_LIMIT = 107 if sys.platform.startswith("linux") else 103


@pytest.fixture
def socket_dir() -> Iterator[Path]:
    """A short directory for test sockets: on macOS pytest's ``tmp_path``
    lies under ``/var/folders`` and is too long for a Unix socket path."""
    directory = Path(
        tempfile.mkdtemp(dir=None if sys.platform == "win32" else "/tmp")
    ).resolve()
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


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
def test_client_sends_only_proof_and_action(socket_dir) -> None:
    async def scenario() -> None:
        socket = socket_dir / "gateway.sock"
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


def test_client_rejects_invalid_endpoint_and_oversized_input(socket_dir) -> None:
    with pytest.raises(ValueError):
        GatewayEndpoint(socket_dir.name)  # type: ignore[arg-type]
    client = GatewayClient(GatewayEndpoint(socket_dir / "gateway.sock"))
    with pytest.raises(ValueError):
        asyncio.run(client.submit(proof=b"", action=b"action"))


@pytest.mark.parametrize("code", [
    "gateway.qualification.missing",
    "gateway.qualification.expired",
    "gateway.qualification.revoked",
    "gateway.qualification.digest-mismatch",
    "gateway.qualification.target-mismatch",
    "gateway.qualification.unavailable",
    "gateway.qualification.revocation-stale",
    "gateway.qualification.clock-untrusted",
    "gateway.connection.restore-rollback",
])
def test_operator_gate_refusals_remain_not_entered_with_the_native_code(code) -> None:
    from auths.gateway import _parse_result

    result = _parse_result(json.dumps({"outcome": "not-entered", "code": code}).encode())
    assert result == GatewayNotEntered(code)
    assert result.outcome == "not-entered"


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
def test_client_requests_read_back_and_returns_signed_bytes(socket_dir) -> None:
    async def scenario() -> None:
        seen: list[dict[str, object]] = []
        server = await _serve_once(socket_dir / "gateway.sock", _signed(), seen)
        async with server:
            client = GatewayClient(GatewayEndpoint(socket_dir / "gateway.sock"))
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
                "schema": "auths.gateway-observe/2",
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
def test_client_requests_outcome_and_surfaces_refusal(socket_dir) -> None:
    async def scenario(reply: bytes) -> tuple[object, list[dict[str, object]]]:
        seen: list[dict[str, object]] = []
        server = await _serve_once(socket_dir / "gateway.sock", reply, seen)
        async with server:
            client = GatewayClient(GatewayEndpoint(socket_dir / "gateway.sock"))
            return await client.observe_outcome("step-1"), seen

    subject = "auths-gateway://ns/operations/step-1"
    signed, seen = asyncio.run(
        scenario(_signed(schema="auths.gateway-outcome/2", subject=subject))
    )
    assert signed == GatewaySignedObservation(
        "auths.gateway-outcome/2", subject, 1_790_000_000, _MEDIA_TYPE, _OBSERVATION
    )
    assert seen == [
        {
            "schema": "auths.gateway-observe/2",
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
def test_client_rejects_malformed_observation_frames(socket_dir) -> None:
    async def scenario(reply: bytes, outcome: Optional[str] = None) -> object:
        server = await _serve_once(socket_dir / "gateway.sock", reply, [])
        async with server:
            client = GatewayClient(GatewayEndpoint(socket_dir / "gateway.sock"))
            if outcome is not None:
                return await client.observe_outcome(outcome)
            return await client.observe_read_back({"record_id": "rec1"})

    # A signed read-back is not accepted as the answer to an outcome request.
    with pytest.raises(GatewayProtocolError):
        asyncio.run(scenario(_signed(), "step-1"))
    for hostile in [
        _signed(schema="auths.gateway-outcome/2"),
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


@pytest.mark.skipif(
    sys.platform == "win32", reason="first gateway deployment is Unix-only"
)
def test_client_requests_pre_entry_observations_and_refuses_malformed_replies(
    socket_dir,
) -> None:
    async def scenario(reply: bytes) -> tuple[object, list[dict[str, object]]]:
        seen: list[dict[str, object]] = []
        server = await _serve_once(socket_dir / "gateway.sock", reply, seen)
        async with server:
            client = GatewayClient(GatewayEndpoint(socket_dir / "gateway.sock"))
            return await client.observe_pre_entry("step-1"), seen

    def reply(**overrides: object) -> bytes:
        body: dict[str, object] = {
            "outcome": "pre-entry",
            "operation_id": "step-1",
            "observations_b64": [_b64(_OBSERVATION)],
        }
        body.update(overrides)
        return json.dumps(body).encode()

    result, seen = asyncio.run(scenario(reply()))
    assert result == GatewayPreEntryObservations("step-1", (_OBSERVATION,))
    assert seen == [
        {
            "schema": "auths.gateway-observe/2",
            "request": {"kind": "pre-entry", "operation_id": "step-1"},
        }
    ]
    empty, _ = asyncio.run(scenario(reply(observations_b64=[])))
    assert empty == GatewayPreEntryObservations("step-1", ())
    refused, _ = asyncio.run(
        scenario(b'{"outcome":"refused","code":"gateway.observer.operation-unknown"}')
    )
    assert refused == GatewayObservationRefused("gateway.observer.operation-unknown")
    for hostile in [
        reply(operation_id="step-2"),
        reply(observations_b64=[_b64(_OBSERVATION)] * 5),
        reply(observations_b64=[""]),
        reply(observations_b64=[_b64(_OBSERVATION) + "="]),
        reply(observations_b64="AAAA"),
        reply(signed=True),
        _signed(),
    ]:
        with pytest.raises(GatewayProtocolError):
            asyncio.run(scenario(hostile))


def test_client_rejects_unbounded_observation_requests(socket_dir) -> None:
    client = GatewayClient(GatewayEndpoint(socket_dir / "gateway.sock"))
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
        with pytest.raises(ValueError):
            asyncio.run(client.observe_pre_entry(operation))


@pytest.mark.skipif(sys.platform == "win32", reason="Unix socket paths only")
def test_endpoint_limit_is_the_platform_sun_path_less_its_nul() -> None:
    GatewayEndpoint(Path("/" + "a" * (_SOCKET_PATH_LIMIT - 1)))
    path = "/" + "a" * _SOCKET_PATH_LIMIT
    with pytest.raises(ValueError) as refused:
        GatewayEndpoint(Path(path))
    text = str(refused.value)
    assert path in text
    assert f"{_SOCKET_PATH_LIMIT + 1} bytes" in text
    assert f"at most {_SOCKET_PATH_LIMIT}" in text


@pytest.mark.skipif(sys.platform == "win32", reason="Unix socket paths only")
def test_endpoint_counts_bytes_not_characters() -> None:
    path = Path("/" + "\u00e9" * (_SOCKET_PATH_LIMIT // 2 + 1))
    assert len(str(path)) <= _SOCKET_PATH_LIMIT < len(os.fsencode(path))
    with pytest.raises(ValueError):
        GatewayEndpoint(path)


@pytest.mark.skipif(sys.platform == "win32", reason="Unix socket paths only")
def test_endpoint_limit_matches_the_operating_system(socket_dir: Path) -> None:
    def padded(size: int) -> Path:
        path = socket_dir / ("s" * (size - len(os.fsencode(socket_dir)) - 1))
        assert len(os.fsencode(path)) == size
        return path

    longest = padded(_SOCKET_PATH_LIMIT)
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(longest))
    GatewayEndpoint(longest)
    with socket.socket(socket.AF_UNIX) as listener:
        with pytest.raises(OSError):
            listener.bind(str(padded(_SOCKET_PATH_LIMIT + 1)))


@pytest.mark.skipif(sys.platform == "win32", reason="Unix socket paths only")
def test_connect_failure_names_the_path_and_cause(socket_dir: Path) -> None:
    missing = socket_dir / "missing.sock"
    client = GatewayClient(GatewayEndpoint(missing))
    with pytest.raises(GatewayProtocolError) as failed:
        asyncio.run(client.submit(proof=b"p", action=b"a"))
    text = str(failed.value)
    assert "outcome may be unknown" in text
    assert str(missing) in text
    assert os.strerror(errno.ENOENT) in text
