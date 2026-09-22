"""Proof/action-only application socket behavior with no provider credential."""

from __future__ import annotations

import asyncio
import json
import struct
import sys

import pytest

from auths.gateway import (
    GatewayClient,
    GatewayEndpoint,
    GatewayObserved,
    GatewayObservedByProvider,
    GatewayProtocolError,
    GatewayProviderEvidence,
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
