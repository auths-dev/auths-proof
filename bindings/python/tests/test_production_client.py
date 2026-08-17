from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from auths.service import create_service_client
from auths._native import (
    decode_production_request_v1,
    decode_production_response_v1,
    encode_production_request_v1,
)
from auths._service import (
    ServiceTransportRequest,
    ServiceTransportResponse,
)
from auths.profiles import github_issue_address

FIXTURE = json.loads(
    (
        Path(__file__).parents[3]
        / "product/fixtures/v1/production-client/contract-v1.json"
    ).read_text()
)


def test_native_request_and_response_contract_matches_rust_fixtures() -> None:
    for vector in FIXTURE["requests"]:
        projection = vector["projection"]
        encoded = bytes(
            encode_production_request_v1(
                projection["verb"],
                projection["profile"],
                _decode(projection["identity"]),
                None
                if projection["authority"] is None
                else _decode(projection["authority"]),
                None if projection["body"] is None else _decode(projection["body"]),
                projection["recoveryReference"],
            )
        )
        assert encoded.hex() == vector["bytesHex"], vector["id"]
        assert json.loads(decode_production_request_v1(encoded)) == projection

    for vector in FIXTURE["responses"]:
        assert json.loads(
            decode_production_response_v1(bytes.fromhex(vector["bytesHex"]))
        ) == vector["projection"]


def test_native_contract_rejects_every_adversarial_fixture() -> None:
    for vector in FIXTURE["adversarial"]:
        decoder = (
            decode_production_request_v1
            if vector["target"] == "request"
            else decode_production_response_v1
        )
        with pytest.raises(ValueError, match=vector["expectedCode"].replace(".", r"\.")):
            decoder(bytes.fromhex(vector["bytesHex"]))


def test_production_facade_uses_closed_profile_routes() -> None:
    completed = next(
        item for item in FIXTURE["responses"] if item["id"] == "completed"
    )

    class Transport:
        def __init__(self) -> None:
            self.paths: list[str] = []

        async def send(
            self, request: ServiceTransportRequest
        ) -> ServiceTransportResponse:
            self.paths.append(request.url.removeprefix("https://operator.example"))
            return ServiceTransportResponse(
                200,
                FIXTURE["contentType"],
                bytes.fromhex(completed["bytesHex"]),
            )

    async def scenario() -> None:
        transport = Transport()
        client = create_service_client(
            endpoint="https://operator.example",
            identity=bytes([1]) * 32,
            profile=github_issue_address(),
            transport=transport,
        )
        authority = await client.create(b"create")
        assert authority.kind == "authority"
        executed = await client.execute(authority, b"execute")
        assert executed.kind == "completed"
        assert transport.paths == [
            "/v1/authority/create",
            "/v1/profiles/github/issue-address/execute",
        ]

    asyncio.run(scenario())


def _decode(value: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
