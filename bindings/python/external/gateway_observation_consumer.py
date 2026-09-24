"""Packed-wheel expected-before-replacement journey against the gateway harness.

The harness serves the gateway's own application socket over a counting
provider. It trusts a fixed test root that grants this agent one read-back
requirement: the record's current value must equal the action's ``expected``
argument, as signed by the gateway observer at most 60 seconds before the
gateway verifies.

1. Request a read-back observation.
2. Attach it to the replacement action.
3. Submit: the write is authorized.
4. Change the record: the stale expectation is refused. The SDK refuses to
   author it, and an agent that skips that check and submits anyway is denied
   by the gateway before any credential lease. An observation older than its
   maximum age is refused the same way.

Usage: ``python gateway_observation_consumer.py <auths-gateway-harness>``.
"""

from __future__ import annotations

import asyncio
import base64
import json
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from auths import _native
from auths.adapters.custody import (
    CustodyDescriptor,
    CustodyKeyState,
    CustodyKind,
    CustodyLifecycle,
    CustodySignatureDescriptor,
    CustodySigned,
    PublicControlEvidence,
    SigningRequest,
    SigningResponse,
)
from auths.authoring import AuthoringUnsuccessful, GrantEvidence, author_mcp_proof
from auths.gateway import (
    GatewayClient,
    GatewayDenied,
    GatewayEndpoint,
    GatewayIndeterminate,
    GatewayObservedByProvider,
    GatewayResult,
    GatewaySignedObservation,
)
from auths.self_hosted import EnumField, ExactMcpTool, StringField, attach_observations

Status = Literal["Approved", "Pending"]
AGENT_SEED = bytes([0x5A]) * 32
NOW = 1_790_000_000


@dataclass(frozen=True)
class SetStatus:
    operation_id: str
    operator_namespace: Literal["observer-demo"]
    recipe_digest: str
    record_id: str
    replacement: Status
    expected: Status
    record_uri: str


CONTRACT = ExactMcpTool(
    service="gateway-observer-test",
    name="set_status_v1",
    command_type=SetStatus,
    fields={
        "operation_id": StringField(min_length=1, max_length=128),
        "operator_namespace": EnumField(("observer-demo",)),
        "recipe_digest": StringField(min_length=64, max_length=64),
        "record_id": StringField(min_length=17, max_length=43),
        "replacement": EnumField(("Approved", "Pending")),
        "expected": EnumField(("Approved", "Pending")),
        "record_uri": StringField(min_length=1, max_length=256),
    },
)


class AgentSigner:
    """CI-only custody adapter over a public test seed."""

    def __init__(self) -> None:
        self.key = _native.DevelopmentEd25519Key.from_seed(AGENT_SEED)
        self.descriptor = CustodyDescriptor(
            "signer-custody/2", CustodyKind.WORKLOAD, "test.gateway-journey",
            self.key.principal,
            CustodySignatureDescriptor(
                self.key.principal_method, self.key.verification_method, self.key.suite,
            ),
            "journey-key-1", CustodyKeyState.ACTIVE_CURRENT, CustodyLifecycle.EPHEMERAL,
        )

    def evidence(self) -> PublicControlEvidence:
        return PublicControlEvidence(
            self.key.evidence_type, self.key.media_type, self.key.evidence,
        )

    async def sign(self, request: SigningRequest) -> CustodySigned:
        return CustodySigned("signed", SigningResponse(
            request.request_id, request.object_id, self.key.principal,
            self.descriptor.signature, self.descriptor.key_version,
            request.transaction_digest, self.key.sign(request.signing_preimage),
            (self.evidence(),),
        ))

    async def aclose(self) -> None:
        return None


def _bytes(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


async def _control(socket: Path, request: dict[str, object]) -> dict[str, int]:
    reader, writer = await asyncio.open_unix_connection(str(socket))
    payload = json.dumps(request).encode()
    writer.write(struct.pack(">I", len(payload)) + payload)
    await writer.drain()
    length = struct.unpack(">I", await reader.readexactly(4))[0]
    response = json.loads(await reader.readexactly(length))
    writer.close()
    await writer.wait_closed()
    if response.get("ok") is not True:
        raise AssertionError(f"harness refused {request}")
    return cast("dict[str, int]", response)


class Journey:
    def __init__(self, setup: dict[str, object], signer: AgentSigner) -> None:
        self.setup = setup
        self.signer = signer
        self.control = Path(cast(str, setup["control_socket"]))
        self.client = GatewayClient(GatewayEndpoint(Path(cast(str, setup["app_socket"]))))
        evidence = cast("dict[str, str]", setup["root_evidence"])
        self.root_evidence = PublicControlEvidence(
            evidence["evidence_type"], evidence["media_type"], _bytes(evidence["bytes_b64"]),
        )
        self.grant = _bytes(cast(str, setup["signed_grant_b64"]))
        self.context = _bytes(cast(str, setup["trusted_context_b64"]))
        self.challenge = _bytes(cast(str, setup["challenge_b64"]))
        self.record = cast("list[dict[str, str]]", setup["records"])[0]

    def command(self, operation: str, expected: Status, replacement: Status) -> SetStatus:
        return SetStatus(
            operation, "observer-demo", cast(str, self.setup["recipe_digest"]),
            self.record["record_id"], replacement, expected,
            self.record["read_back_subject"],
        )

    async def read_back(self) -> GatewaySignedObservation:
        result = await self.client.observe_read_back({"record_id": self.record["record_id"]})
        assert isinstance(result, GatewaySignedObservation), result
        assert result.subject == self.record["read_back_subject"]
        return result

    async def author(
        self, command: SetStatus, observation: GatewaySignedObservation, now: int,
    ) -> tuple[bytes, bytes]:
        authored = await author_mcp_proof(
            contract=CONTRACT,
            command=command,
            grants=(GrantEvidence(self.grant, (self.root_evidence,)),),
            trusted_context_template=self.context,
            signer=self.signer,
            challenge=self.challenge,
            evaluation_time=now,
            observations=(observation,),
        )
        return authored.proof, authored.action

    def author_unchecked(
        self, command: SetStatus, observation: GatewaySignedObservation, now: int,
    ) -> tuple[bytes, bytes]:
        """What an agent that skips its SDK's final verification would send."""
        grant = _native.parse_signed("grant", self.grant)
        prepared = attach_observations(
            CONTRACT.prepare(
                command, actor=_native.Principal(self.signer.key.principal),
                terminal_grant=grant, challenge=self.challenge, evaluation_time=now,
            ),
            (observation,),
        )
        context = _native.parse_trusted_context(self.context).bind_request(
            prepared.audience, self.challenge, now,
        )
        key = self.signer.key
        request = _native.prepare_signing(
            prepared.action.unsigned, key.principal_method, key.verification_method, key.suite,
        )
        signed = request.complete(key.sign(request.signing_preimage))
        evidence = self.root_evidence
        agent = self.signer.evidence()
        proof, action, _ = _native.assemble_mcp_proof(
            prepared.action, signed, [grant],
            [[(evidence.evidence_type, evidence.media_type, bytes(evidence.bytes))]],
            [(agent.evidence_type, agent.media_type, bytes(agent.bytes))],
            context,
        )
        return bytes(proof), bytes(action)

    async def counts(self) -> tuple[int, int]:
        counts = await _control(self.control, {"command": "counts"})
        return counts["writes"], counts["leases"]

    async def refused_before_lease(
        self, command: SetStatus, observation: GatewaySignedObservation, now: int,
        expected: GatewayResult,
    ) -> None:
        try:
            await self.author(command, observation, now)
        except AuthoringUnsuccessful as refusal:
            assert refusal.code == getattr(expected, "code"), refusal.code
        else:
            raise AssertionError("the SDK authored a refused replacement")
        before = await self.counts()
        proof, action = self.author_unchecked(command, observation, now)
        result = await self.client.submit(proof=proof, action=action)
        assert result == expected, result
        assert await self.counts() == before, "no write and no credential lease"


async def journey(harness: Path, state: Path) -> None:
    signer = AgentSigner()
    process = subprocess.Popen(
        [
            str(harness), "--state-dir", str(state),
            "--agent", signer.key.principal, "--now", str(NOW),
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        setup = json.loads(process.stdout.readline())
        assert setup["schema"] == "auths.gateway-harness/1" and setup["now"] == NOW
        run = Journey(setup, signer)

        observed = await run.read_back()
        proof, action = await run.author(
            run.command("journey-1", "Pending", "Approved"), observed, NOW,
        )
        written = await run.client.submit(proof=proof, action=action)
        assert isinstance(written, GatewayObservedByProvider), written
        assert written.status == 200
        assert await run.counts() == (1, 2), "one write; the read-back and write leases"

        await _control(run.control, {
            "command": "set-record", "record_id": run.record["record_id"],
            "status": "Pending",
        })
        changed = await run.read_back()
        await run.refused_before_lease(
            run.command("journey-2", "Approved", "Pending"), changed, NOW,
            GatewayDenied("observation-condition-false"),
        )

        aged = (await _control(run.control, {"command": "advance-clock", "seconds": 61}))["now"]
        await run.refused_before_lease(
            run.command("journey-3", "Pending", "Approved"), changed, aged,
            GatewayIndeterminate("observation-missing"),
        )
        assert await run.counts() == (1, 3), "only the second read-back leased again"
    finally:
        process.kill()
        process.wait()


def main(harness: Path) -> None:
    if sys.platform == "win32":
        raise SystemExit("the gateway harness requires Unix sockets")
    with tempfile.TemporaryDirectory(prefix="agh") as temporary:
        asyncio.run(journey(harness, Path(temporary)))
    print("gateway observation journey: write authorized; changed and stale refused before lease")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
