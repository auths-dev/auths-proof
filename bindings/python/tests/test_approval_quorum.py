"""Two-of-three manager approval: Python authors the gateway's quorum bytes."""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import pytest

from auths import _native
from auths.adapters.custody import (
    CustodyDescriptor,
    CustodyFailure,
    CustodyKeyState,
    CustodyKind,
    CustodyLifecycle,
    CustodyRejected,
    CustodySignatureDescriptor,
    CustodySigned,
    PublicControlEvidence,
    SigningRequest,
    SigningResponse,
)
from auths.authoring import (
    AuthoringUnsuccessful,
    QuorumApprover,
    author_mcp_quorum_proof,
)
from auths.self_hosted import EnumField, ExactMcpTool, StringField

FIXTURE: dict[str, Any] = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "fixtures/gateway/approval-quorum.json"
    ).read_text()
)
MEMBERS = {member["name"]: member for member in FIXTURE["members"]}
CASES = {case["id"]: case for case in FIXTURE["cases"]}
CHALLENGE = bytes.fromhex(FIXTURE["challenge_hex"])


@dataclass(frozen=True)
class SetStatus:
    operation_id: str
    operator_namespace: Literal["airtable-demo"]
    recipe_digest: str
    record_id: str
    replacement: Literal["Approved", "Pending"]


TOOL = ExactMcpTool(
    service=FIXTURE["service"],
    name=FIXTURE["tool"],
    command_type=SetStatus,
    fields={
        "operation_id": StringField(min_length=1, max_length=128),
        "operator_namespace": EnumField(("airtable-demo",)),
        "recipe_digest": StringField(min_length=64, max_length=64),
        "record_id": StringField(min_length=17, max_length=43),
        "replacement": EnumField(("Approved", "Pending")),
    },
)


class SeededSigner:
    def __init__(self, name: str, *, reject: bool = False) -> None:
        self.key = _native.DevelopmentEd25519Key.from_seed(
            bytes([MEMBERS[name]["seed_byte"]]) * 32
        )
        assert self.key.principal == MEMBERS[name]["principal"]
        self.reject = reject
        self.requests: list[SigningRequest] = []
        self.descriptor = CustodyDescriptor(
            "signer-custody/2",
            CustodyKind.WORKLOAD,
            "test.seeded-manager",
            self.key.principal,
            CustodySignatureDescriptor(
                self.key.principal_method, self.key.verification_method, self.key.suite
            ),
            "test-key-1",
            CustodyKeyState.ACTIVE_CURRENT,
            CustodyLifecycle.EPHEMERAL,
        )

    async def sign(self, request: SigningRequest) -> CustodySigned | CustodyRejected:
        self.requests.append(request)
        if self.reject:
            return CustodyRejected("rejected", CustodyFailure.DENIED)
        return CustodySigned(
            "signed",
            SigningResponse(
                request.request_id,
                request.object_id,
                self.key.principal,
                self.descriptor.signature,
                self.descriptor.key_version,
                request.transaction_digest,
                self.key.sign(request.signing_preimage),
                (
                    PublicControlEvidence(
                        self.key.evidence_type, self.key.media_type, self.key.evidence
                    ),
                ),
            ),
        )

    async def aclose(self) -> None:
        return None


def _template() -> bytes:
    now = FIXTURE["evaluation_time"]
    audience = f"mcp://{FIXTURE['service']}"
    resource = f"{audience}/tools/{FIXTURE['tool']}"
    anchors = [
        _native.TrustAnchor(
            member["name"],
            _native.Principal(member["principal"]),
            ["raw-key-v1"],
            [("auths.mcp", 2)],
            [("tools/call", resource)],
            [audience],
            [audience],
            now - 86_400,
            now + 86_400,
            None,
            0,
            "approval-quorum-test-v1",
            None,
        )
        for member in FIXTURE["members"]
        if member["member"]
    ]
    context = _native.compile_trusted_context(
        _native.self_contained_configuration(),
        None,
        FIXTURE["required"],
        FIXTURE["required"],
        1,
        anchors,
        _native.AssurancePolicy(
            "approval-quorum-test-v1",
            [
                ("root", "every", "self-certifying-identifier", None),
                ("actor", "every", "self-certifying-identifier", None),
                ("actor", "every", "offline-verifiable", None),
            ],
        ),
        None,
        None,
        "none-v1",
        ["raw-key-v1"],
        [],
    )
    return bytes(_native.inspect_trusted_context(context))


def _command(case: dict[str, Any]) -> SetStatus:
    return TOOL.validate_arguments(json.loads(case["arguments_json"]))


def _b64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


async def _author(case_id: str, names: list[str], required: int) -> Any:
    return await author_mcp_quorum_proof(
        contract=TOOL,
        command=_command(CASES[case_id]),
        required=required,
        approvers=[QuorumApprover(SeededSigner(name)) for name in names],
        trusted_context_template=_template(),
        challenge=CHALLENGE,
        evaluation_time=FIXTURE["authored_at"],
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case_id",
    [case["id"] for case in FIXTURE["cases"] if case["decision"] == "authorized"],
)
async def test_python_authors_the_exact_gateway_quorum_bytes(case_id: str) -> None:
    case = CASES[case_id]
    authored = await _author(case_id, case["approvers"], case["required"])
    assert authored.proof == _b64(case["proof_b64"])
    assert authored.action == _b64(case["action_b64"])
    assert authored.command == _command(case)
    assert authored.plan.required == case["required"]
    assert authored.plan.approvers == tuple(
        MEMBERS[name]["principal"] for name in case["approvers"]
    )
    assert len(authored.plan.proof_references) == len(case["approvers"])
    assert len(set(authored.plan.proof_references)) == len(case["approvers"])
    assert (authored.plan.valid_from, authored.plan.valid_until) == (
        FIXTURE["authored_at"],
        FIXTURE["authored_at"] + FIXTURE["validity_seconds"],
    )


@pytest.mark.asyncio
async def test_quorum_window_defaults_to_a_day_and_is_configurable() -> None:
    case = CASES["two-of-three-managers"]

    async def author(validity: Any) -> Any:
        return await author_mcp_quorum_proof(
            contract=TOOL,
            command=_command(case),
            required=2,
            approvers=[QuorumApprover(SeededSigner(name)) for name in case["approvers"]],
            trusted_context_template=_template(),
            challenge=CHALLENGE,
            evaluation_time=FIXTURE["authored_at"],
            validity_seconds=validity,
        )

    assert FIXTURE["validity_seconds"] == 86_400
    explicit = await author(FIXTURE["validity_seconds"])
    assert explicit.proof == _b64(case["proof_b64"])
    shorter = await author(3_600)
    assert shorter.plan.valid_until == FIXTURE["authored_at"] + 3_600
    assert shorter.proof != explicit.proof
    # A week passes the native bound; the one-day trust anchors then refuse it.
    with pytest.raises(AuthoringUnsuccessful) as week:
        await author(604_800)
    assert (week.value.kind, week.value.code) == ("rejected", "action-outside-validity")
    for invalid in (0, 604_801):
        with pytest.raises(ValueError):
            await author(invalid)


@pytest.mark.asyncio
async def test_every_approver_reviews_the_same_action_and_plan() -> None:
    signers = [SeededSigner(name) for name in ("manager-a", "manager-b", "manager-c")]
    await author_mcp_quorum_proof(
        contract=TOOL,
        command=_command(CASES["three-of-three-managers"]),
        required=2,
        approvers=[QuorumApprover(signer) for signer in signers],
        trusted_context_template=_template(),
        challenge=CHALLENGE,
        evaluation_time=FIXTURE["authored_at"],
    )
    displays = {request.display for signer in signers for request in signer.requests}
    assert len(displays) == 1
    fields = dict((field.label, field.value) for field in displays.pop())
    assert fields["Approval quorum"] == "2 of 3"
    assert len({signer.requests[0].object_id for signer in signers}) == 3
    assert all(
        signer.requests[0].expires_at_unix_seconds
        == FIXTURE["authored_at"] + FIXTURE["validity_seconds"]
        for signer in signers
    )


def test_python_compiles_the_same_quorum_trust_template() -> None:
    assert _template() == _b64(FIXTURE["sdk_trusted_context_b64"])


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=lambda case: case["id"])
def test_python_verifier_decides_every_gateway_vector_identically(
    case: dict[str, Any],
) -> None:
    template = _native.parse_trusted_context(_template())
    context = template.bind_request(
        f"mcp://{FIXTURE['service']}", CHALLENGE, FIXTURE["evaluation_time"]
    )
    verdict = _native.verify_v1(
        _b64(case["proof_b64"]),
        _b64(case["action_b64"]),
        bytes(_native.inspect_trusted_context(context)),
    )
    assert verdict.kind == case["decision"]
    if case["decision"] != "authorized":
        assert verdict.code == case["code"]


@pytest.mark.asyncio
async def test_one_approval_or_an_outsider_never_authors_a_quorum() -> None:
    with pytest.raises(AuthoringUnsuccessful) as single:
        await _author("one-of-three-managers", ["manager-a"], 1)
    assert (single.value.kind, single.value.code) == (
        "rejected",
        CASES["one-of-three-managers"]["code"],
    )
    with pytest.raises(AuthoringUnsuccessful) as outsider:
        await _author("outsider-does-not-count", ["manager-a", "outsider"], 2)
    assert (outsider.value.kind, outsider.value.code) == (
        "rejected",
        CASES["outsider-does-not-count"]["code"],
    )


@pytest.mark.asyncio
async def test_duplicate_approver_and_impossible_threshold_are_refused() -> None:
    command = _command(CASES["two-of-three-managers"])
    for approvers, required in (
        (["manager-a", "manager-a"], 2),
        (["manager-a", "manager-b"], 3),
        (["manager-a", "manager-b"], 0),
    ):
        with pytest.raises(ValueError):
            await author_mcp_quorum_proof(
                contract=TOOL,
                command=command,
                required=required,
                approvers=[QuorumApprover(SeededSigner(name)) for name in approvers],
                trusted_context_template=_template(),
                challenge=CHALLENGE,
                evaluation_time=FIXTURE["authored_at"],
            )


@pytest.mark.asyncio
async def test_a_declining_approver_stops_the_quorum() -> None:
    with pytest.raises(AuthoringUnsuccessful) as declined:
        await author_mcp_quorum_proof(
            contract=TOOL,
            command=_command(CASES["two-of-three-managers"]),
            required=2,
            approvers=[
                QuorumApprover(SeededSigner("manager-a")),
                QuorumApprover(SeededSigner("manager-b", reject=True)),
            ],
            trusted_context_template=_template(),
            challenge=CHALLENGE,
            evaluation_time=FIXTURE["authored_at"],
        )
    assert declined.value.kind == "rejected"


def test_runnable_example_authors_the_gateway_quorum() -> None:
    example = (
        Path(__file__).resolve().parents[3]
        / "examples/approval-quorum/python/two_of_three.py"
    )
    output = subprocess.run(
        [sys.executable, str(example)], check=True, capture_output=True, text=True
    ).stdout
    report = json.loads(output.strip().splitlines()[-1])
    assert report["outcome"] == "authorized"
    assert (report["approvals"], report["members"]) == (2, 3)
    assert report["matches_gateway_vector"] is True
    assert report["single_approval"] == CASES["one-of-three-managers"]["code"]
