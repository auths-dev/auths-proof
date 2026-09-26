"""Explicit proof authoring for application-owned exact MCP operations.

The caller supplies an existing scoped grant chain, independent trusted
context, and custody signer. This module never creates production trust.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Generic, Iterator, Literal, Optional, Sequence, TypeVar, Union, cast

from . import _native
from .adapters.custody import (
    CustodyDescriptor,
    CustodyKeyState,
    CustodyLifecycle,
    CustodyIndeterminate,
    CustodyRejected,
    CustodySigned,
    CustodySigner,
    PublicControlEvidence,
    ReviewField,
    SigningObjectKind,
    SigningRequest,
    SigningResponse,
)
from .self_hosted import (
    ExactMcpTool,
    SignedObservationAttachment,
    _canonical_arguments,
    attach_observations,
)

CommandT = TypeVar("CommandT")


@dataclass(frozen=True)
class GrantEvidence:
    """One canonical signed grant with its public control evidence."""

    signed_grant: bytes
    evidence: tuple[PublicControlEvidence, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "signed_grant", bytes(self.signed_grant))
        object.__setattr__(self, "evidence", tuple(self.evidence))
        if not self.signed_grant or len(self.signed_grant) > 262_144:
            raise ValueError("signed grant size is outside bounds")
        if not 1 <= len(self.evidence) <= 32:
            raise ValueError("grant control evidence count is outside bounds")


@dataclass(frozen=True)
class ProductionAuthoringInputs:
    """Explicit production inputs; structural validation is not trust proof.

    The operator must distribute the trust template independently of the
    signer. These bytes alone cannot prove their provenance or grant scope.
    No provider credential belongs in this bundle.
    """

    grants: tuple[GrantEvidence, ...]
    trusted_context_template: bytes
    signer: CustodySigner
    challenge: bytes
    evaluation_time: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "grants", tuple(self.grants))
        object.__setattr__(self, "trusted_context_template", bytes(self.trusted_context_template))
        object.__setattr__(self, "challenge", bytes(self.challenge))
        if not 1 <= len(self.grants) <= 16:
            raise ValueError("production grant chain count is outside bounds")
        if not all(isinstance(grant, GrantEvidence) for grant in self.grants):
            raise TypeError("production grants must be GrantEvidence values")
        if not 1 <= len(self.trusted_context_template) <= 262_144:
            raise ValueError("production trusted context size is outside bounds")
        try:
            _native.parse_trusted_context(self.trusted_context_template)
        except Exception as error:
            raise ValueError("production trusted context is invalid") from error
        for grant in self.grants:
            try:
                _native.parse_signed("grant", grant.signed_grant)
            except Exception as error:
                raise ValueError("production signed grant is invalid") from error
        if len(self.challenge) != 32:
            raise ValueError("production challenge must contain 32 bytes")
        if type(self.evaluation_time) is not int or not 0 <= self.evaluation_time < 2**64 - 300:
            raise ValueError("production evaluation time is outside bounds")
        descriptor = self.signer.descriptor
        if descriptor.contract != "signer-custody/2":
            raise ValueError("production signer custody contract is invalid")
        if descriptor.lifecycle != CustodyLifecycle.DURABLE:
            raise ValueError("production signer must have durable custody")
        if descriptor.key_state != CustodyKeyState.ACTIVE_CURRENT:
            raise ValueError("production signer key must be active-current")


async def author_production_mcp_proof(
    *,
    contract: ExactMcpTool[CommandT],
    command: CommandT,
    inputs: ProductionAuthoringInputs,
    observations: Sequence[SignedObservationAttachment] = (),
    validity_seconds: Optional[int] = None,
) -> AuthoredMcpProof[CommandT]:
    """Author with explicit durable custody and separately supplied trust.

    The verifier decides authorization; structural readiness is not a grant,
    proof of independent trust provisioning, or provider qualification.
    ``observations`` and ``validity_seconds`` are as in :func:`author_mcp_proof`.
    """
    return await author_mcp_proof(
        contract=contract,
        command=command,
        grants=inputs.grants,
        trusted_context_template=inputs.trusted_context_template,
        signer=inputs.signer,
        challenge=inputs.challenge,
        evaluation_time=inputs.evaluation_time,
        observations=observations,
        validity_seconds=validity_seconds,
    )


@dataclass(frozen=True)
class AuthoredMcpProof(Generic[CommandT]):
    command: CommandT
    proof: bytes
    action: bytes
    trusted_context: bytes
    action_commitment: bytes
    review_fields: tuple[tuple[str, str], ...]


class AuthoringUnsuccessful(RuntimeError):
    """Custody or final verification did not yield an authorized proof."""

    def __init__(
        self,
        *,
        kind: Literal["rejected", "indeterminate"],
        code: str,
    ) -> None:
        super().__init__(f"proof authoring {kind}: {code}")
        self.kind = kind
        self.code = code


async def author_mcp_proof(
    *,
    contract: ExactMcpTool[CommandT],
    command: CommandT,
    grants: Sequence[GrantEvidence],
    trusted_context_template: bytes,
    signer: CustodySigner,
    challenge: bytes,
    evaluation_time: int,
    observations: Sequence[SignedObservationAttachment] = (),
    validity_seconds: Optional[int] = None,
) -> AuthoredMcpProof[CommandT]:
    """Sign and assemble one exact action with externally supplied authority.

    The signed grant, signer identity, and trusted context remain distinct
    inputs. Native Rust owns canonical action, bundle, and verifier semantics.
    The caller retains custody of the signer and must close it separately.

    Each signed observation in ``observations`` (for example a gateway
    read-back) is carried as a detached attachment that the action signature
    covers; a grant's observation requirements are then judged by the final
    verification against the trusted context.

    The action is valid from ``evaluation_time`` for ``validity_seconds``
    (the native default when ``None``, bounded natively), cut to the terminal
    grant's expiry, so a gateway verifying at its own clock accepts it inside
    that window. The window is not a replay defence: the executor's durable
    exactly-once claim is, inside and after the window. Observation freshness
    is judged at the verifier's evaluation time, so the window never extends
    an observation's maximum age.
    """
    if not 1 <= len(grants) <= 16:
        raise ValueError("grant chain count is outside bounds")
    if not 0 <= evaluation_time < 2**64 - 300:
        raise ValueError("evaluation time is outside bounds")
    if len(challenge) != 32:
        raise ValueError("challenge must contain 32 bytes")
    descriptor = signer.descriptor
    if descriptor.contract != "signer-custody/2":
        raise ValueError("signer does not implement the custody contract")
    actor = _native.Principal(descriptor.principal)
    signed_grants = [
        _native.parse_signed("grant", grant.signed_grant) for grant in grants
    ]
    prepared = contract.prepare(
        command,
        actor=actor,
        terminal_grant=signed_grants[-1],
        challenge=challenge,
        evaluation_time=evaluation_time,
        validity_seconds=validity_seconds,
    )
    if observations:
        prepared = attach_observations(prepared, observations)
    template = _native.parse_trusted_context(bytes(trusted_context_template))
    context = template.bind_request(prepared.audience, bytes(challenge), evaluation_time)
    signature = descriptor.signature
    request = _native.prepare_signing(
        prepared.action.unsigned,
        signature.principal_method,
        signature.verification_method,
        signature.suite,
    )
    custody_request = SigningRequest(
        request.request_id,
        SigningObjectKind.ACTION,
        bytes(request.object_id),
        descriptor,
        bytes(request.transaction_digest),
        bytes(request.signing_preimage),
        evaluation_time + 300,
        tuple(ReviewField(label, value) for label, value in prepared.review_fields),
    )
    outcome = await signer.sign(custody_request)
    if isinstance(outcome, (CustodyRejected, CustodyIndeterminate)):
        kind: Literal["rejected", "indeterminate"] = (
            "rejected" if isinstance(outcome, CustodyRejected) else "indeterminate"
        )
        raise AuthoringUnsuccessful(kind=kind, code=str(outcome.failure))
    if not isinstance(outcome, CustodySigned):
        raise TypeError("custody signer returned an invalid result")
    response = outcome.response
    if (
        response.request_id != custody_request.request_id
        or response.object_id != custody_request.object_id
        or response.principal != descriptor.principal
        or response.descriptor != descriptor.signature
        or response.provider_key_version != descriptor.key_version
        or response.transaction_digest != custody_request.transaction_digest
        or not 1 <= len(response.evidence) <= 32
    ):
        raise ValueError("custody response does not bind the exact signing request")
    signed_action = request.complete(bytes(response.signature))
    proof, action, trusted_context = _native.assemble_mcp_proof(
        prepared.action,
        signed_action,
        signed_grants,
        [
            [_evidence_tuple(item) for item in grant.evidence]
            for grant in grants
        ],
        [_evidence_tuple(item) for item in response.evidence],
        context,
    )
    verdict = _native.verify_v1(proof, action, trusted_context)
    if verdict.kind != "authorized":
        kind = "rejected" if verdict.kind == "denied" else "indeterminate"
        raise AuthoringUnsuccessful(kind=kind, code=verdict.code)
    return AuthoredMcpProof(
        prepared.command,
        bytes(proof),
        bytes(action),
        bytes(trusted_context),
        prepared.action_commitment,
        prepared.review_fields,
    )


@dataclass(frozen=True)
class QuorumApprover:
    """One member asked to approve, with the custody signer that holds its key.

    ``grants`` is the member's grant chain, root first; leave it empty when the
    member is itself a trust anchor of the operator's installation.
    """

    signer: CustodySigner
    grants: tuple[GrantEvidence, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "grants", tuple(self.grants))
        if len(self.grants) > 16:
            raise ValueError("approver grant chain count is outside bounds")
        if not all(isinstance(grant, GrantEvidence) for grant in self.grants):
            raise TypeError("approver grants must be GrantEvidence values")


@dataclass(frozen=True)
class QuorumPlan:
    """Projection of the native threshold plan every approval signed.

    ``approvers`` and ``proof_references`` are in approver order; the plan
    itself is canonical and independent of that order. Every approval is
    valid from ``valid_from`` through ``valid_until`` inclusive.
    """

    required: int
    approvers: tuple[str, ...]
    plan_id: bytes
    canonical_plan: bytes
    proof_references: tuple[bytes, ...]
    valid_from: int
    valid_until: int


@dataclass(frozen=True)
class AuthoredMcpQuorumProof(Generic[CommandT]):
    command: CommandT
    proof: bytes
    action: bytes
    trusted_context: bytes
    action_commitment: bytes
    review_fields: tuple[tuple[str, str], ...]
    plan: QuorumPlan


async def author_mcp_quorum_proof(
    *,
    contract: ExactMcpTool[CommandT],
    command: CommandT,
    required: int,
    approvers: Sequence[QuorumApprover],
    trusted_context_template: bytes,
    challenge: bytes,
    evaluation_time: int,
    validity_seconds: Optional[int] = None,
) -> AuthoredMcpQuorumProof[CommandT]:
    """Collect one signature per approver over one exact action and assemble
    a ``required``-of-N threshold proof.

    Each signature commits to the whole approver set, so every listed approver
    must sign; list only the approvers being asked. The threshold the verifier
    enforces comes from the operator's trusted context (branches and distinct
    actors), never from the proof. Signers are asked concurrently and are not
    closed.

    Every approval is valid from ``evaluation_time`` for ``validity_seconds``
    (the native quorum default when ``None``, bounded natively), cut to the
    earliest approver grant expiry; every approval must be collected and
    verified inside that window, and each custody request stays valid for
    the whole window.
    """
    if type(required) is not int or not 1 <= required <= len(approvers) <= 16:
        raise ValueError("quorum threshold or approver count is outside bounds")
    if not all(isinstance(approver, QuorumApprover) for approver in approvers):
        raise TypeError("approvers must be QuorumApprover values")
    if len(challenge) != 32:
        raise ValueError("challenge must contain 32 bytes")
    if type(evaluation_time) is not int or not 0 <= evaluation_time < 2**64:
        raise ValueError("evaluation time is outside bounds")
    descriptors = [approver.signer.descriptor for approver in approvers]
    if any(descriptor.contract != "signer-custody/2" for descriptor in descriptors):
        raise ValueError("signer does not implement the custody contract")
    if type(command) is not contract.command_type:
        raise TypeError("command does not belong to this exact tool")
    arguments = contract.encode(command)
    checked = contract.validate_arguments(arguments)
    chains = [
        [_native.parse_signed("grant", grant.signed_grant) for grant in approver.grants]
        for approver in approvers
    ]
    quorum = _native.prepare_mcp_quorum(
        contract.service,
        contract.name,
        _canonical_arguments(arguments),
        [
            (_native.Principal(descriptor.principal), chain[-1] if chain else None)
            for descriptor, chain in zip(descriptors, chains)
        ],
        required,
        bytes(challenge),
        evaluation_time,
        validity_seconds,
    )
    template = _native.parse_trusted_context(bytes(trusted_context_template))
    context = template.bind_request(quorum.audience, bytes(challenge), evaluation_time)
    _, valid_until = quorum.validity
    review = tuple(quorum.review_fields) + (
        ("Approval quorum", f"{required} of {len(approvers)}"),
        ("Quorum plan", bytes(quorum.plan_id).hex()),
    )
    requests = [
        _native.prepare_signing(
            quorum.unsigned(index),
            descriptor.signature.principal_method,
            descriptor.signature.verification_method,
            descriptor.signature.suite,
        )
        for index, descriptor in enumerate(descriptors)
    ]
    custody_requests = [
        SigningRequest(
            request.request_id,
            SigningObjectKind.ACTION,
            bytes(request.object_id),
            descriptor,
            bytes(request.transaction_digest),
            bytes(request.signing_preimage),
            valid_until,
            tuple(ReviewField(label, value) for label, value in review),
        )
        for request, descriptor in zip(requests, descriptors)
    ]
    outcomes = await asyncio.gather(
        *(
            approver.signer.sign(custody_request)
            for approver, custody_request in zip(approvers, custody_requests)
        )
    )
    approvals: list[
        tuple[
            _native.SignedObject,
            list[_native.SignedObject],
            list[list[tuple[str, str, bytes]]],
            list[tuple[str, str, bytes]],
        ]
    ] = []
    for approver, chain, request, custody_request, outcome in zip(
        approvers, chains, requests, custody_requests, outcomes
    ):
        response = _signed_response(outcome, custody_request)
        approvals.append(
            (
                request.complete(bytes(response.signature)),
                chain,
                [
                    [_evidence_tuple(item) for item in grant.evidence]
                    for grant in approver.grants
                ],
                [_evidence_tuple(item) for item in response.evidence],
            )
        )
    proof = bytes(_native.assemble_mcp_quorum_proof(quorum, approvals))
    action = bytes(quorum.canonical_action)
    trusted_context = bytes(_native.inspect_trusted_context(context))
    verdict = _native.verify_v1(proof, action, trusted_context)
    if verdict.kind != "authorized":
        kind: Literal["rejected", "indeterminate"] = (
            "rejected" if verdict.kind == "denied" else "indeterminate"
        )
        raise AuthoringUnsuccessful(kind=kind, code=verdict.code)
    return AuthoredMcpQuorumProof(
        checked,
        proof,
        action,
        trusted_context,
        bytes(_native.commit_canonical_v1("auths.canonical-action.v1", action)),
        tuple(quorum.review_fields),
        QuorumPlan(
            quorum.required,
            tuple(quorum.approvers),
            bytes(quorum.plan_id),
            bytes(quorum.canonical_plan),
            tuple(bytes(reference) for reference in quorum.proof_references),
            *quorum.validity,
        ),
    )


class ApprovalRefused(ValueError):
    """A remote approval operation refused its input with a stable
    ``approval.*`` code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@contextmanager
def _refusals() -> Iterator[None]:
    try:
        yield
    except _native.ApprovalRefusal as refused:
        raise ApprovalRefused(str(refused.args[0])) from None


@dataclass(frozen=True)
class ApprovalMember:
    """One approver named in a remote proposal. ``terminal_grant`` is the
    canonical signed grant its authority descends from; ``None`` when the
    approver is itself a trust anchor."""

    principal: str
    terminal_grant: Optional[bytes] = None


@dataclass(frozen=True)
class ApprovalProposal(Generic[CommandT]):
    """One exact action, its envelopes, and the threshold plan, built by the
    requester. ``action`` is the canonical action the assembled proof carries."""

    command: CommandT
    action: bytes
    requester: str
    plan: QuorumPlan
    _quorum: _native.McpQuorum = field(repr=False, compare=False)


@dataclass(frozen=True)
class ApprovalRequest:
    """One request, addressed to one approver, as bytes and printable text."""

    approver: str
    data: bytes
    text: str
    request_id: bytes


@dataclass(frozen=True)
class ApprovalReview:
    """A request that passed every native check. The title, fields, and
    display digest are the profile's review of the exact canonical action;
    render them and nothing else."""

    title: str
    fields: tuple[tuple[str, str], ...]
    display_digest_hex: str
    requester: str
    approvers: tuple[str, ...]
    required: int
    approver: str
    valid_from: int
    valid_until: int
    request_id: bytes
    _handle: _native.ReviewedApprovalRequest = field(repr=False, compare=False)


@dataclass(frozen=True)
class ApprovalResponse:
    """One approver's signed answer, as bytes and printable text."""

    decision: Literal["approve", "decline"]
    data: bytes
    text: str


@dataclass(frozen=True)
class ApproverStatus:
    approver: str
    status: Literal["pending", "approved", "declined", "rejected"]
    code: Optional[str]
    decided_at: Optional[int]


@dataclass(frozen=True)
class ApprovalCollection:
    """Where each listed approver stands, in proposal order.
    ``unattributed`` lists responses matched to no approver, by input index."""

    statuses: tuple[ApproverStatus, ...]
    unattributed: tuple[tuple[int, str], ...]
    _handle: _native.ApprovalCollection = field(repr=False, compare=False)

    def assemble(self) -> bytes:
        """Returns the proof once every listed approver approved; raises
        :class:`ApprovalRefused` with ``approval.incomplete`` otherwise."""
        with _refusals():
            return bytes(self._handle.assemble())


def _message(data: Union[bytes, str]) -> bytes:
    if isinstance(data, str):
        return data.encode("utf-8")
    return bytes(data)


def propose_mcp_approval(
    *,
    contract: ExactMcpTool[CommandT],
    command: CommandT,
    required: int,
    approvers: Sequence[ApprovalMember],
    requester: str,
    challenge: bytes,
    evaluation_time: int,
    validity_seconds: Optional[int] = None,
) -> ApprovalProposal[CommandT]:
    """Build a ``required``-of-N proposal for approvers on their own devices.

    Every listed approver must approve; ``requester`` is the listed approver
    building the proposal. The window follows :func:`author_mcp_quorum_proof`.
    """
    if type(command) is not contract.command_type:
        raise TypeError("command does not belong to this exact tool")
    if not all(isinstance(approver, ApprovalMember) for approver in approvers):
        raise TypeError("approvers must be ApprovalMember values")
    arguments = contract.encode(command)
    checked = contract.validate_arguments(arguments)
    quorum = _native.prepare_mcp_quorum(
        contract.service,
        contract.name,
        _canonical_arguments(arguments),
        [
            (
                _native.Principal(approver.principal),
                None
                if approver.terminal_grant is None
                else _native.parse_signed("grant", bytes(approver.terminal_grant)),
            )
            for approver in approvers
        ],
        required,
        bytes(challenge),
        evaluation_time,
        validity_seconds,
    )
    return ApprovalProposal(
        checked,
        bytes(quorum.canonical_action),
        requester,
        QuorumPlan(
            quorum.required,
            tuple(quorum.approvers),
            bytes(quorum.plan_id),
            bytes(quorum.canonical_plan),
            tuple(bytes(reference) for reference in quorum.proof_references),
            *quorum.validity,
        ),
        quorum,
    )


def approval_requests(proposal: ApprovalProposal[CommandT]) -> tuple[ApprovalRequest, ...]:
    """One request per listed approver, in proposal order."""
    with _refusals():
        issued = _native.approval_requests(proposal._quorum, proposal.requester)
    return tuple(
        ApprovalRequest(approver, bytes(data), text, bytes(request_id))
        for approver, data, text, request_id in issued
    )


def open_approval_request(
    data: Union[bytes, str], *, now: Optional[int] = None
) -> ApprovalReview:
    """Check one request natively and return the review to show.

    Raises :class:`ApprovalRefused` with the first failing check's code.
    """
    moment = int(time.time()) if now is None else now
    with _refusals():
        reviewed = _native.open_approval_request(_message(data), moment)
    valid_from, valid_until = reviewed.window
    return ApprovalReview(
        reviewed.title,
        tuple(reviewed.fields),
        reviewed.display_digest_hex,
        reviewed.requester,
        tuple(reviewed.approvers),
        reviewed.required,
        reviewed.approver,
        valid_from,
        valid_until,
        bytes(reviewed.request_id),
        reviewed,
    )


async def _answer(
    pending: _native.PendingApproval,
    signer: CustodySigner,
    grants: Sequence[GrantEvidence],
) -> ApprovalResponse:
    descriptor = signer.descriptor
    request = SigningRequest(
        pending.request_id,
        SigningObjectKind(pending.object_kind),
        bytes(pending.object_id),
        descriptor,
        bytes(pending.transaction_digest),
        bytes(pending.signing_preimage),
        pending.expires_at,
        tuple(ReviewField(label, value) for label, value in pending.display),
    )
    decision: Literal["approve", "decline"] = (
        "approve" if pending.decision == "approve" else "decline"
    )
    response = _signed_response(await signer.sign(request), request)
    with _refusals():
        data, text = pending.complete(
            bytes(response.signature),
            [_native.parse_signed("grant", grant.signed_grant) for grant in grants],
            [[_evidence_tuple(item) for item in grant.evidence] for grant in grants],
            [_evidence_tuple(item) for item in response.evidence],
        )
    return ApprovalResponse(decision, bytes(data), text)


def _custody(signer: CustodySigner) -> CustodyDescriptor:
    descriptor = signer.descriptor
    if descriptor.contract != "signer-custody/2":
        raise ValueError("signer does not implement the custody contract")
    return descriptor


async def approve(
    reviewed: ApprovalReview,
    signer: CustodySigner,
    *,
    grants: Sequence[GrantEvidence] = (),
) -> ApprovalResponse:
    """Sign the reviewed envelope with ``signer``, whose custody request shows
    the same review and expires at the window's end. ``grants`` is the
    approver's grant chain, root first. The signer is not closed."""
    descriptor = _custody(signer)
    signature = descriptor.signature
    with _refusals():
        pending = reviewed._handle.prepare_approval(
            descriptor.principal,
            signature.principal_method,
            signature.verification_method,
            signature.suite,
        )
    return await _answer(pending, signer, grants)


async def decline(
    reviewed: ApprovalReview,
    signer: CustodySigner,
    *,
    now: Optional[int] = None,
    grants: Sequence[GrantEvidence] = (),
) -> ApprovalResponse:
    """Sign a refusal at ``now``. A decline carries no authority; it stops
    the collector and records who refused."""
    descriptor = _custody(signer)
    signature = descriptor.signature
    with _refusals():
        pending = reviewed._handle.prepare_decline(
            descriptor.principal,
            signature.principal_method,
            signature.verification_method,
            signature.suite,
            int(time.time()) if now is None else now,
        )
    return await _answer(pending, signer, grants)


def collect_approvals(
    proposal: ApprovalProposal[CommandT], responses: Sequence[Union[bytes, str]]
) -> ApprovalCollection:
    """Match responses to the proposal's requests. Signatures are checked by
    the verifier when the assembled proof is used."""
    with _refusals():
        collection = _native.collect_approvals(
            proposal._quorum, [_message(response) for response in responses]
        )
    return ApprovalCollection(
        tuple(
            ApproverStatus(
                approver,
                cast(Literal["pending", "approved", "declined", "rejected"], status),
                code,
                decided_at,
            )
            for approver, status, code, decided_at in collection.statuses
        ),
        tuple((index, code) for index, code in collection.unattributed),
        collection,
    )


def _signed_response(
    outcome: Union[CustodySigned, CustodyRejected, CustodyIndeterminate],
    request: SigningRequest,
) -> SigningResponse:
    if isinstance(outcome, (CustodyRejected, CustodyIndeterminate)):
        kind: Literal["rejected", "indeterminate"] = (
            "rejected" if isinstance(outcome, CustodyRejected) else "indeterminate"
        )
        raise AuthoringUnsuccessful(kind=kind, code=str(outcome.failure))
    if not isinstance(outcome, CustodySigned):
        raise TypeError("custody signer returned an invalid result")
    response = outcome.response
    descriptor = request.descriptor
    if (
        response.request_id != request.request_id
        or response.object_id != request.object_id
        or response.principal != descriptor.principal
        or response.descriptor != descriptor.signature
        or response.provider_key_version != descriptor.key_version
        or response.transaction_digest != request.transaction_digest
        or not 1 <= len(response.evidence) <= 32
    ):
        raise ValueError("custody response does not bind the exact signing request")
    return response


def _evidence_tuple(value: PublicControlEvidence) -> tuple[str, str, bytes]:
    return value.evidence_type, value.media_type, bytes(value.bytes)


__all__ = [
    "ApprovalCollection",
    "ApprovalMember",
    "ApprovalProposal",
    "ApprovalRefused",
    "ApprovalRequest",
    "ApprovalResponse",
    "ApprovalReview",
    "ApproverStatus",
    "AuthoredMcpProof",
    "AuthoredMcpQuorumProof",
    "AuthoringUnsuccessful",
    "GrantEvidence",
    "ProductionAuthoringInputs",
    "QuorumApprover",
    "QuorumPlan",
    "approval_requests",
    "approve",
    "author_mcp_proof",
    "author_mcp_quorum_proof",
    "author_production_mcp_proof",
    "collect_approvals",
    "decline",
    "open_approval_request",
    "propose_mcp_approval",
]
