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
class QuorumRequirement:
    """Projection of the native approval requirement every approval binds.

    Any ``required`` distinct approvers of ``approvers`` (ascending) suffice.
    The verifier enforces the requirement installed in its own trusted
    context, never one a proof carries. The actor's action and every approval
    are valid from ``valid_from`` through ``valid_until`` inclusive.
    """

    required: int
    approvers: tuple[str, ...]
    requirement_id: bytes
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
    requirement: QuorumRequirement


_MAX_APPROVERS = 16


def _requirement(quorum: _native.McpQuorum) -> QuorumRequirement:
    return QuorumRequirement(
        quorum.required,
        tuple(quorum.approvers),
        bytes(quorum.requirement_id),
        *quorum.validity,
    )


def _quorum_review(quorum: _native.McpQuorum) -> tuple[ReviewField, ...]:
    fields = tuple(quorum.review_fields) + (
        ("Approvals required", f"any {quorum.required} of {len(quorum.approvers)}"),
        ("Approval requirement", bytes(quorum.requirement_id).hex()),
    )
    return tuple(ReviewField(label, value) for label, value in fields)


def _prepare_quorum(
    contract: ExactMcpTool[CommandT],
    command: CommandT,
    required: int,
    approvers: Sequence[str],
    actor: str,
    actor_grant: Optional[_native.SignedObject],
    challenge: bytes,
    evaluation_time: int,
    validity_seconds: Optional[int],
) -> tuple[CommandT, _native.McpQuorum]:
    if type(command) is not contract.command_type:
        raise TypeError("command does not belong to this exact tool")
    values = tuple(approvers)
    if type(required) is not int or not 1 <= required <= len(values) <= _MAX_APPROVERS:
        raise ValueError("quorum threshold or approver count is outside bounds")
    if any(type(value) is not str or not value for value in values):
        raise TypeError("approvers must be principal strings")
    if len(challenge) != 32:
        raise ValueError("challenge must contain 32 bytes")
    if type(evaluation_time) is not int or not 0 <= evaluation_time < 2**64:
        raise ValueError("evaluation time is outside bounds")
    arguments = contract.encode(command)
    checked = contract.validate_arguments(arguments)
    quorum = _native.prepare_mcp_quorum(
        contract.service,
        contract.name,
        _canonical_arguments(arguments),
        required,
        list(values),
        actor,
        actor_grant,
        bytes(challenge),
        evaluation_time,
        validity_seconds,
    )
    return checked, quorum


def _action_request(
    quorum: _native.McpQuorum, descriptor: CustodyDescriptor
) -> tuple[_native.SigningRequest, SigningRequest]:
    signature = descriptor.signature
    request = _native.prepare_signing(
        quorum.unsigned_action(),
        signature.principal_method,
        signature.verification_method,
        signature.suite,
    )
    return request, SigningRequest(
        request.request_id,
        SigningObjectKind.ACTION,
        bytes(request.object_id),
        descriptor,
        bytes(request.transaction_digest),
        bytes(request.signing_preimage),
        quorum.validity[1],
        _quorum_review(quorum),
    )


def _quorum_action(
    request: _native.SigningRequest,
    response: SigningResponse,
    grants: Sequence[GrantEvidence],
) -> _native.QuorumAction:
    return _native.QuorumAction(
        request.complete(bytes(response.signature)),
        [_native.parse_signed("grant", grant.signed_grant) for grant in grants],
        [[_evidence_tuple(item) for item in grant.evidence] for grant in grants],
        [_evidence_tuple(item) for item in response.evidence],
    )


def _actor_grants(grants: Sequence[GrantEvidence]) -> tuple[GrantEvidence, ...]:
    values = tuple(grants)
    if len(values) > 16:
        raise ValueError("actor grant chain count is outside bounds")
    if not all(isinstance(grant, GrantEvidence) for grant in values):
        raise TypeError("actor grants must be GrantEvidence values")
    return values


async def author_mcp_quorum_proof(
    *,
    contract: ExactMcpTool[CommandT],
    command: CommandT,
    actor: CustodySigner,
    grants: Sequence[GrantEvidence] = (),
    required: int,
    approvers: Sequence[str],
    signers: Sequence[CustodySigner],
    trusted_context_template: bytes,
    challenge: bytes,
    evaluation_time: int,
    validity_seconds: Optional[int] = None,
) -> AuthoredMcpQuorumProof[CommandT]:
    """Have ``actor`` sign one exact action and any ``required`` of
    ``approvers`` approve it, in process, and assemble the proof.

    ``actor`` submits the action under its own grant chain ``grants``, root
    first (empty when the actor is itself a trust anchor). ``approvers`` are
    the principals of the approval requirement the operator installed;
    ``signers`` are the custody signers of the approvers who approve, each
    listed, distinct, at least ``required`` of them. The actor never counts
    as an approver. The actor and the approvers are asked concurrently;
    signers are not closed.

    The proof is verified against ``trusted_context_template`` bound to this
    request before it is returned; a proof the verifier would not authorize
    raises :class:`AuthoringUnsuccessful` with the verifier's code. The action
    and every approval are valid from ``evaluation_time`` for
    ``validity_seconds`` (the native quorum default when ``None``, bounded
    natively), cut to the actor's terminal-grant expiry; each custody request
    stays valid for that whole window.
    """
    chain = _actor_grants(grants)
    signer_values = tuple(signers)
    listed = set(approvers)
    descriptors = [_custody(actor)] + [_custody(signer) for signer in signer_values]
    principals = [descriptor.principal for descriptor in descriptors[1:]]
    if len(set(principals)) != len(principals):
        raise ValueError("an approver signer appears twice")
    if not listed.issuperset(principals):
        raise ValueError("every approving signer must be a listed approver")
    if type(required) is not int or len(principals) < required:
        raise ValueError("fewer approving signers than the threshold")
    signed_grants = [_native.parse_signed("grant", grant.signed_grant) for grant in chain]
    checked, quorum = _prepare_quorum(
        contract,
        command,
        required,
        approvers,
        descriptors[0].principal,
        signed_grants[-1] if signed_grants else None,
        challenge,
        evaluation_time,
        validity_seconds,
    )
    template = _native.parse_trusted_context(bytes(trusted_context_template))
    context = template.bind_request(quorum.audience, bytes(challenge), evaluation_time)
    action_request, action_custody = _action_request(quorum, descriptors[0])
    review = _quorum_review(quorum)
    approval_requests = [
        quorum.prepare_approval(
            descriptor.principal,
            descriptor.signature.principal_method,
            descriptor.signature.verification_method,
            descriptor.signature.suite,
        )
        for descriptor in descriptors[1:]
    ]
    approval_custody = [
        SigningRequest(
            request.request_id,
            SigningObjectKind.APPROVAL,
            bytes(request.object_id),
            descriptor,
            bytes(request.transaction_digest),
            bytes(request.signing_preimage),
            request.expires_at,
            review,
        )
        for request, descriptor in zip(approval_requests, descriptors[1:])
    ]
    outcomes = await asyncio.gather(
        actor.sign(action_custody),
        *(
            signer.sign(custody_request)
            for signer, custody_request in zip(signer_values, approval_custody)
        ),
    )
    action = _quorum_action(
        action_request, _signed_response(outcomes[0], action_custody), chain
    )
    approvals: list[_native.SignedApproval] = []
    for request, custody_request, outcome in zip(
        approval_requests, approval_custody, outcomes[1:]
    ):
        response = _signed_response(outcome, custody_request)
        approvals.append(
            request.complete(
                bytes(response.signature),
                [_evidence_tuple(item) for item in response.evidence],
            )
        )
    proof = bytes(_native.assemble_mcp_quorum_proof(quorum, action, approvals))
    canonical_action = bytes(quorum.canonical_action)
    trusted_context = bytes(_native.inspect_trusted_context(context))
    verdict = _native.verify_v1(proof, canonical_action, trusted_context)
    if verdict.kind != "authorized":
        kind: Literal["rejected", "indeterminate"] = (
            "rejected" if verdict.kind == "denied" else "indeterminate"
        )
        raise AuthoringUnsuccessful(kind=kind, code=verdict.code)
    return AuthoredMcpQuorumProof(
        checked,
        proof,
        canonical_action,
        trusted_context,
        bytes(_native.commit_canonical_v1("auths.canonical-action.v1", canonical_action)),
        tuple(quorum.review_fields),
        _requirement(quorum),
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
class ApprovalProposal(Generic[CommandT]):
    """One exact action the actor submits and any ``requirement.required``
    of ``requirement.approvers`` approve, built by the actor. ``action`` is
    the canonical action the assembled proof carries."""

    command: CommandT
    action: bytes
    actor: str
    requirement: QuorumRequirement
    _quorum: _native.McpQuorum = field(repr=False, compare=False)


@dataclass(frozen=True)
class ApprovalAction:
    """The actor's signature over a proposal's envelope, with its grant
    chain. Opaque; pass it to :meth:`ApprovalCollection.assemble`."""

    actor: str
    _handle: _native.QuorumAction = field(repr=False, compare=False)


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
    render them and nothing else. ``requester`` is the actor that will submit
    the action; its own signature on the action, not the request,
    authenticates it."""

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
    """Where each listed approver stands, in ascending approver order, and
    how many approved of the ``required``. ``unattributed`` lists responses
    matched to no approver, by input index."""

    statuses: tuple[ApproverStatus, ...]
    unattributed: tuple[tuple[int, str], ...]
    approved: int
    required: int
    _handle: _native.ApprovalCollection = field(repr=False, compare=False)

    def assemble(self, action: ApprovalAction) -> bytes:
        """Returns the proof once ``required`` listed approvers approved,
        carrying every matching approval and the actor's signed ``action``.
        Raises :class:`ApprovalRefused` with ``approval.incomplete`` below
        the threshold and ``approval.action-mismatch`` when ``action`` is not
        the proposal's envelope."""
        if not isinstance(action, ApprovalAction):
            raise TypeError("action must be an ApprovalAction")
        with _refusals():
            return bytes(self._handle.assemble(action._handle))


def _message(data: Union[bytes, str]) -> bytes:
    if isinstance(data, str):
        return data.encode("utf-8")
    return bytes(data)


def propose_mcp_approval(
    *,
    contract: ExactMcpTool[CommandT],
    command: CommandT,
    required: int,
    approvers: Sequence[str],
    actor: str,
    actor_grant: Optional[bytes],
    challenge: bytes,
    evaluation_time: int,
    validity_seconds: Optional[int] = None,
) -> ApprovalProposal[CommandT]:
    """Build a proposal for approvers on their own devices: ``actor`` submits
    the action and any ``required`` of ``approvers`` approve it.

    ``actor_grant`` is the canonical signed grant the actor's authority
    descends from, ``None`` when the actor is itself a trust anchor. The
    actor may not be listed as an approver. The window follows
    :func:`author_mcp_quorum_proof`.
    """
    if type(actor) is not str or not actor:
        raise TypeError("actor must be a principal string")
    checked, quorum = _prepare_quorum(
        contract,
        command,
        required,
        approvers,
        actor,
        None
        if actor_grant is None
        else _native.parse_signed("grant", bytes(actor_grant)),
        challenge,
        evaluation_time,
        validity_seconds,
    )
    return ApprovalProposal(
        checked,
        bytes(quorum.canonical_action),
        quorum.actor,
        _requirement(quorum),
        quorum,
    )


def approval_requests(proposal: ApprovalProposal[CommandT]) -> tuple[ApprovalRequest, ...]:
    """One request per listed approver, in ascending approver order."""
    with _refusals():
        issued = _native.approval_requests(proposal._quorum)
    return tuple(
        ApprovalRequest(approver, bytes(data), text, bytes(request_id))
        for approver, data, text, request_id in issued
    )


async def sign_approval_action(
    proposal: ApprovalProposal[CommandT],
    signer: CustodySigner,
    *,
    grants: Sequence[GrantEvidence] = (),
) -> ApprovalAction:
    """Have the actor's custody ``signer`` sign the proposal's envelope.
    ``grants`` is the actor's grant chain, root first, ending in the
    proposal's ``actor_grant``. The custody request shows the action's review
    and the requirement and expires at the window's end. The signer is not
    closed."""
    chain = _actor_grants(grants)
    descriptor = _custody(signer)
    if descriptor.principal != proposal.actor:
        raise ValueError("signer is not the proposal's actor")
    request, custody_request = _action_request(proposal._quorum, descriptor)
    response = _signed_response(await signer.sign(custody_request), custody_request)
    return ApprovalAction(proposal.actor, _quorum_action(request, response, chain))


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
    pending: _native.PendingApproval, signer: CustodySigner
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
            [_evidence_tuple(item) for item in response.evidence],
        )
    return ApprovalResponse(decision, bytes(data), text)


def _custody(signer: CustodySigner) -> CustodyDescriptor:
    descriptor = signer.descriptor
    if descriptor.contract != "signer-custody/2":
        raise ValueError("signer does not implement the custody contract")
    return descriptor


async def approve(reviewed: ApprovalReview, signer: CustodySigner) -> ApprovalResponse:
    """Sign the reviewed approval statement with ``signer``, whose custody
    request shows the same review and expires at the window's end. An
    approval carries no grant chain. The signer is not closed."""
    descriptor = _custody(signer)
    signature = descriptor.signature
    with _refusals():
        pending = reviewed._handle.prepare_approval(
            descriptor.principal,
            signature.principal_method,
            signature.verification_method,
            signature.suite,
        )
    return await _answer(pending, signer)


async def decline(
    reviewed: ApprovalReview,
    signer: CustodySigner,
    *,
    now: Optional[int] = None,
) -> ApprovalResponse:
    """Sign a refusal at ``now``. A decline carries no authority; it records
    who refused and when."""
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
    return await _answer(pending, signer)


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
        collection.approved,
        collection.required,
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
    "ApprovalAction",
    "ApprovalCollection",
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
    "QuorumRequirement",
    "approval_requests",
    "approve",
    "author_mcp_proof",
    "author_mcp_quorum_proof",
    "author_production_mcp_proof",
    "collect_approvals",
    "decline",
    "open_approval_request",
    "propose_mcp_approval",
    "sign_approval_action",
]
