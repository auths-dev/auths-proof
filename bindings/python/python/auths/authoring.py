"""Explicit proof authoring for application-owned exact MCP operations.

The caller supplies an existing scoped grant chain, independent trusted
context, and custody signer. This module never creates production trust.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Generic, Literal, Sequence, TypeVar, Union

from . import _native
from .adapters.custody import (
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
from .self_hosted import ExactMcpTool, _canonical_arguments

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
) -> AuthoredMcpProof[CommandT]:
    """Author with explicit durable custody and separately supplied trust.

    The verifier decides authorization; structural readiness is not a grant,
    proof of independent trust provisioning, or provider qualification.
    """
    return await author_mcp_proof(
        contract=contract,
        command=command,
        grants=inputs.grants,
        trusted_context_template=inputs.trusted_context_template,
        signer=inputs.signer,
        challenge=inputs.challenge,
        evaluation_time=inputs.evaluation_time,
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
) -> AuthoredMcpProof[CommandT]:
    """Sign and assemble one exact action with externally supplied authority.

    The signed grant, signer identity, and trusted context remain distinct
    inputs. Native Rust owns canonical action, bundle, and verifier semantics.
    The caller retains custody of the signer and must close it separately.
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
    )
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
    itself is canonical and independent of that order.
    """

    required: int
    approvers: tuple[str, ...]
    plan_id: bytes
    canonical_plan: bytes
    proof_references: tuple[bytes, ...]


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
    expires_at: int,
) -> AuthoredMcpQuorumProof[CommandT]:
    """Collect one signature per approver over one exact action and assemble
    a ``required``-of-N threshold proof.

    Each signature commits to the whole approver set, so every listed approver
    must sign; list only the approvers being asked. The threshold the verifier
    enforces comes from the operator's trusted context (branches and distinct
    actors), never from the proof. Approvals are valid from ``evaluation_time``
    through ``expires_at``. Signers are asked concurrently and are not closed.
    """
    if type(required) is not int or not 1 <= required <= len(approvers) <= 16:
        raise ValueError("quorum threshold or approver count is outside bounds")
    if not all(isinstance(approver, QuorumApprover) for approver in approvers):
        raise TypeError("approvers must be QuorumApprover values")
    if len(challenge) != 32:
        raise ValueError("challenge must contain 32 bytes")
    if (
        type(evaluation_time) is not int
        or type(expires_at) is not int
        or not 0 <= evaluation_time <= expires_at < 2**64
        or expires_at - evaluation_time > 86_400
    ):
        raise ValueError("quorum validity window is outside bounds")
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
        expires_at,
    )
    template = _native.parse_trusted_context(bytes(trusted_context_template))
    context = template.bind_request(quorum.audience, bytes(challenge), evaluation_time)
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
            expires_at,
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
        ),
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
    "AuthoredMcpProof",
    "AuthoredMcpQuorumProof",
    "AuthoringUnsuccessful",
    "GrantEvidence",
    "ProductionAuthoringInputs",
    "QuorumApprover",
    "QuorumPlan",
    "author_mcp_proof",
    "author_mcp_quorum_proof",
    "author_production_mcp_proof",
]
