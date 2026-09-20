"""Explicit proof authoring for application-owned exact MCP operations.

The caller supplies an existing scoped grant chain, independent trusted
context, and custody signer. This module never creates production trust.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, Literal, Sequence, TypeVar

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
)
from .self_hosted import ExactMcpTool

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
        _native.parse_trusted_context(self.trusted_context_template)
        for grant in self.grants:
            _native.parse_signed("grant", grant.signed_grant)
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


def _evidence_tuple(value: PublicControlEvidence) -> tuple[str, str, bytes]:
    return value.evidence_type, value.media_type, bytes(value.bytes)


__all__ = [
    "AuthoredMcpProof",
    "AuthoringUnsuccessful",
    "GrantEvidence",
    "ProductionAuthoringInputs",
    "author_mcp_proof",
    "author_production_mcp_proof",
]
