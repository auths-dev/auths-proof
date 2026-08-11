"""Typed trust configuration, evidence, and offline bundles."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Literal, Optional, Protocol, Sequence, Tuple, runtime_checkable

from . import _native as native
from .authority import ProofPlan, _native_proof_plan
from .lifecycle import GrantStatusSnapshot, PrincipalStatusSnapshot
from .workflow import (
    BudgetCeiling,
    Permission,
    Principal,
    Profile,
    TrustedAuthority,
    TrustedAuthoritySnapshot,
)

AssuranceRole = Literal["root", "intermediate", "actor", "external-issuer"]
AssuranceQuantifier = Literal["any", "every"]


@dataclass(frozen=True)
class AssuranceRequirement:
    role: AssuranceRole
    quantifier: AssuranceQuantifier
    claim: str
    maximum_age: Optional[int] = None


@dataclass(frozen=True)
class AssurancePolicy:
    id: str
    requirements: Tuple[AssuranceRequirement, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "requirements", tuple(self.requirements))

    def _native(self) -> native.AssurancePolicy:
        return native.AssurancePolicy(
            self.id,
            [
                (value.role, value.quantifier, value.claim, value.maximum_age)
                for value in self.requirements
            ],
        )


@dataclass(frozen=True)
class TrustAnchor:
    id: str
    principal: Principal
    accepted_methods: Tuple[str, ...]
    profiles: Tuple[Profile, ...]
    permissions: Tuple[Permission, ...]
    resource_namespaces: Tuple[str, ...]
    audiences: Tuple[str, ...]
    not_before: int
    expires_at: int
    max_delegation_depth: int
    assurance_policy: str
    budget: Optional[BudgetCeiling] = None
    status: Optional[Tuple[str, int]] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "accepted_methods", tuple(self.accepted_methods))
        object.__setattr__(self, "profiles", tuple(self.profiles))
        object.__setattr__(self, "permissions", tuple(self.permissions))
        object.__setattr__(self, "resource_namespaces", tuple(self.resource_namespaces))
        object.__setattr__(self, "audiences", tuple(self.audiences))

    def _native(self) -> native.TrustAnchor:
        return native.TrustAnchor(
            self.id,
            self.principal,
            list(self.accepted_methods),
            [(value.id, value.version) for value in self.profiles],
            [(value.capability, value.resource) for value in self.permissions],
            list(self.resource_namespaces),
            list(self.audiences),
            self.not_before,
            self.expires_at,
            None if self.budget is None else (self.budget.algebra, self.budget.value),
            self.max_delegation_depth,
            self.assurance_policy,
            self.status,
        )


@dataclass(frozen=True)
class EvidenceRequest:
    source_id: str
    maximum_bytes: int
    timeout: float
    maximum_redirects: int = 0
    allow_private_network: bool = False


@dataclass(frozen=True)
class EvidenceProvenance:
    source_id: str
    observed_at: int
    valid_until: int
    version: str


@dataclass(frozen=True)
class ResolvedEvidence:
    bytes: bytes
    media_type: str
    provenance: EvidenceProvenance

    def __post_init__(self) -> None:
        object.__setattr__(self, "bytes", bytes(self.bytes))


@runtime_checkable
class EvidenceProvider(Protocol):
    async def resolve(self, request: EvidenceRequest) -> ResolvedEvidence: ...


@dataclass(frozen=True)
class OfflineEvidenceBundle:
    evidence: Tuple[ResolvedEvidence, ...]
    captured_at: int

    def __post_init__(self) -> None:
        values = tuple(self.evidence)
        if not values:
            raise ValueError("offline evidence bundle cannot be empty")
        object.__setattr__(self, "evidence", values)


@dataclass(frozen=True)
class CompiledTrust:
    context: native.TrustedContext
    roots: Tuple[Principal, ...]
    offline_evidence: Optional[OfflineEvidenceBundle]


@dataclass(frozen=True)
class PolicyReplacement:
    current: CompiledTrust
    replacement: CompiledTrust
    activated_at: int


def replace_policy(
    current: CompiledTrust,
    replacement: CompiledTrust,
    *,
    activated_at: int,
) -> PolicyReplacement:
    if type(current) is not CompiledTrust or type(replacement) is not CompiledTrust:
        raise TypeError("policy replacement requires compiled trust values")
    if activated_at < 0:
        raise ValueError("policy activation time cannot be negative")
    if bytes(native.inspect_trusted_context(current.context)) == bytes(
        native.inspect_trusted_context(replacement.context)
    ):
        raise ValueError("replacement policy must have a different configuration")
    return PolicyReplacement(current, replacement, activated_at)


async def load_evidence(
    provider: EvidenceProvider, request: EvidenceRequest
) -> ResolvedEvidence:
    if (
        request.maximum_bytes < 1
        or request.maximum_bytes > 16 * 1024 * 1024
        or request.timeout <= 0
        or request.timeout > 300
        or request.maximum_redirects < 0
        or request.maximum_redirects > 8
    ):
        raise ValueError("evidence request is outside supported bounds")
    result = await asyncio.wait_for(provider.resolve(request), request.timeout)
    if type(result) is not ResolvedEvidence:
        raise TypeError("evidence provider returned the wrong type")
    if (
        len(result.bytes) > request.maximum_bytes
        or result.provenance.source_id != request.source_id
        or result.provenance.valid_until < result.provenance.observed_at
    ):
        raise ValueError("evidence provider returned inconsistent evidence")
    return result


def compile_trust(
    *,
    anchors: Sequence[TrustAnchor],
    assurance: AssurancePolicy,
    minimum_authorized_branches: int = 1,
    minimum_distinct_actors: int = 1,
    minimum_distinct_roots: int = 1,
    expected_plan: Optional[ProofPlan] = None,
    principal_status: Optional[PrincipalStatusSnapshot] = None,
    grant_status: Optional[GrantStatusSnapshot] = None,
    channel_policy: str = "none-v1",
    evidence_types: Sequence[str] = (),
    critical_extensions: Sequence[str] = (),
    offline_evidence: Optional[OfflineEvidenceBundle] = None,
) -> CompiledTrust:
    anchor_values = tuple(anchors)
    if not anchor_values or any(
        type(value) is not TrustAnchor for value in anchor_values
    ):
        raise ValueError("trust requires at least one typed anchor")
    context = native.compile_trusted_context(
        native.self_contained_configuration(),
        None if expected_plan is None else _native_proof_plan(expected_plan),
        minimum_authorized_branches,
        minimum_distinct_actors,
        minimum_distinct_roots,
        [value._native() for value in anchor_values],
        assurance._native(),
        None if principal_status is None else principal_status._native,
        None if grant_status is None else grant_status._native,
        channel_policy,
        list(evidence_types),
        list(critical_extensions),
    )
    return CompiledTrust(
        context,
        tuple(value.principal for value in anchor_values),
        offline_evidence,
    )


StatusSnapshot = native.StatusSnapshot
TrustedContext = native.TrustedContext
compile_trusted_context = native.compile_trusted_context
parse_trusted_context = native.parse_trusted_context
self_contained_configuration = native.self_contained_configuration
status_snapshot = native.status_snapshot

__all__ = [
    "AssurancePolicy",
    "AssuranceQuantifier",
    "AssuranceRequirement",
    "AssuranceRole",
    "CompiledTrust",
    "EvidenceProvenance",
    "EvidenceProvider",
    "EvidenceRequest",
    "OfflineEvidenceBundle",
    "PolicyReplacement",
    "ResolvedEvidence",
    "StatusSnapshot",
    "TrustAnchor",
    "TrustedAuthority",
    "TrustedAuthoritySnapshot",
    "TrustedContext",
    "compile_trust",
    "compile_trusted_context",
    "load_evidence",
    "parse_trusted_context",
    "replace_policy",
    "self_contained_configuration",
    "status_snapshot",
]
