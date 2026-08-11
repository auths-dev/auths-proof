"""Typed authority authoring, proof plans, and attenuation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Sequence, Tuple

from ._native import (
    AuthorityDiff,
    AuthorizationPlan as _NativeAuthorizationPlan,
    AuthorizationPlanBuilder as _NativeAuthorizationPlanBuilder,
    GrantAuthority,
    GrantPlan,
    GrantRequest,
    Principal,
    PrincipalDescriptor,
    SignedObject,
    UnsignedObject,
    bind_delegated_authority,
    grant_request_from_statement,
    plan_child,
    plan_child_fields,
    plan_child_statement,
    root_grant,
    validate_root_authority,
    validate_trusted_authority,
)
from ._native import inspect_plan as _inspect_plan
from .workflow import (
    AllowedBodies,
    AnyBody,
    BudgetCeiling,
    DelegatedAuthority,
    DelegationReview,
    ExactBody,
    ExpiryOnly,
    InheritAction,
    InheritBudget,
    InheritStatus,
    NoBudget,
    Permission,
    SignedGrantInput,
    SignedGrantLoadRequest,
    SignedGrantMaterial,
    SignedGrantProvider,
    SignedGrantSource,
    SnapshotRequired,
    Validity,
)

ProofPlanKind = Literal["proof", "all-of", "any-of", "threshold"]
_PLAN_TOKEN = object()


@dataclass(frozen=True)
class ProofReference:
    bytes: bytes

    def __post_init__(self) -> None:
        value = bytes(self.bytes)
        if len(value) != 32:
            raise ValueError("proof reference must contain 32 bytes")
        object.__setattr__(self, "bytes", value)

    @classmethod
    def parse(cls, value: str) -> ProofReference:
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise ValueError("proof reference must be 64 lowercase hexadecimal characters")
        return cls(bytes.fromhex(value))


class ProofPlan:
    def __init__(
        self,
        token: object,
        owner: ProofPlanBuilder,
        kind: ProofPlanKind,
        native: _NativeAuthorizationPlan,
        references: Tuple[ProofReference, ...],
    ) -> None:
        if token is not _PLAN_TOKEN:
            raise TypeError("sealed Auths proof plan")
        self._owner = owner
        self._native = native
        self._references = references
        self.kind = kind

    @property
    def plan_id(self) -> bytes:
        return bytes(self._native.plan_id)

    @property
    def leaf_count(self) -> int:
        return self._native.shape[0]

    @property
    def maximum_depth(self) -> int:
        return self._native.shape[1]

    @property
    def proof_references(self) -> Tuple[ProofReference, ...]:
        return self._references

    def canonical_bytes(self) -> bytes:
        return bytes(_inspect_plan(self._native))


class ProofPlanBuilder:
    def __init__(self) -> None:
        self._native = _NativeAuthorizationPlanBuilder()

    def proof(self, reference: ProofReference) -> ProofPlan:
        if type(reference) is not ProofReference:
            raise TypeError("proof plan requires a ProofReference")
        return ProofPlan(
            _PLAN_TOKEN,
            self,
            "proof",
            self._native.proof(reference.bytes),
            (reference,),
        )

    def all_of(self, members: Sequence[ProofPlan]) -> ProofPlan:
        return self._compound("all-of", members)

    def any_of(self, members: Sequence[ProofPlan]) -> ProofPlan:
        return self._compound("any-of", members)

    def threshold(self, required: int, members: Sequence[ProofPlan]) -> ProofPlan:
        values = self._members(members)
        native = self._native.threshold(required, [value._native for value in values])
        return ProofPlan(
            _PLAN_TOKEN,
            self,
            "threshold",
            native,
            tuple(reference for value in values for reference in value._references),
        )

    def _compound(
        self, kind: Literal["all-of", "any-of"], members: Sequence[ProofPlan]
    ) -> ProofPlan:
        values = self._members(members)
        native_members = [value._native for value in values]
        native = (
            self._native.all_of(native_members)
            if kind == "all-of"
            else self._native.any_of(native_members)
        )
        return ProofPlan(
            _PLAN_TOKEN,
            self,
            kind,
            native,
            tuple(reference for value in values for reference in value._references),
        )

    def _members(self, members: Sequence[ProofPlan]) -> Tuple[ProofPlan, ...]:
        values = tuple(members)
        if any(type(value) is not ProofPlan or value._owner is not self for value in values):
            raise ValueError("proof plan member belongs to another builder")
        return values


def _native_proof_plan(plan: ProofPlan) -> _NativeAuthorizationPlan:
    if type(plan) is not ProofPlan:
        raise TypeError("expected a sealed Auths proof plan")
    return plan._native

__all__ = [
    "AllowedBodies",
    "AnyBody",
    "AuthorityDiff",
    "BudgetCeiling",
    "DelegatedAuthority",
    "DelegationReview",
    "ExactBody",
    "ExpiryOnly",
    "GrantAuthority",
    "GrantPlan",
    "GrantRequest",
    "InheritAction",
    "InheritBudget",
    "InheritStatus",
    "NoBudget",
    "Permission",
    "ProofPlan",
    "ProofPlanBuilder",
    "ProofPlanKind",
    "ProofReference",
    "Principal",
    "PrincipalDescriptor",
    "SignedGrantInput",
    "SignedGrantLoadRequest",
    "SignedGrantMaterial",
    "SignedGrantProvider",
    "SignedGrantSource",
    "SignedObject",
    "SnapshotRequired",
    "UnsignedObject",
    "Validity",
    "bind_delegated_authority",
    "grant_request_from_statement",
    "plan_child",
    "plan_child_fields",
    "plan_child_statement",
    "root_grant",
    "validate_root_authority",
    "validate_trusted_authority",
]
