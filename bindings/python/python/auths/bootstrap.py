"""Native raw-key authority bootstrap for a closed application profile."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional, Sequence

from . import _native as native
from .trust import AssurancePolicy, AssuranceRequirement, TrustAnchor, compile_trust
from .workflow import (
    ApprovalConfiguration,
    BudgetCeiling,
    Permission,
    PrincipalDescriptor,
    Profile,
    ReviewField,
    SignedGrantMaterial,
    Signer,
    TrustedAuthority,
    Validity,
    _SigningCoordinator,
)


@dataclass(frozen=True)
class PreparedRawKeyAuthority:
    trusted_authority: TrustedAuthority
    authority: SignedGrantMaterial


async def prepare_raw_key_authority(
    *,
    authority_id: str,
    root_signer: Signer,
    subject: PrincipalDescriptor,
    profile: Profile,
    permissions: Sequence[Permission],
    resource_namespaces: Sequence[str],
    validity: Validity,
    audiences: Sequence[str],
    remaining_depth: int,
    approval: ApprovalConfiguration,
    budget: Optional[BudgetCeiling] = None,
) -> PreparedRawKeyAuthority:
    root = await root_signer.public_identity()
    if (
        type(root) is not PrincipalDescriptor
        or root.principal_method != "raw-key-v1"
        or root.suite != "ed25519-v1"
    ):
        raise TypeError("raw-key bootstrap requires an Ed25519 raw-key root signer")
    if type(subject) is not PrincipalDescriptor:
        raise TypeError("raw-key bootstrap requires a typed subject")
    permission_values = tuple(permissions)
    namespace_values = tuple(resource_namespaces)
    audience_values = tuple(audiences)
    if not permission_values or not namespace_values or not audience_values:
        raise ValueError("raw-key authority scope cannot be empty")
    request = native.GrantRequest(
        subject.principal,
        profile.id,
        profile.version,
        [(value.capability, value.resource) for value in permission_values],
        validity.not_before,
        validity.expires_at,
        list(audience_values),
        None,
        None if budget is None else (budget.algebra, budget.value),
        remaining_depth,
        None,
        "raw-key-baseline",
        [],
    )
    unsigned = native.root_grant(root.principal, request)
    signed = await _SigningCoordinator().execute(
        unsigned=unsigned,
        principal=root,
        signer=root_signer,
        approval=approval,
        required_approval=approval.policy.reference,
        expires_at=int(time.time()) + min(approval.policy.expires_in_seconds, 300),
        display=(
            ReviewField("Authority", authority_id),
            ReviewField("Subject", subject.principal.value),
            ReviewField("Profile", f"{profile.id}/{profile.version}"),
            ReviewField("Permissions", str(len(permission_values))),
            ReviewField("Delegation depth", str(remaining_depth)),
        ),
    )
    compiled = compile_trust(
        anchors=(
            TrustAnchor(
                authority_id,
                root.principal,
                (root.principal_method,),
                (profile,),
                permission_values,
                namespace_values,
                audience_values,
                validity.not_before,
                validity.expires_at,
                remaining_depth + 1,
                "raw-key-baseline",
                budget,
            ),
        ),
        assurance=AssurancePolicy(
            "raw-key-baseline",
            (
                AssuranceRequirement("root", "every", "self-certifying-identifier"),
                AssuranceRequirement("actor", "every", "self-certifying-identifier"),
                AssuranceRequirement("root", "every", "offline-verifiable"),
                AssuranceRequirement("actor", "every", "offline-verifiable"),
            ),
        ),
        evidence_types=(root.principal_method,),
    )
    return PreparedRawKeyAuthority(
        TrustedAuthority(
            authority_id,
            root.principal,
            compiled.context,
            approval.policy.reference,
        ),
        SignedGrantMaterial(signed.signed_object, signed.evidence),
    )


__all__ = ["PreparedRawKeyAuthority", "prepare_raw_key_authority"]
