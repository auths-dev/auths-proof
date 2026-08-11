"""Auths identity, authority, and protected-action SDK."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .workflow import *  # noqa: F403

_WORKFLOW_EXPORTS = (
    "ActionConstraintSummary",
    "AgentIdentity",
    "AllowedBodies",
    "AnyBody",
    "Approval",
    "ApprovalConfiguration",
    "ApprovalDecision",
    "ApprovalMode",
    "ApprovalPolicy",
    "ApprovalPolicyReference",
    "ApprovalProvider",
    "ApprovalRequest",
    "ApprovalResponse",
    "AttachedAgent",
    "AuthorityExplanation",
    "AuthsClient",
    "AuthsError",
    "AuthsWorkflowError",
    "BudgetCeiling",
    "BudgetSummary",
    "ControlEvidence",
    "DelegatedActionConstraint",
    "DelegatedAuthority",
    "DelegatedBudget",
    "DelegatedStatus",
    "DelegationReview",
    "EffectiveAuthoritySummary",
    "ExactBody",
    "ExpiryOnly",
    "InheritAction",
    "InheritBudget",
    "InheritStatus",
    "NoBudget",
    "Permission",
    "Principal",
    "PrincipalDescriptor",
    "Profile",
    "ProviderFailureKind",
    "ProviderOperationError",
    "ReviewField",
    "SignatureSummary",
    "SignedGrantInput",
    "SignedGrantLoadRequest",
    "SignedGrantMaterial",
    "SignedGrantProvider",
    "SignedGrantSource",
    "Signer",
    "SignerLifecycle",
    "SigningObjectKind",
    "SigningRequest",
    "SigningResponse",
    "SnapshotRequired",
    "StatusSummary",
    "TrustedAuthority",
    "TrustedAuthoritySnapshot",
    "Validity",
)

__all__ = list(_WORKFLOW_EXPORTS)


def __getattr__(name: str) -> Any:
    if name not in _WORKFLOW_EXPORTS:
        raise AttributeError(f"module 'auths' has no attribute {name!r}")
    return getattr(import_module(".workflow", __name__), name)


def __dir__() -> list[str]:
    return sorted((*globals(), *_WORKFLOW_EXPORTS))
