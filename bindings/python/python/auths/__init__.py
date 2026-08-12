"""Auths identity, authority, and protected-action SDK."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .bootstrap import PreparedRawKeyAuthority as PreparedRawKeyAuthority
    from .bootstrap import prepare_raw_key_authority as prepare_raw_key_authority
    from .workflow import *  # noqa: F403
    from ._product import *  # noqa: F403

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

_BOOTSTRAP_EXPORTS = (
    "PreparedRawKeyAuthority",
    "prepare_raw_key_authority",
)

_PRODUCT_EXPORTS = (
    "Actor",
    "Auths",
    "AuthsConfiguration",
    "Authority",
    "Completed",
    "Denied",
    "decode_execution_reference",
    "decode_receipt",
    "encode_execution_reference",
    "encode_receipt",
    "ExecutionReference",
    "ExecutionResult",
    "Indeterminate",
    "PlanCompleted",
    "PlanRecoveryResult",
    "Receipt",
    "RecoveryResult",
    "verify_receipt",
)

__all__ = [*_WORKFLOW_EXPORTS, *_BOOTSTRAP_EXPORTS, *_PRODUCT_EXPORTS]


def __getattr__(name: str) -> Any:
    if name in _PRODUCT_EXPORTS:
        return getattr(import_module("._product", __name__), name)
    if name in _BOOTSTRAP_EXPORTS:
        return getattr(import_module(".bootstrap", __name__), name)
    if name not in _WORKFLOW_EXPORTS:
        raise AttributeError(f"module 'auths' has no attribute {name!r}")
    return getattr(import_module(".workflow", __name__), name)


def __dir__() -> list[str]:
    return sorted((*globals(), *_WORKFLOW_EXPORTS))
