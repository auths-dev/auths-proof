"""The remote Auths service client.

Separate from the product facade on purpose. The local facade
(`auths`) executes against providers this process holds; this client talks to
a service over HTTPS, and the two draw their `code` values from the same Rust
registry but nothing else. Keeping them at one import path published two
complete, unrelated SDKs under one name.
"""

from __future__ import annotations

from ._product_errors import (
    AuthsError,
    AuthsErrorCode,
    EffectState,
    ProductVerb,
    RecommendedAction,
    RetryClass,
)
from ._github_agent import (
    GitHubAgentBoundary,
    GitHubAgentClient,
    GitHubAgentError,
    GitHubAgentOutcome,
    GitHubAgentSession,
    GitHubAgentTask,
    GitHubCandidateFile,
    GitHubCandidateInspection,
    GitHubDenialFixture,
    GitHubVerifiedReceipts,
    create_github_agent_client,
)
from ._service import (
    NextCall,
    ServiceAuthority,
    import_authority,
    ServiceAuthorityResult,
    ServiceClient,
    ServiceCompleted,
    ServiceDenied,
    ServiceExecutionResult,
    ServiceIndeterminate,
    ServiceReceipt,
    ServiceRecoverable,
    ServiceRecoveryReference,
    ServiceRejected,
    ServiceTransport,
    ServiceTransportRequest,
    ServiceTransportResponse,
    ServiceVerificationResult,
    ServiceVerified,
    create_service_client,
)

__all__ = [
    "AuthsError",
    "AuthsErrorCode",
    "EffectState",
    "GitHubAgentBoundary",
    "GitHubAgentClient",
    "GitHubAgentError",
    "GitHubAgentOutcome",
    "GitHubAgentSession",
    "GitHubAgentTask",
    "GitHubCandidateFile",
    "GitHubCandidateInspection",
    "GitHubDenialFixture",
    "GitHubVerifiedReceipts",
    "NextCall",
    "ProductVerb",
    "RecommendedAction",
    "RetryClass",
    "ServiceAuthority",
    "import_authority",
    "ServiceAuthorityResult",
    "ServiceClient",
    "ServiceCompleted",
    "ServiceDenied",
    "ServiceExecutionResult",
    "ServiceIndeterminate",
    "ServiceReceipt",
    "ServiceRecoverable",
    "ServiceRecoveryReference",
    "ServiceRejected",
    "ServiceTransport",
    "ServiceTransportRequest",
    "ServiceTransportResponse",
    "ServiceVerificationResult",
    "ServiceVerified",
    "create_service_client",
    "create_github_agent_client",
]
