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
from ._service import (
    NextCall,
    ServiceAuthority,
    ServiceAuthorityResult,
    ServiceAuths,
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
    create_auths,
)

__all__ = [
    "AuthsError",
    "AuthsErrorCode",
    "EffectState",
    "NextCall",
    "ProductVerb",
    "RecommendedAction",
    "RetryClass",
    "ServiceAuthority",
    "ServiceAuthorityResult",
    "ServiceAuths",
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
    "create_auths",
]
