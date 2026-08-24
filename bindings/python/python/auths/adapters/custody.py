from __future__ import annotations

from dataclasses import dataclass as _dataclass
from enum import Enum as _Enum
from typing import Literal as _Literal, Protocol as _Protocol, Tuple as _Tuple, Union as _Union, cast as _cast


class _StringEnum(str, _Enum):
    def __str__(self) -> str:
        return _cast(str, self.value)


class SigningObjectKind(_StringEnum):
    GRANT = "grant"
    ACTION = "action"
    PRINCIPAL_STATUS = "principal-status"
    GRANT_STATUS = "grant-status"


class CustodyLifecycle(_StringEnum):
    DURABLE = "durable"
    EPHEMERAL = "ephemeral"


class CustodyKind(_StringEnum):
    WEBAUTHN = "webauthn"
    WORKLOAD = "workload"
    KMS = "kms"
    HSM = "hsm"
    PKCS11 = "pkcs11"


class CustodyKeyState(_StringEnum):
    ENROLLED = "enrolled"
    READY = "ready"
    ROTATION_PENDING = "rotation-pending"
    ACTIVE_CURRENT = "active-current"
    RETIRING_PREVIOUS = "retiring-previous"
    REVOKED = "revoked"
    DISABLED = "disabled"
    UNAVAILABLE = "unavailable"
    INDETERMINATE = "indeterminate"


class CustodyFailure(_StringEnum):
    DENIED = "denied"
    CANCELLED = "cancelled"
    THROTTLED = "throttled"
    UNAVAILABLE = "unavailable"
    REVOKED_KEY = "revoked-key"
    DISABLED_KEY = "disabled-key"
    PROVIDER_UNKNOWN = "provider-unknown"
    INVALID_PROVIDER_RESPONSE = "invalid-provider-response"


@_dataclass(frozen=True)
class CustodySignatureDescriptor:
    principal_method: str
    verification_method: str
    suite: str


@_dataclass(frozen=True)
class CustodyDescriptor:
    contract: _Literal["signer-custody/2"]
    kind: CustodyKind
    adapter_id: str
    principal: str
    signature: CustodySignatureDescriptor
    key_version: str
    key_state: CustodyKeyState
    lifecycle: CustodyLifecycle


@_dataclass(frozen=True)
class ReviewField:
    label: str
    value: str


@_dataclass(frozen=True)
class PublicControlEvidence:
    evidence_type: str
    media_type: str
    bytes: bytes


@_dataclass(frozen=True)
class SigningRequest:
    request_id: str
    object_kind: SigningObjectKind
    object_id: bytes
    descriptor: CustodyDescriptor
    transaction_digest: bytes
    signing_preimage: bytes
    expires_at_unix_seconds: int
    display: _Tuple[ReviewField, ...]


@_dataclass(frozen=True)
class SigningResponse:
    request_id: str
    object_id: bytes
    principal: str
    descriptor: CustodySignatureDescriptor
    provider_key_version: str
    transaction_digest: bytes
    signature: bytes
    evidence: _Tuple[PublicControlEvidence, ...]


@_dataclass(frozen=True)
class CustodySigned:
    kind: _Literal["signed"]
    response: SigningResponse


@_dataclass(frozen=True)
class CustodyRejected:
    kind: _Literal["rejected"]
    failure: _Literal[CustodyFailure.DENIED, CustodyFailure.CANCELLED, CustodyFailure.REVOKED_KEY, CustodyFailure.DISABLED_KEY]


@_dataclass(frozen=True)
class CustodyIndeterminate:
    kind: _Literal["indeterminate"]
    failure: _Literal[CustodyFailure.THROTTLED, CustodyFailure.UNAVAILABLE, CustodyFailure.PROVIDER_UNKNOWN, CustodyFailure.INVALID_PROVIDER_RESPONSE]


CustodySignResult = _Union[CustodySigned, CustodyRejected, CustodyIndeterminate]


class CustodySigner(_Protocol):
    @property
    def descriptor(self) -> CustodyDescriptor: ...
    async def sign(self, request: SigningRequest) -> CustodySignResult: ...
    async def aclose(self) -> None: ...


__all__ = [
    "SigningObjectKind", "CustodyLifecycle", "CustodyKind", "CustodyKeyState",
    "CustodyFailure", "CustodySignatureDescriptor", "CustodyDescriptor",
    "ReviewField", "PublicControlEvidence", "SigningRequest", "SigningResponse",
    "CustodySigned", "CustodyRejected", "CustodyIndeterminate",
    "CustodySignResult", "CustodySigner",
]
