"""Typed principal and delegated-authority lifecycle authoring."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Literal, Optional, Protocol, Sequence, Tuple, Union, runtime_checkable

from . import _native as native
from ._native import SignedObject
from .workflow import (
    ApprovalConfiguration,
    ApprovalPolicyReference,
    AuthsWorkflowError,
    Principal,
    ReviewField,
    Signer,
    _SigningCoordinator,
    _call_public_identity,
)

LifecycleState = Literal["active", "revoked", "superseded"]
_SIGNED_TOKEN = object()
_SNAPSHOT_TOKEN = object()


@dataclass(frozen=True)
class ProtocolDigest:
    bytes: bytes

    def __post_init__(self) -> None:
        value = bytes(self.bytes)
        if len(value) != 32:
            raise ValueError("protocol digest must contain 32 bytes")
        object.__setattr__(self, "bytes", value)

    @classmethod
    def parse(cls, value: str) -> ProtocolDigest:
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise ValueError("protocol digest must be 64 lowercase hexadecimal characters")
        return cls(bytes.fromhex(value))


@dataclass(frozen=True)
class CriticalExtension:
    id: str
    bytes: bytes

    def __post_init__(self) -> None:
        object.__setattr__(self, "bytes", bytes(self.bytes))


@dataclass(frozen=True)
class PrincipalStatusRequest:
    method: str
    principal: Principal
    purpose: str
    state: LifecycleState
    sequence: int
    observed_at: int
    valid_until: int
    issuer: Principal
    extensions: Tuple[CriticalExtension, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "extensions", tuple(self.extensions))


@dataclass(frozen=True)
class GrantStatusRequest:
    method: str
    grant_id: ProtocolDigest
    state: LifecycleState
    sequence: int
    observed_at: int
    valid_until: int
    issuer: Principal
    extensions: Tuple[CriticalExtension, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "extensions", tuple(self.extensions))


@dataclass(frozen=True)
class IdentityRotation:
    previous: PrincipalStatusRequest
    current: PrincipalStatusRequest


class SignedPrincipalStatus:
    def __init__(self, token: object, value: SignedObject) -> None:
        if token is not _SIGNED_TOKEN:
            raise TypeError("sealed Auths principal status")
        self._value = value


class SignedGrantStatus:
    def __init__(self, token: object, value: SignedObject) -> None:
        if token is not _SIGNED_TOKEN:
            raise TypeError("sealed Auths grant status")
        self._value = value


@dataclass(frozen=True)
class StatusTrustRule:
    method: str
    issuer: Principal
    sequence_floor: int


class PrincipalStatusSnapshot:
    def __init__(
        self, token: object, identifier: ProtocolDigest, native: native.StatusSnapshot
    ) -> None:
        if token is not _SNAPSHOT_TOKEN:
            raise TypeError("sealed Auths principal status snapshot")
        self.id = identifier
        self._native = native


class GrantStatusSnapshot:
    def __init__(
        self, token: object, identifier: ProtocolDigest, native: native.StatusSnapshot
    ) -> None:
        if token is not _SNAPSHOT_TOKEN:
            raise TypeError("sealed Auths grant status snapshot")
        self.id = identifier
        self._native = native


class LifecycleAuthor:
    def __init__(
        self,
        *,
        signer: Signer,
        approval: ApprovalConfiguration,
        required_approval: ApprovalPolicyReference,
    ) -> None:
        self._signer = signer
        self._approval = approval
        self._required_approval = required_approval
        self._closed = False

    async def principal_status(
        self, request: PrincipalStatusRequest
    ) -> SignedPrincipalStatus:
        self._assert_open()
        if type(request) is not PrincipalStatusRequest:
            raise TypeError("request must be a PrincipalStatusRequest")
        unsigned = native.principal_status_statement(
            request.method,
            request.principal,
            request.purpose,
            request.state,
            request.sequence,
            request.observed_at,
            request.valid_until,
            request.issuer,
            [(value.id, value.bytes) for value in request.extensions],
        )
        return SignedPrincipalStatus(
            _SIGNED_TOKEN,
            await self._sign(unsigned, request.issuer, request.valid_until, "Principal status"),
        )

    async def grant_status(self, request: GrantStatusRequest) -> SignedGrantStatus:
        self._assert_open()
        if type(request) is not GrantStatusRequest:
            raise TypeError("request must be a GrantStatusRequest")
        unsigned = native.grant_status_statement(
            request.method,
            request.grant_id.bytes,
            request.state,
            request.sequence,
            request.observed_at,
            request.valid_until,
            request.issuer,
            [(value.id, value.bytes) for value in request.extensions],
        )
        return SignedGrantStatus(
            _SIGNED_TOKEN,
            await self._sign(unsigned, request.issuer, request.valid_until, "Grant status"),
        )

    def close(self) -> None:
        self._closed = True

    async def _sign(
        self, unsigned: native.UnsignedObject, issuer: Principal, expires_at: int, label: str
    ) -> SignedObject:
        descriptor = await _call_public_identity(self._signer, "lifecycle signer")
        if descriptor.principal.value != issuer.value:
            raise AuthsWorkflowError(
                "invalid-principal", "lifecycle signer does not control the declared issuer"
            )
        result = await _SigningCoordinator().execute(
            unsigned=unsigned,
            principal=descriptor,
            signer=self._signer,
            approval=self._approval,
            required_approval=self._required_approval,
            expires_at=expires_at,
            display=(ReviewField("Operation", label), ReviewField("Issuer", issuer.value)),
        )
        return result.signed_object

    def _assert_open(self) -> None:
        if self._closed:
            raise AuthsWorkflowError("disposed", "lifecycle author is closed")


def principal_status_snapshot(
    identifier: ProtocolDigest,
    *,
    observed_at: int,
    valid_until: int,
    statements: Sequence[SignedPrincipalStatus],
    checkpoints: Sequence[ProtocolDigest] = (),
    trust: Sequence[StatusTrustRule] = (),
) -> PrincipalStatusSnapshot:
    values = tuple(statements)
    if any(type(value) is not SignedPrincipalStatus for value in values):
        raise TypeError("principal snapshot contains another status kind")
    snapshot = native.status_snapshot(
        "principal",
        identifier.bytes,
        observed_at,
        valid_until,
        [value._value for value in values],
        [value.bytes for value in checkpoints],
        [(value.method, value.issuer.value, value.sequence_floor) for value in trust],
    )
    return PrincipalStatusSnapshot(_SNAPSHOT_TOKEN, identifier, snapshot)


def grant_status_snapshot(
    identifier: ProtocolDigest,
    *,
    observed_at: int,
    valid_until: int,
    statements: Sequence[SignedGrantStatus],
    checkpoints: Sequence[ProtocolDigest] = (),
    trust: Sequence[StatusTrustRule] = (),
) -> GrantStatusSnapshot:
    values = tuple(statements)
    if any(type(value) is not SignedGrantStatus for value in values):
        raise TypeError("grant snapshot contains another status kind")
    snapshot = native.status_snapshot(
        "grant",
        identifier.bytes,
        observed_at,
        valid_until,
        [value._value for value in values],
        [value.bytes for value in checkpoints],
        [(value.method, value.issuer.value, value.sequence_floor) for value in trust],
    )
    return GrantStatusSnapshot(_SNAPSHOT_TOKEN, identifier, snapshot)


def withdraw_delegation(
    *,
    method: str,
    grant_id: ProtocolDigest,
    issuer: Principal,
    sequence: int,
    valid_for: int,
    observed_at: Optional[int] = None,
) -> GrantStatusRequest:
    observed = int(time.time()) if observed_at is None else observed_at
    return GrantStatusRequest(
        method, grant_id, "revoked", sequence, observed, observed + valid_for, issuer
    )


def record_compromise(
    *,
    method: str,
    principal: Principal,
    purpose: str,
    issuer: Principal,
    sequence: int,
    valid_for: int,
    observed_at: Optional[int] = None,
) -> PrincipalStatusRequest:
    observed = int(time.time()) if observed_at is None else observed_at
    return PrincipalStatusRequest(
        method,
        principal,
        purpose,
        "revoked",
        sequence,
        observed,
        observed + valid_for,
        issuer,
    )


def rotate_identity(
    *,
    method: str,
    previous: Principal,
    current: Principal,
    purpose: str,
    issuer: Principal,
    previous_sequence: int,
    current_sequence: int,
    valid_for: int,
    observed_at: Optional[int] = None,
) -> IdentityRotation:
    observed = int(time.time()) if observed_at is None else observed_at
    valid_until = observed + valid_for
    return IdentityRotation(
        PrincipalStatusRequest(
            method,
            previous,
            purpose,
            "superseded",
            previous_sequence,
            observed,
            valid_until,
            issuer,
        ),
        PrincipalStatusRequest(
            method,
            current,
            purpose,
            "active",
            current_sequence,
            observed,
            valid_until,
            issuer,
        ),
    )


StatusSnapshot = Union[PrincipalStatusSnapshot, GrantStatusSnapshot]


@runtime_checkable
class StatusProvider(Protocol):
    contract_version: int

    async def principal(
        self, identifier: ProtocolDigest, *, observed_at: int
    ) -> PrincipalStatusSnapshot: ...

    async def grant(
        self, identifier: ProtocolDigest, *, observed_at: int
    ) -> GrantStatusSnapshot: ...

__all__ = [
    "CriticalExtension",
    "GrantStatusRequest",
    "GrantStatusSnapshot",
    "IdentityRotation",
    "LifecycleAuthor",
    "LifecycleState",
    "PrincipalStatusRequest",
    "PrincipalStatusSnapshot",
    "ProtocolDigest",
    "SignedGrantStatus",
    "SignedPrincipalStatus",
    "StatusSnapshot",
    "StatusProvider",
    "StatusTrustRule",
    "grant_status_snapshot",
    "principal_status_snapshot",
    "record_compromise",
    "rotate_identity",
    "withdraw_delegation",
]
