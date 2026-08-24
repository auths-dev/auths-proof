from __future__ import annotations

from dataclasses import dataclass as _dataclass
from typing import Generic as _Generic, Literal as _Literal, Protocol as _Protocol
from typing import Sequence as _Sequence, Tuple as _Tuple, TypeVar as _TypeVar, Union as _Union

from . import IdentityClient, _create_client


@_dataclass(frozen=True)
class VerificationMaterial:
    material_id: str
    bytes: bytes


@_dataclass(frozen=True)
class VerificationRelationship:
    relationship_id: str
    purpose: str
    suite_id: str
    verification_material: _Tuple[VerificationMaterial, ...]


@_dataclass(frozen=True)
class DecodedIdentityRecord:
    method_id: str
    identity_id: str
    method_material: bytes
    relationships: _Tuple[VerificationRelationship, ...]


@_dataclass(frozen=True)
class ResolutionEvidence:
    source: str
    observed_at_unix_seconds: int
    expires_at_unix_seconds: int
    provenance: _Tuple[str, ...]
    history: _Tuple[str, ...] = ()


@_dataclass(frozen=True)
class ResolvedIdentityRecord:
    method_id: str
    identity_id: str
    method_material: bytes
    relationships: _Tuple[VerificationRelationship, ...]
    evidence: ResolutionEvidence


_AdapterT = _TypeVar("_AdapterT")
_AdapterRejection = _Literal["not-found", "malformed", "not-permitted", "expired", "invalid-signature"]
_AdapterUncertainty = _Literal["cancelled", "timeout", "unavailable", "invalid-response"]


@_dataclass(frozen=True)
class AdapterOk(_Generic[_AdapterT]):
    kind: _Literal["ok"]
    value: _AdapterT


@_dataclass(frozen=True)
class AdapterRejected:
    kind: _Literal["rejected"]
    reason: _AdapterRejection


@_dataclass(frozen=True)
class AdapterIndeterminate:
    kind: _Literal["indeterminate"]
    reason: _AdapterUncertainty


AdapterResult = _Union[AdapterOk[_AdapterT], AdapterRejected, AdapterIndeterminate]


class IdentityResolver(_Protocol):
    async def resolve(self, descriptor: DecodedIdentityRecord, /, *, maximum_bytes: int) -> AdapterResult[ResolvedIdentityRecord]: ...
    async def aclose(self) -> None: ...


class IdentityMethod(_Protocol):
    method_id: str
    version: int
    async def resolve(self, descriptor: DecodedIdentityRecord) -> AdapterResult[ResolvedIdentityRecord]: ...
    async def validate(self, record: ResolvedIdentityRecord) -> AdapterResult[None]: ...
    async def aclose(self) -> None: ...


class MessageAuthenticator(_Protocol):
    suite_id: str
    version: int
    async def verify(self, *, relationship: VerificationRelationship, preimage: bytes, signature: bytes) -> AdapterResult[None]: ...
    async def aclose(self) -> None: ...


class _ResolverMethod:
    def __init__(self, method_id: str, version: int, resolver: IdentityResolver, maximum_bytes: int, owns: bool) -> None:
        if not method_id or not 1 <= len(method_id.encode("utf-8")) <= 128 or version < 1:
            raise ValueError("invalid identity method descriptor")
        if not 1 <= maximum_bytes <= 131_072:
            raise ValueError("maximum_bytes is outside 1..131072")
        self.method_id = method_id
        self.version = version
        self._resolver = resolver
        self._maximum = maximum_bytes
        self._owns = owns

    async def resolve(self, descriptor: DecodedIdentityRecord) -> AdapterResult[ResolvedIdentityRecord]:
        return await self._resolver.resolve(descriptor, maximum_bytes=self._maximum)

    async def validate(self, record: ResolvedIdentityRecord) -> AdapterResult[None]:
        return AdapterOk("ok", None)

    async def aclose(self) -> None:
        if self._owns:
            await self._resolver.aclose()


def create_client(*, methods: _Sequence[IdentityMethod], authenticators: _Sequence[MessageAuthenticator], owns_adapters: bool = False) -> IdentityClient:
    if not 1 <= len(methods) <= 32 or not 1 <= len(authenticators) <= 32:
        raise ValueError("identity client requires 1..32 methods and authenticators")
    return _create_client(tuple(methods), tuple(authenticators), owns_adapters)


def resolver_method(*, method_id: str, version: int, resolver: IdentityResolver, maximum_bytes: int = 131_072, owns_resolver: bool = False) -> IdentityMethod:
    return _ResolverMethod(method_id, version, resolver, maximum_bytes, owns_resolver)


__all__ = [
    "VerificationMaterial", "VerificationRelationship", "DecodedIdentityRecord",
    "ResolutionEvidence", "ResolvedIdentityRecord", "AdapterOk", "AdapterRejected",
    "AdapterIndeterminate", "AdapterResult", "IdentityResolver", "IdentityMethod",
    "MessageAuthenticator", "create_client", "resolver_method",
]
