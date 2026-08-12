"""Transport- and authority-independent identity and authentication."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from types import MappingProxyType
from typing import (
    Awaitable,
    Mapping,
    Protocol,
    Sequence,
    Tuple,
    TypeVar,
    runtime_checkable,
)

from ._native import (
    compact_identity_descriptor_v1,
    decode_identity_descriptor_v1,
    encode_identity_descriptor_v1,
    identity_descriptor_signing_preimage_v1,
    raw_key_identity_v2,
    validate_raw_key_identity_v2,
    verify_ed25519_preimage_v1,
)

MAX_IDENTITY_TIMEOUT = 300.0
ValueT = TypeVar("ValueT")


@dataclass(frozen=True)
class VerificationMaterial:
    material_id: str
    bytes: bytes

    def __post_init__(self) -> None:
        value = bytes(self.bytes)
        if not self.material_id or not value or len(value) > 128 * 1024:
            raise ValueError("verification material is outside supported bounds")
        object.__setattr__(self, "bytes", value)


@dataclass(frozen=True)
class VerificationRelationship:
    relationship_id: str
    purpose: str
    suite_id: str
    verification_material: Tuple[VerificationMaterial, ...]

    def __post_init__(self) -> None:
        values = tuple(self.verification_material)
        if not values or any(
            type(value) is not VerificationMaterial for value in values
        ):
            raise ValueError("verification relationship requires typed material")
        object.__setattr__(self, "verification_material", values)


@dataclass(frozen=True)
class ResolutionEvidence:
    source: str
    observed_at: int
    expires_at: int
    provenance: Tuple[str, ...]
    history: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            not self.source
            or self.observed_at < 0
            or self.expires_at < self.observed_at
        ):
            raise ValueError("invalid identity resolution evidence")
        object.__setattr__(self, "provenance", tuple(self.provenance))
        object.__setattr__(self, "history", tuple(self.history))


@dataclass(frozen=True)
class ResolvedIdentityRecord:
    method_id: str
    identity_id: str
    method_material: bytes
    relationships: Tuple[VerificationRelationship, ...]
    evidence: ResolutionEvidence

    def __post_init__(self) -> None:
        object.__setattr__(self, "method_material", bytes(self.method_material))
        values = tuple(self.relationships)
        if not values or any(
            type(value) is not VerificationRelationship for value in values
        ):
            raise ValueError(
                "resolved identity has no typed verification relationships"
            )
        object.__setattr__(self, "relationships", values)

    def relationship(self, relationship_id: str) -> VerificationRelationship:
        values = tuple(
            value
            for value in self.relationships
            if value.relationship_id == relationship_id
        )
        if len(values) != 1:
            raise ValueError("identity relationship is missing or ambiguous")
        return values[0]

    def canonical_bytes(self) -> bytes:
        return _encode_descriptor(
            self.method_id,
            self.identity_id,
            self.method_material,
            self.relationships,
        )


@runtime_checkable
class IdentityResolver(Protocol):
    async def resolve(
        self, method_id: str, identity_id: str, *, maximum_bytes: int
    ) -> ResolvedIdentityRecord: ...


@runtime_checkable
class IdentityMethod(Protocol):
    method_id: str
    version: int

    async def resolve(self, identity: DecodedIdentity) -> ResolvedIdentityRecord: ...

    async def validate(self, identity: ResolvedIdentity) -> None: ...


@runtime_checkable
class SignatureSuite(Protocol):
    suite_id: str
    version: int

    async def verify(
        self,
        material: Tuple[VerificationMaterial, ...],
        preimage: bytes,
        signature: bytes,
    ) -> None: ...


@dataclass(frozen=True)
class DecodedIdentity:
    method_id: str
    identity_id: str
    method_material: bytes
    relationships: Tuple[VerificationRelationship, ...]
    packet: bytes

    def relationship(self, relationship_id: str) -> VerificationRelationship:
        return self._record().relationship(relationship_id)

    async def resolve(
        self,
        registry: IdentityRegistry,
        *,
        timeout: float = 10.0,
    ) -> ResolvedIdentity:
        method = registry.method(self.method_id)
        record = await _bounded_await(method.resolve(self), timeout)
        if record.method_id != self.method_id or record.identity_id != self.identity_id:
            raise ValueError("identity resolver returned a different identity")
        return ResolvedIdentity(self, record)

    async def validate(
        self,
        registry: IdentityRegistry,
        *,
        timeout: float = 10.0,
    ) -> ValidatedIdentity:
        resolved = await self.resolve(registry, timeout=timeout)
        return await resolved.validate(registry, timeout=timeout)

    def _record(self) -> ResolvedIdentityRecord:
        return ResolvedIdentityRecord(
            self.method_id,
            self.identity_id,
            self.method_material,
            self.relationships,
            ResolutionEvidence("packet", 0, (1 << 64) - 1, ("packet",)),
        )


@dataclass(frozen=True)
class ResolvedIdentity:
    decoded: DecodedIdentity
    record: ResolvedIdentityRecord

    @property
    def identity_id(self) -> str:
        return self.record.identity_id

    @property
    def evidence(self) -> ResolutionEvidence:
        return self.record.evidence

    async def validate(
        self,
        registry: IdentityRegistry,
        *,
        timeout: float = 10.0,
    ) -> ValidatedIdentity:
        method = registry.method(self.record.method_id)
        await _bounded_await(method.validate(self), timeout)
        return ValidatedIdentity(self)


@dataclass(frozen=True)
class ValidatedIdentity:
    resolved: ResolvedIdentity

    @property
    def identity_id(self) -> str:
        return self.resolved.identity_id

    async def authenticate(
        self,
        message: bytes,
        signature: bytes,
        registry: IdentityRegistry,
        *,
        relationship_id: str = "default-signing",
        timeout: float = 10.0,
    ) -> AuthenticatedIdentity:
        message_bytes = bytes(message)
        signature_bytes = bytes(signature)
        relationship = self.resolved.record.relationship(relationship_id)
        preimage = bytes(
            identity_descriptor_signing_preimage_v1(
                self.resolved.record.canonical_bytes(),
                relationship_id,
                message_bytes,
            )
        )
        suite = registry.suite(relationship.suite_id)
        await _bounded_await(
            suite.verify(relationship.verification_material, preimage, signature_bytes),
            timeout,
        )
        return AuthenticatedIdentity(
            self, relationship_id, message_bytes, signature_bytes
        )

    def authority_input(
        self, *, relationship_id: str = "default-signing", assurance: str
    ) -> IdentityPrincipal:
        if not assurance:
            raise ValueError("identity assurance cannot be empty")
        relationship = self.resolved.record.relationship(relationship_id)
        return IdentityPrincipal(
            principal_id=self.resolved.record.identity_id,
            method_id=self.resolved.record.method_id,
            relationship_id=relationship.relationship_id,
            suite_id=relationship.suite_id,
            purpose=relationship.purpose,
            provenance=self.resolved.evidence.provenance,
            assurance=assurance,
        )


@dataclass(frozen=True)
class AuthenticatedIdentity:
    validated: ValidatedIdentity
    relationship_id: str
    message: bytes
    signature: bytes

    @property
    def identity_id(self) -> str:
        return self.validated.identity_id


@dataclass(frozen=True)
class IdentityPrincipal:
    principal_id: str
    method_id: str
    relationship_id: str
    suite_id: str
    purpose: str
    provenance: Tuple[str, ...]
    assurance: str


class IdentityRegistry:
    def __init__(
        self,
        *,
        methods: Sequence[IdentityMethod],
        suites: Sequence[SignatureSuite],
    ) -> None:
        method_map = _exact_registry(methods, "method_id", "identity method")
        suite_map = _exact_registry(suites, "suite_id", "signature suite")
        self._methods: Mapping[str, IdentityMethod] = MappingProxyType(method_map)
        self._suites: Mapping[str, SignatureSuite] = MappingProxyType(suite_map)

    def method(self, method_id: str) -> IdentityMethod:
        try:
            return self._methods[method_id]
        except KeyError:
            raise ValueError("unsupported identity method") from None

    def suite(self, suite_id: str) -> SignatureSuite:
        try:
            return self._suites[suite_id]
        except KeyError:
            raise ValueError("unsupported signature suite") from None


class RawKeyIdentityMethod:
    method_id = "raw-key-v2"
    version = 2

    async def resolve(self, identity: DecodedIdentity) -> ResolvedIdentityRecord:
        return identity._record()

    async def validate(self, identity: ResolvedIdentity) -> None:
        record = identity.record
        relationship = record.relationship("default-signing")
        if (
            relationship.purpose != "authentication"
            or len(relationship.verification_material) != 1
        ):
            raise ValueError(
                "raw-key identity has an invalid verification relationship"
            )
        validate_raw_key_identity_v2(
            record.method_id,
            record.identity_id,
            relationship.suite_id,
            relationship.verification_material[0].bytes,
        )


class ResolverIdentityMethod:
    def __init__(
        self,
        method_id: str,
        resolver: IdentityResolver,
        *,
        version: int = 1,
        maximum_bytes: int = 128 * 1024,
    ) -> None:
        if not method_id or version < 1 or maximum_bytes < 1:
            raise ValueError("invalid resolver identity method")
        self.method_id = method_id
        self.version = version
        self._resolver = resolver
        self._maximum_bytes = maximum_bytes

    async def resolve(self, identity: DecodedIdentity) -> ResolvedIdentityRecord:
        return await self._resolver.resolve(
            self.method_id,
            identity.identity_id,
            maximum_bytes=self._maximum_bytes,
        )

    async def validate(self, identity: ResolvedIdentity) -> None:
        if identity.evidence.expires_at < identity.evidence.observed_at:
            raise ValueError("resolved identity evidence is invalid")


class Ed25519SignatureSuite:
    suite_id = "ed25519-v1"
    version = 1

    async def verify(
        self,
        material: Tuple[VerificationMaterial, ...],
        preimage: bytes,
        signature: bytes,
    ) -> None:
        if len(material) != 1:
            raise ValueError("Ed25519 requires one verification material object")
        verify_ed25519_preimage_v1(material[0].bytes, preimage, signature)


def decode_identity(packet: bytes) -> DecodedIdentity:
    packet_bytes = bytes(packet)
    try:
        native = decode_identity_descriptor_v1(packet_bytes)
    except ValueError:
        packet_bytes = bytes(compact_identity_descriptor_v1(packet_bytes))
        native = decode_identity_descriptor_v1(packet_bytes)
    relationships = tuple(
        VerificationRelationship(
            relationship_id,
            purpose,
            suite_id,
            tuple(
                VerificationMaterial(material_id, material)
                for material_id, material in materials
            ),
        )
        for relationship_id, purpose, suite_id, materials in native.relationships
    )
    return DecodedIdentity(
        native.method_id,
        native.identity_id,
        bytes(native.method_material),
        relationships,
        packet_bytes,
    )


def encode_identity(
    method_id: str,
    identity_id: str,
    *,
    method_material: bytes = b"",
    relationships: Sequence[VerificationRelationship],
) -> bytes:
    return _encode_descriptor(
        method_id, identity_id, bytes(method_material), tuple(relationships)
    )


def encode_raw_key_identity(suite_id: str, public_key: bytes) -> bytes:
    return bytes(raw_key_identity_v2(suite_id, public_key))


def _encode_descriptor(
    method_id: str,
    identity_id: str,
    method_material: bytes,
    relationships: Sequence[VerificationRelationship],
) -> bytes:
    return bytes(
        encode_identity_descriptor_v1(
            method_id,
            identity_id,
            method_material,
            [
                (
                    value.relationship_id,
                    value.purpose,
                    value.suite_id,
                    [
                        (material.material_id, material.bytes)
                        for material in value.verification_material
                    ],
                )
                for value in relationships
            ],
        )
    )


async def _bounded_await(value: Awaitable[ValueT], timeout: float) -> ValueT:
    if timeout <= 0 or timeout > MAX_IDENTITY_TIMEOUT:
        raise ValueError("identity timeout is outside supported limits")
    return await asyncio.wait_for(value, timeout=timeout)


def _exact_registry(
    values: Sequence[ValueT], attribute: str, label: str
) -> dict[str, ValueT]:
    result: dict[str, ValueT] = {}
    for value in values:
        identifier = getattr(value, attribute, None)
        version = getattr(value, "version", None)
        if (
            not isinstance(identifier, str)
            or not identifier
            or type(version) is not int
        ):
            raise TypeError(label + " does not declare an exact identifier and version")
        if identifier in result:
            raise ValueError("duplicate " + label)
        result[identifier] = value
    return result


__all__ = [
    "AuthenticatedIdentity",
    "DecodedIdentity",
    "Ed25519SignatureSuite",
    "IdentityMethod",
    "IdentityPrincipal",
    "IdentityRegistry",
    "IdentityResolver",
    "RawKeyIdentityMethod",
    "ResolutionEvidence",
    "ResolvedIdentity",
    "ResolvedIdentityRecord",
    "ResolverIdentityMethod",
    "SignatureSuite",
    "ValidatedIdentity",
    "VerificationMaterial",
    "VerificationRelationship",
    "decode_identity",
    "encode_identity",
    "encode_raw_key_identity",
]
