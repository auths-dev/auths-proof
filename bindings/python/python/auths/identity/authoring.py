from __future__ import annotations

from typing import Sequence as _Sequence

from .._native import (
    compact_identity_descriptor_v1 as _compact_descriptor,
    decode_identity_descriptor_v1 as _decode_descriptor,
    encode_identity_descriptor_v1 as _encode_descriptor,
    identity_descriptor_signing_preimage_v1 as _signing_preimage,
    raw_key_identity_v2 as _raw_key_identity,
)
from . import ValidatedIdentity, _validated
from .adapters import DecodedIdentityRecord, ResolutionEvidence, ResolvedIdentityRecord, VerificationMaterial, VerificationRelationship

_TOKEN = object()


class PreparedIdentityMessage:
    __slots__ = ("identity", "relationship_id", "message", "signing_preimage")

    def __init__(self, token: object, identity: ValidatedIdentity, relationship_id: str, message: bytes, preimage: bytes) -> None:
        if token is not _TOKEN:
            raise TypeError("PreparedIdentityMessage is sealed")
        self.identity = identity
        self.relationship_id = relationship_id
        self.message = bytes(message)
        self.signing_preimage = bytes(preimage)


def create_raw_key_ed25519_identity(public_key: bytes, /) -> ValidatedIdentity:
    key = bytes(public_key)
    if len(key) != 32:
        raise ValueError("Ed25519 public key must contain exactly 32 bytes")
    packet = bytes(_compact_descriptor(_raw_key_identity("ed25519-v1", key)))
    projection = _decode_descriptor(packet)
    relationships = tuple(
        VerificationRelationship(
            relationship_id,
            purpose,
            suite_id,
            tuple(
                VerificationMaterial(material_id, bytes(material))
                for material_id, material in materials
            ),
        )
        for relationship_id, purpose, suite_id, materials in projection.relationships
    )
    decoded = DecodedIdentityRecord(
        projection.method_id,
        projection.identity_id,
        bytes(projection.method_material),
        relationships,
    )
    evidence = ResolutionEvidence("authoring", 0, 2**63 - 1, ("self-contained",))
    return _validated(packet, ResolvedIdentityRecord(decoded.method_id, decoded.identity_id, decoded.method_material, decoded.relationships, evidence))


def encode_identity(*, method_id: str, identity_id: str, relationships: _Sequence[VerificationRelationship], method_material: bytes = b"") -> bytes:
    values = tuple(relationships)
    if not 1 <= len(values) <= 16:
        raise ValueError("identity requires 1..16 relationships")
    native = [
        (value.relationship_id, value.purpose, value.suite_id, [(material.material_id, bytes(material.bytes)) for material in value.verification_material])
        for value in values
    ]
    return bytes(_encode_descriptor(method_id, identity_id, bytes(method_material), native))


def prepare_identity_message(identity: ValidatedIdentity, /, *, message: bytes, relationship_id: str = "default-signing") -> PreparedIdentityMessage:
    if relationship_id not in identity.relationships:
        raise ValueError("relationship is not present on the validated identity")
    body = bytes(message)
    if len(body) > 65_536:
        raise ValueError("identity message exceeds 65536 bytes")
    return PreparedIdentityMessage(_TOKEN, identity, relationship_id, body, _signing_preimage(identity.to_bytes(), relationship_id, body))


__all__ = [
    "PreparedIdentityMessage", "create_raw_key_ed25519_identity",
    "encode_identity", "prepare_identity_message",
]
