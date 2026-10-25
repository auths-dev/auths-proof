"""Bridge a proved Ed25519 identity key to the target-V1 Auths principal."""

from __future__ import annotations


def raw_key_public_for_identity_packet(packet: bytes) -> bytes:
    from auths import _native
    from auths.identity import IdentityOk, raw_key_ed25519

    decoded = raw_key_ed25519().decode(packet)
    if not isinstance(decoded, IdentityOk) or decoded.value.method_id != "raw-key-v2":
        raise ValueError("unsupported identity packet")
    projection = _native.decode_identity_descriptor_v1(packet)
    expected = (("default-signing", "authentication", "ed25519-v1"),)
    if tuple(item[:3] for item in projection.relationships) != expected:
        raise ValueError("unsupported identity relationship")
    materials = projection.relationships[0][3]
    if len(materials) != 1 or materials[0][0] != "default-key":
        raise ValueError("unsupported identity verification material")
    public_key = bytes(materials[0][1])
    if len(public_key) != 32:
        raise ValueError("unsupported identity verification material")
    return public_key


def authority_for_identity_packet(packet: bytes) -> tuple[str, bytes]:
    from auths import _native

    return _native.raw_key_ed25519_authority_v1(
        raw_key_public_for_identity_packet(packet),
    )
