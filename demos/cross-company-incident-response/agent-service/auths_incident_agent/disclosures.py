from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_SCHEMA = b"auths.receipt-disclosure-protection/1"
_MAX_PROTECTED_BYTES = 2 * 1024 * 1024 + 2048


class AesGcmDisclosureProtector:
    def __init__(self, key: bytes | None = None) -> None:
        configured = key if key is not None else _configured_key()
        self._cipher = AESGCM(
            AESGCM.generate_key(bit_length=256) if configured is None else configured
        )

    def protect(self, tenant: str, receipt_id: bytes, plaintext: bytes) -> bytes:
        material = bytes(plaintext)
        if not material or len(material) > _MAX_PROTECTED_BYTES:
            raise ValueError("receipt disclosure plaintext is outside bounds")
        nonce = os.urandom(12)
        return (
            b"\x01"
            + nonce
            + self._cipher.encrypt(
                nonce, material, _associated_data(tenant, receipt_id)
            )
        )

    def reveal(self, tenant: str, receipt_id: bytes, protected: bytes) -> bytes:
        material = bytes(protected)
        if len(material) < 30 or len(material) > _MAX_PROTECTED_BYTES + 32:
            raise ValueError("protected receipt disclosure is outside bounds")
        if material[0] != 1:
            raise ValueError("protected receipt disclosure version is unsupported")
        return self._cipher.decrypt(
            material[1:13], material[13:], _associated_data(tenant, receipt_id)
        )


def _configured_key() -> bytes | None:
    value = os.environ.get("AUTHS_RECEIPT_DISCLOSURE_KEY")
    if value is None:
        return None
    try:
        key = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError:
        raise ValueError("receipt disclosure key is malformed") from None
    if len(key) != 32:
        raise ValueError("receipt disclosure key must contain 32 bytes")
    return key


def _associated_data(tenant: str, receipt_id: bytes) -> bytes:
    tenant_bytes = tenant.encode()
    identifier = bytes(receipt_id)
    if not tenant_bytes or len(tenant_bytes) > 256 or len(identifier) != 32:
        raise ValueError("receipt disclosure scope is outside bounds")
    return b"".join(
        (
            _SCHEMA,
            len(tenant_bytes).to_bytes(2, "big"),
            tenant_bytes,
            identifier,
        )
    )


__all__ = ["AesGcmDisclosureProtector"]
