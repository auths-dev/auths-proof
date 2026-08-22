from __future__ import annotations

import asyncio as _asyncio
import time as _time
from dataclasses import dataclass as _dataclass
from datetime import timedelta as _timedelta
from typing import Any as _Any, Dict as _Dict, Generic as _Generic, Literal as _Literal
from typing import Optional as _Optional, Tuple as _Tuple, TypeVar as _TypeVar, Union as _Union

from .._native import (
    decode_identity_descriptor_v1 as _decode_descriptor,
    decode_identity_v1 as _decode_legacy,
    identity_descriptor_signing_preimage_v1 as _signing_preimage,
    validate_raw_key_identity_v2 as _validate_raw_key,
    verify_ed25519_preimage_v1 as _verify_ed25519,
)
from .._public import ErrorInfo as _ErrorInfo, error_info as _error_info

_IdentityT = _TypeVar("_IdentityT")


@_dataclass(frozen=True)
class IdentityOk(_Generic[_IdentityT]):
    kind: _Literal["ok"]
    value: _IdentityT


@_dataclass(frozen=True)
class IdentityRejected:
    kind: _Literal["rejected"]
    issue: _ErrorInfo


@_dataclass(frozen=True)
class IdentityIndeterminate:
    kind: _Literal["indeterminate"]
    issue: _ErrorInfo


IdentityResult = _Union[IdentityOk[_IdentityT], IdentityRejected, IdentityIndeterminate]

_TOKEN = object()


class DecodedIdentity:
    __slots__ = ("method_id", "identity_id", "method_material", "relationships", "_packet", "_record")

    def __init__(self, token: object, packet: bytes, record: _Any) -> None:
        if token is not _TOKEN:
            raise TypeError("DecodedIdentity is sealed")
        self.method_id = record.method_id
        self.identity_id = record.identity_id
        self.method_material = bytes(record.method_material)
        self.relationships = tuple(item.relationship_id for item in record.relationships)
        self._packet = bytes(packet)
        self._record = record

    def to_bytes(self) -> bytes:
        return bytes(self._packet)

    async def resolve(self, client: "IdentityClient", *, timeout: _timedelta = _timedelta(seconds=10)) -> IdentityResult["ResolvedIdentity"]:
        return await client.resolve(self, timeout=timeout)


class ResolvedIdentity:
    __slots__ = ("method_id", "identity_id", "evidence_source", "observed_at_unix_seconds", "expires_at_unix_seconds", "provenance", "_packet", "_record")

    def __init__(self, token: object, packet: bytes, record: _Any) -> None:
        if token is not _TOKEN:
            raise TypeError("ResolvedIdentity is sealed")
        evidence = record.evidence
        self.method_id = record.method_id
        self.identity_id = record.identity_id
        self.evidence_source = evidence.source
        self.observed_at_unix_seconds = evidence.observed_at_unix_seconds
        self.expires_at_unix_seconds = evidence.expires_at_unix_seconds
        self.provenance = tuple(evidence.provenance)
        self._packet = bytes(packet)
        self._record = record

    async def validate(self, client: "IdentityClient", *, timeout: _timedelta = _timedelta(seconds=10)) -> IdentityResult["ValidatedIdentity"]:
        return await client.validate(self, timeout=timeout)


class ValidatedIdentity:
    __slots__ = ("method_id", "identity_id", "relationships", "_packet", "_record")

    def __init__(self, token: object, packet: bytes, record: _Any) -> None:
        if token is not _TOKEN:
            raise TypeError("ValidatedIdentity is sealed")
        self.method_id = record.method_id
        self.identity_id = record.identity_id
        self.relationships = tuple(item.relationship_id for item in record.relationships)
        self._packet = bytes(packet)
        self._record = record

    def to_bytes(self) -> bytes:
        return bytes(self._packet)

    async def authenticate(self, client: "IdentityClient", *, message: bytes, signature: bytes, relationship_id: str = "default-signing", timeout: _timedelta = _timedelta(seconds=10)) -> IdentityResult["AuthenticatedIdentityMessage"]:
        return await client.authenticate(self, relationship_id=relationship_id, message=message, signature=signature, timeout=timeout)


class AuthenticatedIdentityMessage:
    __slots__ = ("identity", "relationship_id", "message")

    def __init__(self, token: object, identity: ValidatedIdentity, relationship_id: str, message: bytes) -> None:
        if token is not _TOKEN:
            raise TypeError("AuthenticatedIdentityMessage is sealed")
        self.identity = identity
        self.relationship_id = relationship_id
        self.message = bytes(message)


def _seconds(value: _timedelta) -> float:
    seconds = value.total_seconds()
    if seconds <= 0 or seconds * 1000 != int(seconds * 1000):
        raise ValueError("timeout must be a positive whole number of milliseconds")
    return seconds


class IdentityClient:
    def __init__(self, token: object, methods: _Tuple[_Any, ...], authenticators: _Tuple[_Any, ...], owns_adapters: bool) -> None:
        if token is not _TOKEN:
            raise TypeError("IdentityClient is sealed")
        self._methods: _Dict[str, _Any] = {value.method_id: value for value in methods}
        self._authenticators: _Dict[str, _Any] = {value.suite_id: value for value in authenticators}
        if len(self._methods) != len(methods) or len(self._authenticators) != len(authenticators):
            raise ValueError("duplicate identity adapter")
        self._owns = owns_adapters
        self._state = "new"

    async def __aenter__(self) -> "IdentityClient":
        if self._state != "new":
            raise RuntimeError("auths client is not open")
        self._state = "open"
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._state == "closed":
            return
        self._state = "closing"
        if self._owns:
            for value in (*self._methods.values(), *self._authenticators.values()):
                close = getattr(value, "aclose", None)
                if close is not None:
                    await close()
        self._state = "closed"

    def _open(self) -> None:
        if self._state != "open":
            raise RuntimeError("auths client is not open")

    def decode(self, packet: bytes, /) -> IdentityResult[DecodedIdentity]:
        from .adapters import DecodedIdentityRecord, VerificationMaterial, VerificationRelationship
        try:
            raw = _decode_descriptor(bytes(packet))
            relationships = tuple(
                VerificationRelationship(rid, purpose, suite, tuple(VerificationMaterial(mid, bytes(material)) for mid, material in values))
                for rid, purpose, suite, values in raw.relationships
            )
            record = DecodedIdentityRecord(raw.method_id, raw.identity_id, bytes(raw.method_material), relationships)
            return IdentityOk("ok", DecodedIdentity(_TOKEN, bytes(packet), record))
        except Exception:
            try:
                legacy = _decode_legacy(bytes(packet))
                relationship = VerificationRelationship("default-signing", "authentication", legacy.suite_id, (VerificationMaterial("default", bytes(legacy.public_key)),))
                record = DecodedIdentityRecord(legacy.method_id, legacy.identity_id, b"", (relationship,))
                return IdentityOk("ok", DecodedIdentity(_TOKEN, bytes(packet), record))
            except Exception:
                return IdentityRejected("rejected", _error_info("identity.packet-malformed"))

    async def resolve(self, identity: DecodedIdentity, /, *, timeout: _timedelta = _timedelta(seconds=10)) -> IdentityResult[ResolvedIdentity]:
        from .adapters import AdapterOk, ResolutionEvidence, ResolvedIdentityRecord
        self._open()
        try:
            method = self._methods.get(identity.method_id)
            if method is None:
                if identity.method_id not in ("raw-key", "did:key"):
                    return IdentityRejected("rejected", _error_info("identity.method-unsupported"))
                now = int(_time.time())
                record = ResolvedIdentityRecord(identity._record.method_id, identity._record.identity_id, identity._record.method_material, identity._record.relationships, ResolutionEvidence("packet", now, now + 300, ("self-contained",)))
            else:
                result = await _asyncio.wait_for(method.resolve(identity._record), _seconds(timeout))
                if not isinstance(result, AdapterOk):
                    return _adapter_result(result, "resolve")
                record = result.value
                if record.method_id != identity.method_id or record.identity_id != identity.identity_id:
                    return IdentityIndeterminate("indeterminate", _error_info("identity.resolution-indeterminate"))
            return IdentityOk("ok", ResolvedIdentity(_TOKEN, identity._packet, record))
        except _asyncio.TimeoutError:
            return IdentityIndeterminate("indeterminate", _error_info("identity.resolution-indeterminate"))
        except _asyncio.CancelledError:
            raise
        except Exception:
            return IdentityIndeterminate("indeterminate", _error_info("identity.resolution-indeterminate"))

    async def validate(self, identity: ResolvedIdentity, /, *, timeout: _timedelta = _timedelta(seconds=10)) -> IdentityResult[ValidatedIdentity]:
        from .adapters import AdapterOk
        self._open()
        if identity.expires_at_unix_seconds < int(_time.time()):
            return IdentityRejected("rejected", _error_info("identity.evidence-expired"))
        try:
            method = self._methods.get(identity.method_id)
            if method is None:
                for relationship in identity._record.relationships:
                    for material in relationship.verification_material:
                        _validate_raw_key(identity.method_id, identity.identity_id, relationship.suite_id, material.bytes)
            else:
                result = await _asyncio.wait_for(method.validate(identity._record), _seconds(timeout))
                if not isinstance(result, AdapterOk):
                    return _adapter_result(result, "validate")
            return IdentityOk("ok", ValidatedIdentity(_TOKEN, identity._packet, identity._record))
        except _asyncio.TimeoutError:
            return IdentityIndeterminate("indeterminate", _error_info("identity.validation-indeterminate"))
        except Exception:
            return IdentityRejected("rejected", _error_info("identity.validation-rejected"))

    async def authenticate(self, identity: ValidatedIdentity, /, *, relationship_id: str = "default-signing", message: bytes, signature: bytes, timeout: _timedelta = _timedelta(seconds=10)) -> IdentityResult[AuthenticatedIdentityMessage]:
        from .adapters import AdapterOk
        self._open()
        relationship = next((value for value in identity._record.relationships if value.relationship_id == relationship_id), None)
        if relationship is None:
            return IdentityRejected("rejected", _error_info("identity.relationship-denied"))
        try:
            preimage = _signing_preimage(identity._packet, relationship_id, bytes(message))
            authenticator = self._authenticators.get(relationship.suite_id)
            if authenticator is None:
                if relationship.suite_id != "ed25519-v1" or len(relationship.verification_material) != 1:
                    return IdentityRejected("rejected", _error_info("identity.method-unsupported"))
                _verify_ed25519(relationship.verification_material[0].bytes, preimage, bytes(signature))
            else:
                result = await _asyncio.wait_for(authenticator.verify(relationship=relationship, preimage=preimage, signature=bytes(signature)), _seconds(timeout))
                if not isinstance(result, AdapterOk):
                    return _adapter_result(result, "authenticate")
            return IdentityOk("ok", AuthenticatedIdentityMessage(_TOKEN, identity, relationship_id, bytes(message)))
        except _asyncio.TimeoutError:
            return IdentityIndeterminate("indeterminate", _error_info("identity.authentication-indeterminate"))
        except Exception:
            return IdentityRejected("rejected", _error_info("identity.signature-invalid"))

    async def authenticate_message(self, identity_packet: bytes, /, *, relationship_id: str = "default-signing", message: bytes, signature: bytes, timeout: _timedelta = _timedelta(seconds=10)) -> IdentityResult[AuthenticatedIdentityMessage]:
        decoded = self.decode(identity_packet)
        if not isinstance(decoded, IdentityOk):
            return decoded
        resolved = await self.resolve(decoded.value, timeout=timeout)
        if not isinstance(resolved, IdentityOk):
            return resolved
        validated = await self.validate(resolved.value, timeout=timeout)
        if not isinstance(validated, IdentityOk):
            return validated
        return await self.authenticate(validated.value, relationship_id=relationship_id, message=message, signature=signature, timeout=timeout)


def _adapter_result(value: _Any, stage: str) -> _Union[IdentityRejected, IdentityIndeterminate]:
    if getattr(value, "kind", None) == "rejected":
        return IdentityRejected("rejected", _error_info(f"identity.{stage}-rejected"))
    return IdentityIndeterminate("indeterminate", _error_info(f"identity.{stage}-indeterminate"))


def _create_client(methods: _Tuple[_Any, ...] = (), authenticators: _Tuple[_Any, ...] = (), owns_adapters: bool = False) -> IdentityClient:
    return IdentityClient(_TOKEN, methods, authenticators, owns_adapters)


def _validated(packet: bytes, record: _Any) -> ValidatedIdentity:
    return ValidatedIdentity(_TOKEN, packet, record)


def raw_key_ed25519() -> IdentityClient:
    return _create_client()


async def authenticate_message(identity_packet: bytes, /, *, message: bytes, signature: bytes, client: _Optional[IdentityClient] = None, relationship_id: str = "default-signing", timeout: _timedelta = _timedelta(seconds=10)) -> IdentityResult[AuthenticatedIdentityMessage]:
    if client is not None:
        return await client.authenticate_message(identity_packet, relationship_id=relationship_id, message=message, signature=signature, timeout=timeout)
    owned = raw_key_ed25519()
    async with owned:
        return await owned.authenticate_message(identity_packet, relationship_id=relationship_id, message=message, signature=signature, timeout=timeout)


__all__ = [
    "IdentityOk", "IdentityRejected", "IdentityIndeterminate", "IdentityResult",
    "DecodedIdentity", "ResolvedIdentity", "ValidatedIdentity",
    "AuthenticatedIdentityMessage", "IdentityClient", "raw_key_ed25519",
    "authenticate_message",
]
