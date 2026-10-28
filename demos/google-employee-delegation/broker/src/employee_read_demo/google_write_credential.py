"""Broker-side Jules write-token lease for an exact pinned producer generation.

Only trusted Auths custody code may call this after native task admission.
This module never sends a provider write or passes a refresh token to the
agent or gateway application socket. Its returned access token is secret.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import timezone
from pathlib import Path

from .timestamps import parse_aware_timestamp
from .admission import AdmissionDenied
from .existing_consent_smoke import _private_grant, _userinfo
from .google_oauth import TOKEN_URL
from .token_store import TokenLease, _exchange_refresh
from .write_handoff import WRITE_SCOPES, WriteHandoffPins, validate_write_handoff


class WriteCredentialDenied(PermissionError):
    """The producer generation, Google grant or Jules subject was refused."""


@dataclass(frozen=True)
class WriteCredentialPins:
    producer: WriteHandoffPins
    client_id: str
    primary_domain: str
    connection_id: str
    connection_generation: int

    def validate(self) -> None:
        self.producer.validate()
        if (not all((self.client_id, self.primary_domain, self.connection_id))
                or type(self.connection_generation) is not int
                or self.connection_generation < 1):
            raise WriteCredentialDenied("write connection pins are incomplete")


def lease_jules_write_token(evidence_path: Path, grant_path: Path,
                            pins: WriteCredentialPins, *, connection_id: str,
                            connection_generation: int,
                            now: int | None = None) -> TokenLease:
    """Return one subject-checked bearer to the trusted credential custodian.

    The caller must enforce task admission, connection generation, lease-time
    record reload and no-write-before-claim. A token lease alone grants no
    Auths authority. The same Desktop OAuth client is required for the
    Picker-granted folder and working Doc.
    """
    pins.validate()
    if ((connection_id, connection_generation)
            != (pins.connection_id, pins.connection_generation)):
        raise WriteCredentialDenied("write task connection generation changed")
    try:
        validate_write_handoff(evidence_path, pins.producer)
        grant = _private_grant(grant_path)
    except (OSError, ValueError, PermissionError) as error:
        raise WriteCredentialDenied("pinned write evidence or private grant is unavailable") from error
    scopes = grant.get("scopes")
    if (grant.get("client_id") != pins.client_id
            or grant.get("token_uri") != TOKEN_URL
            or grant.get("universe_domain") != "googleapis.com"
            or type(scopes) is not list or len(scopes) != 3
            or any(type(scope) is not str for scope in scopes)
            or set(scopes) != WRITE_SCOPES):
        raise WriteCredentialDenied("write grant client or scopes disagree with pins")
    token, expiry = grant.get("token"), grant.get("expiry")
    if type(token) is not str or not token or type(expiry) is not str:
        raise WriteCredentialDenied("write grant lacks an access token or expiry")
    now = int(time.time()) if now is None else now
    try:
        parsed = parse_aware_timestamp(expiry)
        if parsed.tzinfo is None:
            raise ValueError("timezone is missing")
        expires_at = int(parsed.astimezone(timezone.utc).timestamp())
    except ValueError as error:
        raise WriteCredentialDenied("write grant expiry is malformed") from error
    if expires_at <= now + 90:
        secret, refresh = grant.get("client_secret"), grant.get("refresh_token")
        if type(secret) is not str or not secret or type(refresh) is not str or not refresh:
            raise WriteCredentialDenied("write grant cannot be refreshed")
        try:
            result = _exchange_refresh(pins.client_id, secret, refresh)
        except AdmissionDenied as error:
            raise WriteCredentialDenied("write grant refresh failed") from error
        token, seconds = result.get("access_token"), result.get("expires_in")
        returned_scopes = result.get("scope")
        if (type(token) is not str or not token or type(seconds) is not int
                or not 90 < seconds <= 86_400
                or (returned_scopes is not None
                    and (type(returned_scopes) is not str
                         or set(returned_scopes.split()) != WRITE_SCOPES))):
            raise WriteCredentialDenied("write grant refresh is incomplete")
        expires_at = now + seconds
    try:
        claims = _userinfo(token)
    except PermissionError as error:
        raise WriteCredentialDenied("write grant subject check failed") from error
    if (claims.get("sub") != pins.producer.jules_subject
            or claims.get("email") != pins.producer.jules_email
            or claims.get("email_verified") is not True
            or claims.get("hd") != pins.primary_domain):
        raise WriteCredentialDenied("write grant subject disagrees with pins")
    return TokenLease(token, expires_at)
