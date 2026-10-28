"""Subject-checked Jules Drive read-only lease for a task exclusion probe.

The demo_co grant stays in operator custody. This lease is only an input to
the gateway's read connection; the native task still decides which resources
an agent may request.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import timezone
from pathlib import Path

from .timestamps import parse_aware_timestamp
from .admission import AdmissionDenied
from .demo_co_contract import ContractRejected
from .existing_consent_smoke import (
    EXISTING_GRANT_SCOPES, ExistingConsentDenied, _private_grant, _userinfo,
)
from .google_oauth import TOKEN_URL
from .project_b_grants_handoff import ProjectBGrantPins, validate_project_b_grants
from .token_store import TokenLease, _exchange_refresh


class ReadOnlyCredentialDenied(PermissionError):
    """The pinned read-only grant or its live Jules identity was refused."""


@dataclass(frozen=True)
class ReadOnlyCredentialPins:
    project_b: ProjectBGrantPins
    client_id: str
    primary_domain: str
    connection_id: str
    connection_generation: int

    def validate(self) -> None:
        try:
            self.project_b.validate()
        except ContractRejected as error:
            raise ReadOnlyCredentialDenied(
                "Project B grant pins are invalid") from error
        if (not all((self.client_id, self.primary_domain, self.connection_id))
                or type(self.connection_generation) is not int
                or self.connection_generation < 1):
            raise ReadOnlyCredentialDenied("read-only connection pins are incomplete")


def lease_jules_readonly_token(
    evidence_path: Path, grant_path: Path, pins: ReadOnlyCredentialPins,
    *, connection_id: str, connection_generation: int,
    now: int | None = None,
) -> TokenLease:
    """Check producer access, exact OAuth scope, refresh and live UserInfo."""
    pins.validate()
    if ((connection_id, connection_generation)
            != (pins.connection_id, pins.connection_generation)):
        raise ReadOnlyCredentialDenied("read-only connection generation changed")
    now = int(time.time()) if now is None else now
    try:
        validate_project_b_grants(evidence_path, pins.project_b, now=now)
        grant = _private_grant(grant_path)
    except (ContractRejected, ExistingConsentDenied, OSError, ValueError) as error:
        raise ReadOnlyCredentialDenied("pinned Project B evidence or grant is unavailable") from error
    scopes = grant.get("scopes")
    if (grant.get("client_id") != pins.client_id
            or grant.get("token_uri") != TOKEN_URL
            or grant.get("universe_domain") != "googleapis.com"
            or type(scopes) is not list or len(scopes) != len(EXISTING_GRANT_SCOPES)
            or any(type(scope) is not str for scope in scopes)
            or set(scopes) != EXISTING_GRANT_SCOPES):
        raise ReadOnlyCredentialDenied("read-only grant client or scopes changed")
    token, expiry = grant.get("token"), grant.get("expiry")
    if type(token) is not str or not token or type(expiry) is not str:
        raise ReadOnlyCredentialDenied("read-only grant lacks usable token metadata")
    try:
        parsed = parse_aware_timestamp(expiry)
        if parsed.tzinfo is None:
            raise ValueError("timezone is missing")
        expires_at = int(parsed.astimezone(timezone.utc).timestamp())
    except ValueError as error:
        raise ReadOnlyCredentialDenied("read-only grant expiry is malformed") from error
    if expires_at <= now + 90:
        secret, refresh = grant.get("client_secret"), grant.get("refresh_token")
        if type(secret) is not str or not secret or type(refresh) is not str or not refresh:
            raise ReadOnlyCredentialDenied("read-only grant cannot refresh")
        try:
            result = _exchange_refresh(pins.client_id, secret, refresh)
        except AdmissionDenied as error:
            raise ReadOnlyCredentialDenied("read-only grant refresh failed") from error
        token, seconds = result.get("access_token"), result.get("expires_in")
        returned_scopes = result.get("scope")
        if (type(token) is not str or not token or type(seconds) is not int
                or not 90 < seconds <= 86_400
                or (returned_scopes is not None
                    and (type(returned_scopes) is not str
                         or set(returned_scopes.split()) != EXISTING_GRANT_SCOPES))):
            raise ReadOnlyCredentialDenied("read-only refresh was incomplete")
        expires_at = now + seconds
    try:
        claims = _userinfo(token)
    except ExistingConsentDenied as error:
        raise ReadOnlyCredentialDenied("read-only grant identity check failed") from error
    if (claims.get("sub") != pins.project_b.jules_subject
            or claims.get("email") != "jules@auths.dev"
            or claims.get("email_verified") is not True
            or claims.get("hd") != pins.primary_domain):
        raise ReadOnlyCredentialDenied("read-only grant subject changed")
    return TokenLease(token, expires_at)
