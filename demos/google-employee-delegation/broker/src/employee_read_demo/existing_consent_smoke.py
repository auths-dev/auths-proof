"""Operator-pinned, local-only adapter for an existing demo_co employee grant.

This is a partial integration shim. It never imports the grant into Auths's
production vault, creates a browser session, or marks a company export ready.
Only a trusted broker process may construct it; agent and browser processes
must never receive its path or token lease.
"""

from __future__ import annotations

import json
import os
import stat
import time
from dataclasses import dataclass
from datetime import timezone
from pathlib import Path

import requests

from .timestamps import parse_aware_timestamp
from .admission import AdmissionDenied
from .contracts import TaskDescriptor
from .google_oauth import DRIVE_SCOPE, TOKEN_URL
from .token_store import TokenLease, _exchange_refresh

USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
MAX_GRANT_BYTES = 16_384
MAX_USERINFO_BYTES = 16_384
SMOKE_INSTANCE = "live-test-atlas-20261025"
SMOKE_CUSTOMER = "C0218tf2n"
EXISTING_GRANT_SCOPES = frozenset({
    "openid", "https://www.googleapis.com/auth/userinfo.email", DRIVE_SCOPE,
})


class ExistingConsentDenied(PermissionError):
    pass


@dataclass(frozen=True)
class ExistingConsentPins:
    company_id: str
    instance_id: str
    person_id: str
    customer_id: str
    domain: str
    email: str
    subject: str
    client_id: str
    employee_principal: str
    identity_binding_ref: str
    connection_id: str
    connection_generation: int
    task_id: str
    file_ids: tuple[str, ...]

    def validate(self) -> None:
        if (self.company_id != "atlas-studio" or self.instance_id != SMOKE_INSTANCE
                or self.person_id != "person-jules" or self.customer_id != SMOKE_CUSTOMER
                or self.domain != "auths.dev" or self.email != "jules@auths.dev"
                or not all((self.subject, self.client_id, self.employee_principal,
                            self.identity_binding_ref, self.connection_id, self.task_id))
                or type(self.connection_generation) is not int
                or self.connection_generation < 1 or not self.file_ids
                or tuple(sorted(set(self.file_ids))) != self.file_ids):
            raise ExistingConsentDenied("existing-consent pins are incomplete")


def _private_grant(path: Path) -> dict:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > MAX_GRANT_BYTES):
                raise ExistingConsentDenied("existing employee grant is not a private regular file")
            raw = os.read(fd, MAX_GRANT_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > MAX_GRANT_BYTES:
            raise ExistingConsentDenied("existing employee grant exceeds limit")
        grant = json.loads(raw)
    except (OSError, ValueError, UnicodeDecodeError) as error:
        raise ExistingConsentDenied("existing employee grant is unavailable") from error
    if type(grant) is not dict:
        raise ExistingConsentDenied("existing employee grant is malformed")
    return grant


def _userinfo(access_token: str) -> dict:
    session = requests.Session()
    session.trust_env = False
    response = None
    try:
        response = session.get(
            USERINFO_URL, headers={"Authorization": f"Bearer {access_token}",
                                   "Accept-Encoding": "identity"},
            timeout=15, allow_redirects=False, stream=True,
        )
        if (response.status_code != 200
                or "application/json" not in response.headers.get("Content-Type", "")
                or response.headers.get("Content-Encoding", "identity") != "identity"):
            raise ExistingConsentDenied("Google identity check was refused")
        declared = response.headers.get("Content-Length")
        if declared is not None and (not declared.isascii() or not declared.isdecimal()
                                     or int(declared) > MAX_USERINFO_BYTES):
            raise ExistingConsentDenied("Google identity response exceeds limit")
        raw = response.raw.read(MAX_USERINFO_BYTES + 1)
        if len(raw) > MAX_USERINFO_BYTES:
            raise ExistingConsentDenied("Google identity response exceeds limit")
        claims = json.loads(raw)
        if type(claims) is not dict:
            raise ExistingConsentDenied("Google identity response is malformed")
        return claims
    except (requests.RequestException, ValueError, UnicodeDecodeError) as error:
        raise ExistingConsentDenied("Google identity check is unavailable") from error
    finally:
        if response is not None:
            response.close()
        session.close()


class ExistingDemoCoConsentLease:
    """One trusted-broker lease source, pinned to a single Jules task binding."""

    def __init__(self, grant_path: Path, pins: ExistingConsentPins) -> None:
        pins.validate()
        self.grant_path = grant_path
        self.pins = pins

    def lease(self, task: TaskDescriptor, *, now: int | None = None) -> TokenLease:
        task.validate()
        now = int(time.time()) if now is None else now
        p = self.pins
        if (task.company_id != p.company_id or task.instance_id != p.instance_id
                or task.employee_principal != p.employee_principal
                or task.identity_binding_ref != p.identity_binding_ref
                or task.connection_id != p.connection_id
                or task.connection_generation != p.connection_generation
                or task.task_id != p.task_id or task.file_ids != p.file_ids
                or not task.not_before <= now < task.expires_at):
            raise ExistingConsentDenied("task does not match existing-consent pins")
        grant = _private_grant(self.grant_path)
        scopes = grant.get("scopes")
        if (grant.get("client_id") != p.client_id or grant.get("token_uri") != TOKEN_URL
                or grant.get("universe_domain") != "googleapis.com"
                or type(scopes) is not list or any(not isinstance(s, str) for s in scopes)
                or not EXISTING_GRANT_SCOPES.issubset(set(scopes))):
            raise ExistingConsentDenied("existing employee grant does not match OAuth pins")
        token = grant.get("token")
        expiry = grant.get("expiry")
        if not isinstance(token, str) or not token or not isinstance(expiry, str):
            raise ExistingConsentDenied("existing employee grant lacks a usable access token")
        try:
            parsed = parse_aware_timestamp(expiry)
            if parsed.tzinfo is None:
                raise ValueError("timezone is missing")
            expires_at = int(parsed.astimezone(timezone.utc).timestamp())
        except ValueError as error:
            raise ExistingConsentDenied("existing employee grant expiry is malformed") from error
        if expires_at <= now + 30:
            secret, refresh = grant.get("client_secret"), grant.get("refresh_token")
            if not isinstance(secret, str) or not secret or not isinstance(refresh, str) or not refresh:
                raise ExistingConsentDenied("existing employee grant cannot be refreshed")
            try:
                result = _exchange_refresh(p.client_id, secret, refresh)
            except AdmissionDenied as error:
                raise ExistingConsentDenied("existing employee grant refresh failed") from error
            token, seconds = result.get("access_token"), result.get("expires_in")
            returned_scopes = result.get("scope")
            if (not isinstance(token, str) or not token or type(seconds) is not int
                    or not 1 <= seconds <= 86_400 or (returned_scopes is not None
                    and (not isinstance(returned_scopes, str)
                         or not EXISTING_GRANT_SCOPES.issubset(set(returned_scopes.split()))))):
                raise ExistingConsentDenied("existing employee grant refresh is incomplete")
            expires_at = now + seconds
        claims = _userinfo(token)
        if (claims.get("sub") != p.subject or claims.get("email") != p.email
                or claims.get("email_verified") is not True
                or claims.get("hd") != p.domain):
            raise ExistingConsentDenied("Google subject does not match existing-consent pins")
        return TokenLease(token, expires_at)
