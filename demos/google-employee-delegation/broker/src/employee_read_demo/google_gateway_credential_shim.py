"""Development-only bridge from the pinned Jules grant to gateway custody.

The demo_co producer owns consent and its private grant. This Auths shim
validates that handoff, leases a subject-checked access token in broker memory,
and pipes it directly to the gateway operator's install command. The agent,
task card, command arguments and logs never receive token material. An
installed bearer is short lived; this is not production OAuth refresh custody.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .google_write_credential import (
    WriteCredentialDenied, WriteCredentialPins, lease_jules_write_token,
)


MIN_REMAINING_SECONDS = 600
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_CONNECTION_ID = re.compile(r"conn_[A-Za-z0-9_-]{22}\Z")


class GatewayWriteCredentialDenied(PermissionError):
    """The pinned bearer could not be installed without exposing it."""


class GatewayReadCredentialDenied(PermissionError):
    """The checked Jules bearer could not be bound to a read connection."""


@dataclass(frozen=True)
class InstalledWriteLease:
    connection_id: str
    connection_subject: str
    connection_generation: int
    expires_at: int


@dataclass(frozen=True)
class InstalledReadLease:
    connection_id: str
    connection_subject: str
    connection_generation: int
    recipe_digest: str
    expires_at: int


def install_jules_write_lease(
    *,
    evidence_path: Path,
    grant_path: Path,
    pins: WriteCredentialPins,
    gateway_binary: Path,
    state_dir: Path,
    recipe_path: Path,
    profile_lock_path: Path,
    trusted_context_path: Path,
    recipe_digest: str,
    alias: str,
    now: int | None = None,
) -> InstalledWriteLease:
    """Install one checked Jules bearer in a new development gateway state.

    The caller supplies operator-reviewed recipe/trust paths. The gateway
    independently checks their digest and refuses existing installations.
    Google UserInfo and demo_co evidence are checked before this process
    opens gateway custody; the gateway connection account label is Jules's
    stable Google `sub`, never her email.
    """
    now = int(time.time()) if now is None else now
    paths = (gateway_binary, state_dir, recipe_path, profile_lock_path,
             trusted_context_path)
    if (not all(path.is_absolute() for path in paths)
            or not _DIGEST.fullmatch(recipe_digest)
            or not alias or len(alias) > 128
            or not all(char.isalnum() or char in "-_" for char in alias)):
        raise GatewayWriteCredentialDenied("operator gateway inputs are incomplete")
    lease = lease_jules_write_token(
        evidence_path, grant_path, pins,
        connection_id=pins.connection_id,
        connection_generation=pins.connection_generation,
        now=now,
    )
    if lease.expires_at <= now + MIN_REMAINING_SECONDS:
        raise GatewayWriteCredentialDenied("Jules bearer expires too soon")
    command = [
        str(gateway_binary), "install",
        "--state-dir", str(state_dir),
        "--recipe", str(recipe_path),
        "--profile-lock", str(profile_lock_path),
        "--trusted-context", str(trusted_context_path),
        "--approve-digest", recipe_digest,
        "--provider", "google",
        "--alias", alias,
        "--account-label", pins.producer.jules_subject,
        "--credential-stdin",
        "--connection-json",
        "--deployment", "development",
    ]
    try:
        result = subprocess.run(
            command,
            input=lease.access_token.encode("ascii"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": os.environ.get("PATH", "")},
            timeout=90,
            check=False,
        )
    except (OSError, UnicodeEncodeError, subprocess.TimeoutExpired) as error:
        raise GatewayWriteCredentialDenied("gateway install did not complete") from error
    if result.returncode != 0:
        # Do not surface child output: an unexpected diagnostic could include
        # the bearer even though the gateway's normal errors are redacted.
        raise GatewayWriteCredentialDenied("gateway refused the checked bearer")
    try:
        if len(result.stdout) > 4096:
            raise ValueError("gateway result exceeds bounds")
        installed = json.loads(result.stdout)
        if (type(installed) is not dict
                or set(installed) != {"schema", "connection_id",
                                      "credential_generation", "recipe_digest", "joined"}
                or installed["schema"] != "auths.gateway-install-result/1"
                or type(installed["connection_id"]) is not str
                or _CONNECTION_ID.fullmatch(installed["connection_id"]) is None
                or type(installed["credential_generation"]) is not int
                or installed["credential_generation"] != pins.connection_generation
                or installed["recipe_digest"] != recipe_digest
                or installed["joined"] is not False):
            raise ValueError("gateway result disagrees with installation")
    except (UnicodeDecodeError, ValueError) as error:
        raise GatewayWriteCredentialDenied(
            "gateway install result unavailable; inspect state before retry",
        ) from error
    return InstalledWriteLease(
        installed["connection_id"], pins.producer.jules_subject,
        installed["credential_generation"], lease.expires_at,
    )


def install_jules_read_lease(
    *,
    evidence_path: Path,
    grant_path: Path,
    write_credential_pins: WriteCredentialPins,
    gateway_binary: Path,
    state_dir: Path,
    read_recipe_path: Path,
    read_profile_lock_path: Path,
    read_recipe_digest: str,
    read_alias: str,
    now: int | None = None,
) -> InstalledReadLease:
    """Install a GET-only Auths connection from the checked Jules grant.

    The existing write connection pins identify the broker-held grant. The
    gateway generates a *different* read connection ID with generation one;
    that ID must be pinned in the later signed task. Neither the refresh token
    nor access token enters the agent package or command arguments.
    """
    now = int(time.time()) if now is None else now
    paths = (gateway_binary, state_dir, read_recipe_path, read_profile_lock_path)
    if (not all(path.is_absolute() for path in paths)
            or not _DIGEST.fullmatch(read_recipe_digest)
            or not read_alias or len(read_alias) > 128
            or not all(char.isalnum() or char in "-_" for char in read_alias)):
        raise GatewayReadCredentialDenied("operator read inputs are incomplete")
    try:
        lease = lease_jules_write_token(
            evidence_path, grant_path, write_credential_pins,
            connection_id=write_credential_pins.connection_id,
            connection_generation=write_credential_pins.connection_generation,
            now=now,
        )
    except WriteCredentialDenied as error:
        raise GatewayReadCredentialDenied("Jules subject-checked grant refused") from error
    if lease.expires_at <= now + MIN_REMAINING_SECONDS:
        raise GatewayReadCredentialDenied("Jules bearer expires too soon")
    command = [
        str(gateway_binary), "task-read-connect",
        "--state-dir", str(state_dir),
        "--recipe", str(read_recipe_path),
        "--profile-lock", str(read_profile_lock_path),
        "--approve-digest", read_recipe_digest,
        "--provider", "google",
        "--alias", read_alias,
        "--account-subject", write_credential_pins.producer.jules_subject,
        "--credential-stdin",
    ]
    try:
        result = subprocess.run(
            command,
            input=lease.access_token.encode("ascii"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": os.environ.get("PATH", "")},
            timeout=90,
            check=False,
        )
    except (OSError, UnicodeEncodeError, subprocess.TimeoutExpired) as error:
        raise GatewayReadCredentialDenied("gateway read install did not complete") from error
    if result.returncode != 0:
        raise GatewayReadCredentialDenied("gateway refused the checked read bearer")
    try:
        if len(result.stdout) > 4096:
            raise ValueError("gateway result exceeds bounds")
        installed = json.loads(result.stdout)
        if (type(installed) is not dict
                or set(installed) != {"outcome", "connection_id",
                                      "connection_generation", "recipe_digest"}
                or installed["outcome"] != "read-connection-installed"
                or type(installed["connection_id"]) is not str
                or _CONNECTION_ID.fullmatch(installed["connection_id"]) is None
                or type(installed["connection_generation"]) is not int
                or installed["connection_generation"] != 1
                or installed["recipe_digest"] != read_recipe_digest):
            raise ValueError("gateway result disagrees with read installation")
    except (UnicodeDecodeError, ValueError) as error:
        raise GatewayReadCredentialDenied(
            "gateway read install result unavailable; inspect state before retry",
        ) from error
    return InstalledReadLease(
        installed["connection_id"], write_credential_pins.producer.jules_subject,
        installed["connection_generation"], read_recipe_digest, lease.expires_at,
    )
