"""Development-only bridge from the pinned Jules write grant to gateway custody.

The demo_co producer owns consent and its private grant. This Auths shim
validates that handoff, leases a subject-checked access token in broker memory,
and pipes it directly to the gateway operator's install command. The agent,
task card, command arguments and logs never receive token material. An
installed bearer is short lived; this is not production OAuth refresh custody.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .google_write_credential import WriteCredentialPins, lease_jules_write_token


MIN_REMAINING_SECONDS = 600
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class GatewayWriteCredentialDenied(PermissionError):
    """The pinned bearer could not be installed without exposing it."""


@dataclass(frozen=True)
class InstalledWriteLease:
    connection_subject: str
    connection_generation: int
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
    return InstalledWriteLease(
        pins.producer.jules_subject,
        pins.connection_generation,
        lease.expires_at,
    )
