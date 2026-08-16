"""Exercises the built Python wheel against the reference stack.

The previous version called ``auths-sandbox-request`` and asserted
``create`` returned an authority. Both are gone, and deliberately: the node
answers ``create`` and ``delegate`` with ``core.unauthenticated-principal``
because ``ProductionRequest.identity`` is unauthenticated bytes and there is no
client authentication at that call site to require instead. That test asserted
the fail-open the kernel rebuild removed.

Authority originates from a trust anchor's signature and arrives inside the
proof. ``auths-local-authority`` authors one offline against the same anchor the
trusted context carries; the client imports it and calls ``execute``, the only
verb the node answers.
"""

import base64
import json
import os
import subprocess
import tempfile

import pytest

from auths.profiles import (
    github_issue_address,
    opentofu_saved_plan_apply,
    postgresql_bounded_update,
)
from auths.service import create_service_client, import_authority


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _author(profile_id: str, body: bytes, agent: str) -> dict:
    with tempfile.NamedTemporaryFile() as action:
        action.write(body)
        action.flush()
        return json.loads(
            subprocess.check_output(
                ["auths-local-authority", profile_id, action.name, agent],
                text=True,
            )
        )


@pytest.mark.asyncio
async def test_installed_python_completes_the_same_reference_flow():
    endpoint = os.environ.get("AUTHS_REFERENCE_ENDPOINT", "https://localhost:8443")
    profiles = (
        ("opentofu", opentofu_saved_plan_apply()),
        ("postgresql", postgresql_bounded_update()),
        ("github", github_issue_address()),
    )
    for name, profile in profiles:
        authored = _author(
            profile.id,
            f"exact {name} operation".encode(),
            f"reference-python-{name}-agent",
        )

        authority = import_authority(_decode(authored["proof"]))
        assert authority.kind == "authority"

        client = create_service_client(endpoint=endpoint, profile=profile)
        completed = await client.execute(authority, _decode(authored["action"]))
        assert completed.kind == "completed"

        verified = await client.verify(completed.receipt)
        assert verified.kind == "verified"

        # The claim is keyed on (proof digest, action digest) and allows one
        # effect, so replaying the identical pair is refused, not repeated.
        replayed = await client.execute(authority, _decode(authored["action"]))
        assert replayed.kind == "denied"


@pytest.mark.asyncio
async def test_installed_python_resolves_an_unknown_effect():
    """A recoverable body leaves the outcome unknown; resuming resolves it.

    ``Indeterminate`` exists precisely so a signed receipt can say the effect
    state is unknown rather than assert a failure that may have applied.
    """

    endpoint = os.environ.get("AUTHS_REFERENCE_ENDPOINT", "https://localhost:8443")
    profile = github_issue_address()
    authored = _author(
        profile.id,
        b"AUTHS-SANDBOX-RECOVER issue 104",
        "reference-python-recovery-agent",
    )

    client = create_service_client(endpoint=endpoint, profile=profile)
    unknown = await client.execute(
        import_authority(_decode(authored["proof"])),
        _decode(authored["action"]),
    )
    assert unknown.kind == "recoverable"

    resumed = await client.resume(unknown.reference)
    assert resumed.kind == "completed"
