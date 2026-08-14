import base64
import json
import os
import subprocess
import tempfile

import pytest

from auths import create_auths
from auths.profiles import (
    github_issue_address,
    opentofu_saved_plan_apply,
    postgresql_bounded_update,
)


@pytest.mark.asyncio
async def test_installed_python_completes_the_same_reference_flow():
    decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    endpoints = os.environ.get(
        "AUTHS_REFERENCE_ENDPOINTS",
        "http://localhost:18081,http://localhost:18082,http://localhost:18083",
    ).split(",")
    assert len(endpoints) == 3
    profiles = (
        ("opentofu", opentofu_saved_plan_apply()),
        ("postgresql", postgresql_bounded_update()),
        ("github", github_issue_address()),
    )
    for name, profile in profiles:
        with tempfile.NamedTemporaryFile() as action:
            action.write(f"exact {name} operation".encode())
            action.flush()
            generated = json.loads(
                subprocess.check_output(
                    ["auths-sandbox-request", action.name], text=True
                )
            )
        human_identity = f"reference-python-{name}-human".encode()
        agent_identity = f"reference-python-{name}-agent".encode()
        human = create_auths(
            endpoint=endpoints[0], identity=human_identity, profile=profile
        )
        authority = await human.create(decode(generated["request"]))
        assert authority.kind == "authority"
        delegator = create_auths(
            endpoint=endpoints[1], identity=human_identity, profile=profile
        )
        delegated = await delegator.delegate(
            authority, agent_identity, decode(generated["attenuation"])
        )
        assert delegated.kind == "authority"
        agent = create_auths(
            endpoint=endpoints[2], identity=agent_identity, profile=profile
        )
        completed = await agent.execute(delegated, decode(generated["action"]))
        assert completed.kind == "completed"
        verifier = create_auths(
            endpoint=endpoints[0], identity=agent_identity, profile=profile
        )
        assert (await verifier.verify(completed.receipt)).kind == "verified"
        assert (await verifier.execute(delegated, decode(generated["action"]))).kind == "denied"

    with tempfile.NamedTemporaryFile() as action:
        action.write(b"AUTHS-SANDBOX-RECOVER issue 104")
        action.flush()
        recovery = json.loads(
            subprocess.check_output(
                ["auths-sandbox-request", action.name], text=True
            )
        )
    recovery_profile = github_issue_address()
    recovery_human = create_auths(
        endpoint=endpoints[0],
        identity=b"reference-python-recovery-human",
        profile=recovery_profile,
    )
    recovery_delegator = create_auths(
        endpoint=endpoints[1],
        identity=b"reference-python-recovery-human",
        profile=recovery_profile,
    )
    recovery_authority = await recovery_human.create(decode(recovery["request"]))
    recovery_delegated = await recovery_delegator.delegate(
        recovery_authority,
        b"reference-python-recovery-agent",
        decode(recovery["attenuation"]),
    )
    recovery_agent = create_auths(
        endpoint=endpoints[2],
        identity=b"reference-python-recovery-agent",
        profile=recovery_profile,
    )
    unknown = await recovery_agent.execute(
        recovery_delegated, decode(recovery["action"])
    )
    assert unknown.kind == "recoverable"
    recovery_verifier = create_auths(
        endpoint=endpoints[0],
        identity=b"reference-python-recovery-agent",
        profile=recovery_profile,
    )
    resumed = await recovery_verifier.resume(unknown.reference)
    assert resumed.kind == "completed"
