"""Installed-package GitHub agent launch path."""

from __future__ import annotations

import asyncio
import os

from auths.service import (
    GitHubAgentTask,
    GitHubCandidateFile,
    create_github_agent_client,
)


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


async def main() -> None:
    client = create_github_agent_client(
        endpoint=required("AUTHS_GITHUB_AGENT_ENDPOINT")
    )
    boundary = await client.boundary()
    session = await client.delegate(
        GitHubAgentTask(
            repository=boundary.repository,
            issue_number=boundary.issue_number,
            base_ref=boundary.base_ref,
            base_revision=boundary.base_revision,
            allowed_paths=boundary.allowed_paths,
            protected_paths=boundary.protected_paths,
            expires_in_seconds=boundary.maximum_expiry_seconds,
            branch_budget=1,
            draft_pull_request_budget=1,
            agent_label=os.environ.get("AUTHS_AGENT_LABEL", "launch-agent"),
        )
    )
    fixture = os.environ.get("AUTHS_GITHUB_FIXTURE")
    if fixture:
        inspection = await client.inspect_fixture(session, fixture)  # type: ignore[arg-type]
    else:
        inspection = await client.inspect_candidate(
            session,
            GitHubCandidateFile(
                path=required("AUTHS_GITHUB_CANDIDATE_BUNDLE"),
                base_revision=boundary.base_revision,
                candidate_revision=required("AUTHS_GITHUB_CANDIDATE_REVISION"),
            ),
        )
    print("candidate", inspection)
    if fixture:
        denied = await client.execute(session)
        assert denied.kind == "denied"
        assert denied.credential_requests == 0
        assert denied.mutations == 0
        print("denied safely", denied.code)
        return
    if os.environ.get("AUTHS_GITHUB_LIVE") != "1":
        raise RuntimeError(
            "set AUTHS_GITHUB_LIVE=1 to permit the isolated draft-PR effect"
        )
    assert inspection.kind == "inspected"
    outcome = await client.execute(session)
    if outcome.next == "reconcile":
        outcome = await client.reconcile(session)
    assert outcome.kind in ("completed", "reconciled")
    verified = await client.verify_receipts(session)
    assert verified.kind == "verified"
    replay = await client.replay(session)
    assert replay.kind == "replayed"
    assert replay.credential_requests == 0
    assert replay.mutations == 0
    print("completed", outcome.pull_request_url, verified)


asyncio.run(main())
