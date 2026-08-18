from __future__ import annotations

import asyncio

from auths.service import GitHubAgentTask, create_github_agent_client


def test_typed_github_task_projects_to_the_closed_launch_api() -> None:
    responses = [
        {
            "schema": "auths-github-agent/v1",
            "repository": "auths-dev/example",
            "issue_number": 123,
            "base_ref": "main",
            "base_revision": "a" * 40,
            "allowed_paths": ["src/**", "tests/**"],
            "denied_paths": [".github/**"],
            "budgets": {"branches": 1, "draft_pull_requests": 1},
            "expiry": {"minimum_seconds": 60, "maximum_seconds": 900},
            "agent_credential_present": False,
        },
        {
            "schema": "auths-github-agent/v1",
            "session_id": "1" * 32,
            "workflow_id": "demo-" + "1" * 32,
            "expires_at": 1_000,
            "target_ref": "auths/issue-123-abcdef123456",
            "agent_principal": "urn:auths:raw-key:agent",
            "required_configuration": "2" * 64,
            "executed_configuration": "2" * 64,
        },
        {
            "schema": "auths-github-agent/v1",
            "candidate": {
                "status": "denied",
                "changed_paths": [],
                "direct_push": {"result": "not-attempted"},
                "preview": {
                    "code": "path-explicitly-denied",
                    "credential_would_be_requested": False,
                },
            },
        },
        {
            "schema": "auths-github-agent/v1",
            "decision": {"class": "denied", "code": "path-explicitly-denied"},
            "execution": {"branch": "not-attempted", "pull_request": "not-attempted"},
            "credential_requests": 0,
            "mutations": 0,
        },
    ]
    calls: list[tuple[str, object]] = []
    client = create_github_agent_client(endpoint="https://operator.example")

    async def fake_call(path: str, body: object = None) -> dict[str, object]:
        calls.append((path, body))
        return responses.pop(0)

    client._call = fake_call  # type: ignore[method-assign]

    async def scenario() -> None:
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
                agent_label="review-agent",
            )
        )
        inspection = await client.inspect_fixture(session, "prohibited-path")
        denied = await client.execute(session)
        assert inspection.kind == "denied"
        assert inspection.credential_would_be_requested is False
        assert denied.kind == "denied"
        assert denied.credential_requests == 0
        assert denied.mutations == 0

    asyncio.run(scenario())
    assert calls[1][1] == {
        "repository": "auths-dev/example",
        "issueNumber": 123,
        "baseRef": "main",
        "baseRevision": "a" * 40,
        "allowedPaths": ["src/**", "tests/**"],
        "protectedPaths": [".github/**"],
        "expiresInSeconds": 900,
        "branchBudget": 1,
        "draftPullRequestBudget": 1,
        "agentLabel": "review-agent",
    }


def test_lost_execute_response_requires_reconciliation() -> None:
    client = create_github_agent_client(endpoint="https://operator.example")
    session_response = {
        "schema": "auths-github-agent/v1",
        "session_id": "1" * 32,
        "workflow_id": "demo-" + "1" * 32,
        "expires_at": 1_000,
        "target_ref": "auths/issue-123-abcdef123456",
        "agent_principal": "urn:auths:raw-key:agent",
        "required_configuration": "2" * 64,
        "executed_configuration": "2" * 64,
    }
    calls = 0

    async def fake_call(_path: str, _body: object = None) -> dict[str, object]:
        nonlocal calls
        calls += 1
        if calls > 1:
            raise OSError("connection lost after request left the process")
        return session_response

    client._call = fake_call  # type: ignore[method-assign]

    async def scenario() -> None:
        session = await client.delegate(
            GitHubAgentTask(
                repository="auths-dev/example",
                issue_number=123,
                base_ref="main",
                base_revision="a" * 40,
                allowed_paths=["src/**"],
                protected_paths=[".github/**"],
                expires_in_seconds=900,
                branch_budget=1,
                draft_pull_request_budget=1,
                agent_label="review-agent",
            )
        )
        outcome = await client.execute(session)
        assert outcome.kind == "indeterminate"
        assert outcome.code == "transport-uncertain"
        assert outcome.credential_requests == "unknown"
        assert outcome.mutations == "unknown"
        assert outcome.next == "reconcile"

    asyncio.run(scenario())
