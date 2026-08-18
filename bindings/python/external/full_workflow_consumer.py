from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from auths.integrations import development
from auths.profiles import mcp
from auths.service import GitHubAgentTask, create_github_agent_client
from auths.verify import verify_receipt


async def run(_: Path) -> None:
    github = create_github_agent_client(endpoint="https://operator.example")
    responses = [
        {
            "schema": "auths-github-agent/v1",
            "repository": "auths-dev/example",
            "issue_number": 7,
            "base_ref": "main",
            "base_revision": "a" * 40,
            "allowed_paths": ["src/**"],
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
            "target_ref": "auths/issue-7-111111111111",
            "agent_principal": "urn:auths:raw-key:agent",
            "required_configuration": "2" * 64,
            "executed_configuration": "2" * 64,
        },
        {
            "schema": "auths-github-agent/v1",
            "candidate": {
                "status": "inspected",
                "candidate_revision": "b" * 40,
                "changed_paths": [{"path": "src/fix.py"}],
                "direct_push": {"result": "refused-without-credential"},
                "preview": {
                    "code": "authorized",
                    "credential_would_be_requested": True,
                },
            },
        },
        {
            "schema": "auths-github-agent/v1",
            "decision": {"class": "authorized", "code": "authorized"},
            "execution": {
                "branch_ref": "auths/issue-7-111111111111",
                "pull_request_number": 8,
                "pull_request_url": "https://github.com/auths-dev/example/pull/8",
            },
            "credential_requests": 2,
            "mutations": 2,
        },
        {
            "schema": "auths-github-agent/v1",
            "workflow_id": "demo-" + "1" * 32,
            "receipts": [{"type": "decision"}, {"type": "execution"}],
        },
        {
            "schema": "auths-github-agent/v1",
            "decision": {"class": "authorized", "code": "action-replay"},
            "execution": {"replay": "original-receipt-returned"},
            "credential_requests": 0,
            "mutations": 0,
        },
    ]

    async def github_boundary(_path: str, _body=None):
        if not responses:
            raise RuntimeError("installed GitHub client made an extra call")
        return responses.pop(0)

    github._call = github_boundary  # type: ignore[method-assign]
    boundary = await github.boundary()
    if boundary.branch_budget != 1 or boundary.agent_credential_present is not False:
        raise RuntimeError("installed GitHub boundary widened")
    github_session = await github.delegate(
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
            agent_label="wheel-consumer",
        )
    )
    inspected = await github.inspect_fixture(github_session, "exact")
    completed = await github.execute(github_session)
    verified = await github.verify_receipts(github_session)
    replayed = await github.replay(github_session)
    if (
        inspected.kind != "inspected"
        or completed.kind != "completed"
        or verified.kind != "verified"
    ):
        raise RuntimeError("installed GitHub journey did not complete")
    if (
        replayed.kind != "replayed"
        or replayed.credential_requests != 0
        or replayed.mutations != 0
    ):
        raise RuntimeError("installed GitHub replay was not bounded")

    calls = 0

    async def publish_report(arguments, context):
        nonlocal calls
        calls += 1
        if context.tool != "publish_report":
            raise RuntimeError("profile context changed the tool")
        return {"published": arguments["report"]}

    provider = mcp.development_provider(tools={"publish_report": publish_report})
    async with development.create_auths(
        authority=mcp.allow_tools(["publish_report"])
    ) as auths:
        result = await auths.execute(
            action=mcp.call_tool(name="publish_report", arguments={"report": "weekly"}),
            provider=provider,
            request_id="external-consumer",
        )
        if result.kind != "completed" or calls != 1:
            raise RuntimeError("installed wheel did not execute the exact action")
        verify_receipt(result.receipt)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: full_workflow_consumer.py <binding-vectors>")
    asyncio.run(run(Path(sys.argv[1]).resolve()))
