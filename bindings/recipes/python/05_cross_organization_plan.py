from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from auths import (
    Approval,
    ApprovalRequest,
    ApprovalResponse,
    decode_execution_reference,
    decode_receipt,
    encode_execution_reference,
    encode_receipt,
    verify_receipt,
)
from auths.approvals import threshold_approval
from auths.integrations import development
from auths.profiles import mcp
from auths.profiles.mcp import McpHandlerOutcome


class OrganizationApproval:
    def __init__(self, organization: str) -> None:
        self.organization = organization

    async def approve(self, request: ApprovalRequest) -> ApprovalResponse:
        return ApprovalResponse(
            request.request_id,
            request.transaction_digest,
            request.policy,
            "approved",
        )


def plan_approval():
    providers = (OrganizationApproval("company-a"), OrganizationApproval("company-b"))
    return Approval.plan_once(
        "approval.cross-company-plan",
        threshold_approval(providers, threshold=2),
        max_uses=2,
        requirements=("company-a", "company-b"),
    )


async def phase_one(root: Path) -> None:
    async def quarantine_service(_arguments, _context):
        return {"quarantined": True}

    async def rotate_token(_arguments, _context):
        (root / "provider-applied").write_text("applied", encoding="utf-8")
        return McpHandlerOutcome("possible", cause="unknown")

    provider = mcp.development_provider(
        tools={
            "quarantine_service": quarantine_service,
            "rotate_token": rotate_token,
        }
    )
    async with development.create_recoverable_auths(
        directory=root,
        authority=mcp.allow_tools(["quarantine_service", "rotate_token"]),
        approval=plan_approval(),
    ) as auths:
        plan = mcp.plan(
            (
                mcp.call_tool(
                    name="quarantine_service",
                    arguments={"region": "eu-west-2"},
                ),
                mcp.call_tool(name="rotate_token", arguments={"region": "eu-west-2"}),
            )
        )
        result = await auths.execute(
            plan=plan, provider=provider, request_id="incident-plan"
        )
        if (
            result.kind != "recoverable"
            or result.reference is None
            or len(result.completed_receipts) != 1
        ):
            raise RuntimeError("ordered plan did not stop with one completed member")
        (root / "reference.bin").write_bytes(
            encode_execution_reference(result.reference)
        )
        (root / "python-receipt.json").write_bytes(
            encode_receipt(result.completed_receipts[0])
        )


async def phase_two(root: Path) -> None:
    entries = 0

    async def no_reentry(_arguments, _context):
        nonlocal entries
        entries += 1
        raise RuntimeError("unexpected provider re-entry")

    async def reconcile(_execution_id, _service):
        if (root / "provider-applied").exists():
            return McpHandlerOutcome("applied", result={"rotated": True})
        return McpHandlerOutcome("possible", cause="unknown")

    provider = mcp.development_provider(
        tools={
            "quarantine_service": no_reentry,
            "rotate_token": no_reentry,
        },
        reconcile=reconcile,
    )
    async with development.create_recoverable_auths(
        directory=root,
        authority=mcp.allow_tools(["quarantine_service", "rotate_token"]),
        approval=plan_approval(),
    ) as auths:
        result = await auths.resume(
            reference=decode_execution_reference((root / "reference.bin").read_bytes()),
            provider=provider,
        )
        if result.kind != "completed" or entries != 0:
            raise RuntimeError("recovery re-entered the provider")
        verify_receipt(result.receipt)
        (root / "python-recovered-receipt.json").write_bytes(
            encode_receipt(result.receipt)
        )


def run_child(mode: str, root: Path) -> None:
    subprocess.run([sys.executable, __file__, mode, str(root)], check=True)


async def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else None
    path = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    if mode == "verify" and path is not None:
        verify_receipt(decode_receipt(path.read_bytes()))
        print(json.dumps({"outcome": "verified-portable-receipt"}))
        return
    if mode == "phase-one" and path is not None:
        await phase_one(path)
        return
    if mode == "phase-two" and path is not None:
        await phase_two(path)
        return
    configured = os.environ.get("AUTHS_RECIPE_OUTPUT")
    if configured is not None:
        root = Path(configured)
        root.mkdir(parents=True, exist_ok=True)
        run_child("phase-one", root)
        run_child("phase-two", root)
    else:
        with tempfile.TemporaryDirectory(prefix="auths-recipe-five-py-") as directory:
            root = Path(directory)
            run_child("phase-one", root)
            run_child("phase-two", root)
    print(
        json.dumps(
            {
                "recipe": "05-cross-organization-plan",
                "outcome": "completed-after-restart",
                "duplicateEntries": 0,
            }
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
