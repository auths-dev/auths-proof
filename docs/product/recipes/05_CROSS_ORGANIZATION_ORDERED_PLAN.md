# 05 — Run a cross-organization ordered plan

## Outcome

Bind two independent approvals to one exact plan, stop on an ambiguous effect, restart, reconcile, and verify receipts across languages.

## Before you start

Use a supported Node.js or CPython runtime and install the single Auths package. The executable source below is run against the packed npm artifact and wheel in CI.

## TypeScript

Source: `typescript/05-cross-organization-plan.ts`

```typescript
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  approvalPolicy,
  decodeExecutionReference,
  decodeReceipt,
  encodeExecutionReference,
  encodeReceipt,
  thresholdApproval,
  verifyReceipt,
  type ApprovalProvider,
} from "@auths-dev/sdk";
import { development } from "@auths-dev/sdk/integrations";
import { mcp } from "@auths-dev/sdk/profiles";

const self = fileURLToPath(import.meta.url);
const mode = process.argv[2];
const directory = process.argv[3];

if (mode === "verify") {
  const receipt = decodeReceipt(await readFile(required(directory)));
  await verifyReceipt(receipt);
  console.log(JSON.stringify({ outcome: "verified-portable-receipt" }));
} else if (mode === "phase-one") {
  await phaseOne(required(directory));
} else if (mode === "phase-two") {
  await phaseTwo(required(directory));
} else {
  const root = process.env.AUTHS_RECIPE_OUTPUT ?? await mkdtemp(join(tmpdir(), "auths-recipe-five-ts-"));
  runChild("phase-one", root);
  runChild("phase-two", root);
  console.log(JSON.stringify({ recipe: "05-cross-organization-plan", outcome: "completed-after-restart", duplicateEntries: 0 }));
}

async function phaseOne(root: string): Promise<void> {
  const auths = await development.createRecoverableAuths({
    directory: root,
    authority: mcp.allowTools(["quarantine_service", "rotate_token"]),
    approval: await planApproval(),
  });
  const provider = mcp.developmentProvider({ tools: {
    async quarantine_service() { return { quarantined: true }; },
    async rotate_token() {
      await writeFile(join(root, "provider-applied"), "applied", { flag: "wx" });
      return { effect: "possible", cause: "unknown" } as const;
    },
  } });
  try {
    const plan = await mcp.plan([
      mcp.callTool({ name: "quarantine_service", arguments: { region: "eu-west-2" } }),
      mcp.callTool({ name: "rotate_token", arguments: { region: "eu-west-2" } }),
    ]);
    const result = await auths.execute({ plan, provider, requestId: "incident-plan" });
    if (result.kind !== "recoverable" || result.reference === undefined || result.completedReceipts.length !== 1) {
      throw new Error("ordered plan did not stop with one completed member");
    }
    await writeFile(join(root, "reference.bin"), encodeExecutionReference(result.reference));
    await writeFile(join(root, "typescript-receipt.json"), encodeReceipt(result.completedReceipts[0]!));
  } finally {
    await auths.close();
  }
}

async function phaseTwo(root: string): Promise<void> {
  const auths = await development.createRecoverableAuths({
    directory: root,
    authority: mcp.allowTools(["quarantine_service", "rotate_token"]),
    approval: await planApproval(),
  });
  let entries = 0;
  const provider = mcp.developmentProvider({
    tools: {
      async quarantine_service() { entries += 1; throw new Error("unexpected provider re-entry"); },
      async rotate_token() { entries += 1; throw new Error("unexpected provider re-entry"); },
    },
    async reconcile() {
      return existsSync(join(root, "provider-applied"))
        ? { effect: "applied", result: { rotated: true } } as const
        : { effect: "possible", cause: "unknown" } as const;
    },
  });
  try {
    const reference = decodeExecutionReference(await readFile(join(root, "reference.bin")));
    const result = await auths.resume({ reference, provider });
    if (result.kind !== "completed" || entries !== 0) throw new Error("recovery re-entered the provider");
    await verifyReceipt(result.receipt);
    await writeFile(join(root, "typescript-recovered-receipt.json"), encodeReceipt(result.receipt));
  } finally {
    await auths.close();
  }
}

async function planApproval() {
  const providers = [approver("company-a"), approver("company-b")];
  return {
    policy: await approvalPolicy.planOnce({
      policyId: "approval.cross-company-plan",
      maxUses: 2,
      requirements: ["company-a", "company-b"],
    }),
    provider: thresholdApproval({ threshold: 2, providers }),
  };
}

function approver(_organization: string): ApprovalProvider {
  return {
    async approve(request) {
      return {
        requestId: request.requestId,
        transactionDigest: request.transactionDigest.slice(),
        policy: request.policy,
        decision: "approved",
      };
    },
  };
}

function runChild(childMode: string, root: string): void {
  const result = spawnSync(process.execPath, [self, childMode, root], { encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr || result.stdout || `${childMode} failed`);
}

function required(value: string | undefined): string {
  if (value === undefined || value.length === 0) throw new Error("path is required");
  return value;
}
```

## Python

Source: `python/05_cross_organization_plan.py`

```python
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from auths import Approval, ExecutionReference
from auths.integrations import development
from auths.profiles import McpHandlerOutcome, mcp
from auths.verify import decode_receipt, encode_receipt, verify_receipt


class OrganizationApproval:
    def __init__(self, organization: str) -> None:
        self.organization = organization

    async def approve(self, request):
        return Approval.response(request, decision="approved")


def plan_approval():
    providers = (OrganizationApproval("company-a"), OrganizationApproval("company-b"))
    return Approval.plan_once(
        "approval.cross-company-plan",
        Approval.threshold(providers, threshold=2),
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
                mcp.call_tool(
                    name="rotate_token", arguments={"region": "eu-west-2"}
                ),
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
```

## What Auths protected

The recipe uses Rust-owned canonicalization, commitments, authorization, and receipt/recovery semantics. TypeScript and Python coordinate bounded I/O but cannot mint an effect-capable authorization object.

## Break it safely

The executable includes its failure exercise and asserts that no unauthorized or duplicate provider entry occurs. CI fails if the adversarial result changes.

## Take it to production

Replace file-backed development state and deterministic local custody with durable shared state, organizational approval adapters, managed keys, and profile-specific provider reconciliation.
