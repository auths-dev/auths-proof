"""Ideal AP-SPEC-040 GitHub agent workflow.

This is a target-API example, not an example of the currently implemented
package. It keeps candidate inspection, effects, reconciliation, receipts,
and replay explicit while making proof creation and verification the two-call
center of the workflow.
"""

from __future__ import annotations

import asyncio
import os

from auths.profiles import github_issue_address
from auths.service import connect


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


async def main() -> None:
    auths = connect(
        endpoint=required("AUTHS_GITHUB_AGENT_ENDPOINT"),
        profile=github_issue_address(),
    )

    # The deployment owns the repository, issue, base revision, path policy,
    # and effect budgets. The caller may narrow expiry and choose a label, but
    # cannot copy, edit, or widen that configured boundary.
    async with await auths.delegate(
        agent_label=os.environ.get("AUTHS_AGENT_LABEL", "launch-agent"),
        expires_in_seconds=15 * 60,
    ) as agent:
        print("bounded task", agent.boundary)

        # Inspection remains explicit: it parses a hostile Git bundle without
        # running candidate code. The scoped agent supplies its bound base.
        fixture = os.environ.get("AUTHS_GITHUB_FIXTURE")
        inspection = (
            await agent.inspect(fixture=fixture)
            if fixture
            else await agent.inspect(
                bundle=required("AUTHS_GITHUB_CANDIDATE_BUNDLE"),
                candidate_revision=required("AUTHS_GITHUB_CANDIDATE_REVISION"),
            )
        )

        # The ordinary Auths proof workflow: create, then verify.
        proof = await agent.create(inspection)
        verification = await agent.verify(proof)

        if not verification.passed:
            if verification.kind == "indeterminate":
                raise RuntimeError(
                    "verification needs trusted input: "
                    f"{verification.code} ({verification.request_id})"
                )
            if not fixture:
                raise RuntimeError(f"unexpected denial: {verification.code}")
            print("denied safely", verification.code)
            return

        if fixture:
            raise RuntimeError("a denial fixture unexpectedly produced a verified proof")
        if os.environ.get("AUTHS_GITHUB_LIVE") != "1":
            raise RuntimeError(
                "set AUTHS_GITHUB_LIVE=1 to permit the isolated draft-PR effect"
            )

        # Verification never performs an effect. Only the sealed verified
        # value can cross the executor boundary.
        outcome = await agent.execute(verification.verified)
        if outcome.kind == "indeterminate" and outcome.next == "reconcile":
            outcome = await agent.reconcile(outcome.reference)
        if outcome.kind not in ("completed", "reconciled"):
            raise RuntimeError(f"workflow did not complete: {outcome.code}")

        # Receipt authenticity and replay remain separate from authorization.
        receipts = await agent.verify_receipts()
        replay = await agent.replay()
        if replay.kind != "replayed" or replay.mutations != 0:
            raise RuntimeError("replay attempted another GitHub mutation")

        print("completed", outcome.pull_request_url, receipts)


asyncio.run(main())
