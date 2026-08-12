from __future__ import annotations

import asyncio
from pathlib import Path

from auths.integrations import development
from auths.profiles import McpHandlerOutcome, mcp


def test_development_composition_executes_and_denies_before_io() -> None:
    calls = 0

    async def publish(arguments, context):
        nonlocal calls
        calls += 1
        return {"published": arguments["name"]}

    async def scenario() -> None:
        provider = mcp.development_provider(tools={"publish_report": publish})
        async with development.create_auths(
            authority=mcp.allow_tools(["publish_report"])
        ) as auths:
            result = await auths.execute(
                action=mcp.call_tool(
                    name="publish_report", arguments={"name": "weekly"}
                ),
                provider=provider,
                request_id="weekly-32",
            )
            assert result.kind == "completed"
            denied = await auths.execute(
                action=mcp.call_tool(
                    name="delete_report", arguments={"name": "weekly"}
                ),
                provider=provider,
            )
            assert denied.kind == "denied"
            assert all(len(value) <= 256 for value in auths.diagnostics)

    asyncio.run(scenario())
    assert calls == 1


def test_recoverable_development_state_reconciles_without_reentry(
    tmp_path: Path,
) -> None:
    calls = 0

    async def ambiguous_handler(arguments, context):
        nonlocal calls
        calls += 1
        return McpHandlerOutcome("possible", cause="unknown")

    async def forbidden_handler(arguments, context):
        raise AssertionError("provider was entered again")

    async def reconcile(execution_id, service):
        return McpHandlerOutcome("applied", {"published": "weekly"})

    async def scenario() -> None:
        authority = mcp.allow_tools(["publish_report"])
        first = await development.create_recoverable_auths(
            directory=tmp_path,
            authority=authority,
        )
        first_actor = first.actor
        pending = await first.execute(
            action=mcp.call_tool(name="publish_report", arguments={"name": "weekly"}),
            provider=mcp.development_provider(
                tools={"publish_report": ambiguous_handler}
            ),
            request_id="recover-weekly-32",
        )
        assert pending.kind == "recoverable"
        await first.aclose()
        second = await development.create_recoverable_auths(
            directory=tmp_path,
            authority=authority,
        )
        assert second.actor == first_actor
        completed = await second.resume(
            reference=pending.reference,
            provider=mcp.development_provider(
                tools={"publish_report": forbidden_handler},
                reconcile=reconcile,
            ),
        )
        assert completed.kind == "completed"
        await second.aclose()

    asyncio.run(scenario())
    assert calls == 1


def test_development_reservation_admits_one_concurrent_provider_entry() -> None:
    calls = 0

    async def publish(arguments, context):
        nonlocal calls
        calls += 1
        return {"published": True}

    async def scenario() -> None:
        auths = await development.create_auths(
            authority=mcp.allow_tools(["publish_report"])
        )
        try:
            action = mcp.call_tool(name="publish_report", arguments={"name": "weekly"})
            results = await asyncio.gather(
                auths.execute(
                    action=action,
                    provider=mcp.development_provider(
                        tools={"publish_report": publish}
                    ),
                    request_id="concurrent-weekly-32",
                ),
                auths.execute(
                    action=action,
                    provider=mcp.development_provider(
                        tools={"publish_report": publish}
                    ),
                    request_id="concurrent-weekly-32",
                ),
            )
            assert sorted(result.kind for result in results) == [
                "completed",
                "exact-replay",
            ], [(result.kind, result.execution_id) for result in results]
        finally:
            await auths.aclose()

    asyncio.run(scenario())
    assert calls == 1


def test_recoverable_development_state_rejects_corruption(tmp_path: Path) -> None:
    async def scenario() -> None:
        authority = mcp.allow_tools(["publish_report"])

        async def ambiguous(arguments, context):
            return McpHandlerOutcome("possible", cause="unknown")

        first = await development.create_recoverable_auths(
            directory=tmp_path,
            authority=authority,
        )
        pending = await first.execute(
            action=mcp.call_tool(name="publish_report", arguments={}),
            provider=mcp.development_provider(tools={"publish_report": ambiguous}),
            request_id="corrupt-recovery-32",
        )
        assert pending.kind == "recoverable"
        await first.aclose()
        recovery = next(tmp_path.glob("recovery-*.json"))
        recovery.write_bytes(b"{")
        second = await development.create_recoverable_auths(
            directory=tmp_path,
            authority=authority,
        )
        try:
            try:
                await second.resume(
                    reference=pending.reference,
                    provider=mcp.development_provider(
                        tools={"publish_report": ambiguous}
                    ),
                )
            except (RuntimeError, ValueError):
                pass
            else:
                raise AssertionError("corrupt recovery record was accepted")
        finally:
            await second.aclose()

    asyncio.run(scenario())
