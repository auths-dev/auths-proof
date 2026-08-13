from __future__ import annotations

import asyncio
import concurrent.futures
import json
import multiprocessing
import time
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


def test_recoverable_development_state_survives_process_death_after_provider_entry(
    tmp_path: Path,
) -> None:
    process = multiprocessing.get_context("spawn").Process(
        target=_run_gateway_until_terminated,
        args=(tmp_path,),
    )
    process.start()
    try:
        _wait_for_provider_checkpoint(tmp_path)
        process.terminate()
        process.join(timeout=10)
        assert not process.is_alive()
        time.sleep(1.1)

        async def scenario() -> None:
            invokes = 0
            reconciles = 0

            async def forbidden_handler(arguments, context):
                nonlocal invokes
                invokes += 1
                raise AssertionError("provider was entered again")

            async def reconcile(execution_id, service):
                nonlocal reconciles
                reconciles += 1
                return McpHandlerOutcome("applied", {"published": "weekly"})

            auths = await development.create_recoverable_auths(
                directory=tmp_path,
                authority=mcp.allow_tools(["publish_report"]),
            )
            try:
                action = mcp.call_tool(
                    name="publish_report", arguments={"name": "weekly"}
                )
                completed = await auths.recover(
                    action=action,
                    provider=mcp.development_provider(
                        tools={"publish_report": forbidden_handler},
                        reconcile=reconcile,
                    ),
                    request_id="crash-weekly-32",
                )
                assert completed.kind == "completed"
                assert invokes == 0
                assert reconciles == 1
                try:
                    await auths.recover(
                        action=action,
                        provider=mcp.development_provider(
                            tools={"publish_report": forbidden_handler},
                            reconcile=reconcile,
                        ),
                        request_id="crash-weekly-32",
                    )
                except Exception as error:
                    assert "no pending" in str(error)
                else:
                    raise AssertionError("completed execution remained recoverable")
            finally:
                await auths.aclose()

        asyncio.run(scenario())
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=10)


def test_recoverable_development_manifest_publishes_atomically_under_contention(
    tmp_path: Path,
) -> None:
    authority = mcp.allow_tools(["publish_report"])
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        pending = tuple(
            executor.map(
                lambda _: development.create_recoverable_auths(
                    directory=tmp_path,
                    authority=authority,
                ),
                range(100),
            )
        )
    manifest = json.loads((tmp_path / "auths-development-v2.json").read_bytes())
    assert manifest["schema"] == "auths.recoverable-development/2"
    assert len(bytes.fromhex(manifest["sessionKey"])) == 32
    assert len(pending) == 100


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
        recoveries = tuple(tmp_path.glob("recovery-*.json"))
        assert recoveries
        for recovery in recoveries:
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


def _run_gateway_until_terminated(directory: Path) -> None:
    async def publish(arguments, context):
        await asyncio.Future()

    async def scenario() -> None:
        auths = await development.create_recoverable_auths(
            directory=directory,
            authority=mcp.allow_tools(["publish_report"]),
        )
        await auths.execute(
            action=mcp.call_tool(name="publish_report", arguments={"name": "weekly"}),
            provider=mcp.development_provider(tools={"publish_report": publish}),
            request_id="crash-weekly-32",
        )

    asyncio.run(scenario())


def _wait_for_provider_checkpoint(directory: Path) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        for path in directory.glob("execution-*.json"):
            if json.loads(path.read_bytes()).get("stage") == "provider":
                return
        time.sleep(0.025)
    raise AssertionError("gateway did not reach its durable provider checkpoint")
