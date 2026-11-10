"""AP076 C1-C7 schedules also run against the installed wheel in binding CI."""
from __future__ import annotations

import asyncio

import pytest

from auths._resource_lifecycle import (
    ResourceLifecycle, Open, Closing, ClosingOverdue, Closed, CleanupFailed, CleanupFailure,
)
from auths._product_errors import AuthsWorkflowError


class ManualTimer:
    def __init__(self, clock, callback, due):
        self.clock, self.callback, self.due = clock, callback, due
    def cancel(self):
        if self in self.clock.jobs:
            self.clock.jobs.remove(self)


class ManualTiming:
    def __init__(self):
        self.value = 100.0
        self.jobs = []
    def now(self):
        return self.value
    def schedule(self, callback, delay):
        timer = ManualTimer(self, callback, self.value + delay)
        self.jobs.append(timer)
        return timer
    def advance(self, delta):
        self.value += delta
        for timer in tuple(self.jobs):
            if timer.due <= self.value:
                timer.cancel()
                timer.callback()


async def scheduled_turn():
    arrived = asyncio.Event()
    asyncio.get_running_loop().call_soon(arrived.set)
    await arrived.wait()


async def no_init() -> None:
    return None


def test_shared_open_waiter_cancellation_and_no_reopening() -> None:
    async def scenario() -> None:
        owner = ResourceLifecycle()
        entered, gate = asyncio.Event(), asyncio.Event()
        calls = 0
        async def initialize() -> None:
            nonlocal calls
            calls += 1
            entered.set()
            await gate.wait()
        first = asyncio.create_task(owner.open(initialize))
        await entered.wait()
        second = asyncio.create_task(owner.open(initialize))
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        gate.set()
        await second
        assert isinstance(owner.state, Open) and calls == 1
        await owner.close()
        with pytest.raises(AuthsWorkflowError):
            await owner.open(initialize)
    asyncio.run(scenario())


def test_close_invalidates_opening_and_retains_late_acquisition() -> None:
    async def scenario() -> None:
        owner = ResourceLifecycle()
        entered, gate = asyncio.Event(), asyncio.Event()
        calls = 0
        async def destroy(_: bool) -> None:
            nonlocal calls
            calls += 1
        async def initialize() -> None:
            entered.set()
            await gate.wait()
            owner.own(object(), destroy)
        opening = asyncio.create_task(owner.open(initialize))
        await entered.wait()
        closing = asyncio.create_task(owner.close())
        with pytest.raises(AuthsWorkflowError):
            await opening
        assert isinstance(owner.state, Closing) and calls == 0
        gate.set()
        await closing
        assert isinstance(owner.state, Closed) and calls == 1
    asyncio.run(scenario())


def test_shared_close_does_not_destroy_active_resources_or_cancel_other_waiters() -> None:
    async def scenario() -> None:
        owner = ResourceLifecycle(opened=True)
        entered, gate, destroyed = asyncio.Event(), asyncio.Event(), asyncio.Event()
        calls = 0
        async def operation() -> str:
            entered.set()
            await gate.wait()
            return "recorded-result"
        async def destroy(_: bool) -> None:
            nonlocal calls
            calls += 1
            destroyed.set()
        owner.own(object(), destroy)
        active = asyncio.create_task(owner.run(operation))
        await entered.wait()
        first = asyncio.create_task(owner.close())
        second = asyncio.create_task(owner.close())
        # The active gate keeps both close waiters pending; cancellation is local.
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        assert calls == 0
        gate.set()
        assert await active == "recorded-result"
        await second
        await destroyed.wait()
        await owner.close()
        assert calls == 1
    asyncio.run(scenario())


def test_open_failure_preserves_original_and_attempts_independent_cleanup() -> None:
    async def scenario() -> None:
        owner = ResourceLifecycle()
        entered, gate = asyncio.Event(), asyncio.Event()
        calls = []
        original = ValueError("opening failure")
        async def failed(_: bool) -> None:
            entered.set()
            await gate.wait()
            calls.append("failed")
            raise ValueError("private provider data")
        async def successful(_: bool) -> None:
            calls.append("success")
        async def initialize() -> None:
            owner.own(object(), failed)
            owner.own(object(), successful)
            raise original
        with pytest.raises(ValueError) as raised:
            await owner.open(initialize)
        assert raised.value is original
        await entered.wait()
        closing = asyncio.create_task(owner.close())
        gate.set()
        with pytest.raises(CleanupFailure):
            await closing
        assert calls == ["failed", "success"] and isinstance(owner.state, CleanupFailed)
        with pytest.raises(AuthsWorkflowError):
            await owner.open(no_init)
    asyncio.run(scenario())


def test_explicit_retry_shares_generation_and_skips_successful_and_unsafe_obligations() -> None:
    async def scenario() -> None:
        owner = ResourceLifecycle(opened=True)
        entered, gate = asyncio.Event(), asyncio.Event()
        counts = [0, 0, 0]
        async def safe(retry: bool) -> None:
            counts[0] += 1
            if not retry:
                raise ValueError()
            entered.set()
            await gate.wait()
        async def unsafe(_: bool) -> None:
            counts[1] += 1
            raise ValueError()
        async def success(_: bool) -> None:
            counts[2] += 1
        owner.own(object(), safe, retry="idempotent")
        owner.own(object(), unsafe)
        owner.own(object(), success)
        for _ in range(2):
            with pytest.raises(CleanupFailure):
                await owner.close()
        assert counts == [1, 1, 1]
        retry = asyncio.create_task(owner.retry_cleanup())
        await entered.wait()
        ordinary = asyncio.create_task(owner.close())
        other = asyncio.create_task(owner.retry_cleanup())
        gate.set()
        outcomes = await asyncio.gather(retry, ordinary, other, return_exceptions=True)
        assert all(isinstance(value, CleanupFailure) for value in outcomes)
        assert counts == [2, 1, 1]
    asyncio.run(scenario())


def test_generation_deadline_retains_unfinished_cleanup_and_late_success() -> None:
    async def scenario() -> None:
        clock = ManualTiming()
        owner = ResourceLifecycle(opened=True, timing=clock)
        entered, gate = asyncio.Event(), asyncio.Event()
        async def destroy(_: bool) -> None:
            entered.set()
            await gate.wait()
        owner.own(object(), destroy)
        first = asyncio.create_task(owner.close(timeout=20))
        await entered.wait()
        short = asyncio.create_task(owner.close(timeout=5))
        second = asyncio.create_task(owner.close())
        await scheduled_turn()
        clock.advance(5)
        with pytest.raises(asyncio.TimeoutError):
            await short
        assert isinstance(owner.state, Closing)
        clock.advance(15)
        results = await asyncio.gather(first, second, return_exceptions=True)
        assert all(isinstance(value, CleanupFailure) and value.cause_chain == ("cleanup-incomplete",) for value in results)
        assert isinstance(owner.state, ClosingOverdue)
        for operation in (owner.close, owner.retry_cleanup):
            with pytest.raises(CleanupFailure):
                await operation()
        gate.set()
        assert owner._cleanup is not None
        await owner._cleanup
        await owner.close()
        assert isinstance(owner.state, Closed) and not clock.jobs
    asyncio.run(scenario())


@pytest.mark.parametrize("event", ["close", "cancel", "publish-first"])
def test_attachment_publication_ownership(event: str) -> None:
    async def scenario() -> None:
        owner = ResourceLifecycle(opened=True)
        entered, gate, destroyed = asyncio.Event(), asyncio.Event(), asyncio.Event()
        child = object()
        calls = 0
        async def create() -> object:
            entered.set()
            await gate.wait()
            return child
        async def destroy(value: object, _: bool) -> None:
            nonlocal calls
            assert value is child
            calls += 1
            destroyed.set()
        attachment = asyncio.create_task(owner.publish(create, destroy))
        await entered.wait()
        if event == "publish-first":
            gate.set()
            assert await attachment is child
            await owner.close()
        else:
            closing = None
            if event == "cancel":
                attachment.cancel()
            else:
                closing = asyncio.create_task(owner.close())
            with pytest.raises((asyncio.CancelledError, AuthsWorkflowError)):
                await attachment
            assert calls == 0
            gate.set()
            await destroyed.wait()
            if closing is not None:
                await closing
            else:
                await owner.close()
        assert calls == 1 and isinstance(owner.state, Closed)
    asyncio.run(scenario())


def test_invalid_timeouts_do_not_begin_lifecycle_work() -> None:
    async def scenario() -> None:
        owner = ResourceLifecycle()
        for value in (0, -1, float("inf"), float("nan")):
            with pytest.raises(ValueError):
                await owner.open(no_init, timeout=value)
            with pytest.raises(ValueError):
                await owner.close(timeout=value)
        await owner.close()
    asyncio.run(scenario())


@pytest.mark.parametrize("kind", ["identity", "remote"])
@pytest.mark.parametrize("owned", [True, False])
def test_public_adapter_cleanup_ownership_and_safe_retry(kind: str, owned: bool) -> None:
    from auths.identity.adapters import create_client
    from auths.protocol import remote_verifier_from_transport

    class Adapter:
        method_id = "test-method"
        suite_id = "test-suite"
        version = 1
        contract = "bounded-byte-transport/2"
        cleanup_retry = "idempotent"
        def __init__(self, fails: bool) -> None:
            self.calls = 0
            self.fails = fails
        async def aclose(self) -> None:
            self.calls += 1
            if self.fails and self.calls == 1:
                raise ValueError("private provider failure")

    async def scenario() -> None:
        first, second = Adapter(True), Adapter(False)
        if kind == "identity":
            client = create_client(methods=[first], authenticators=[second], owns_adapters=owned)
        else:
            client = remote_verifier_from_transport("https://verification.auths.example", first, owns_transport=owned)
        await client.open()
        if owned:
            for _ in range(2):
                with pytest.raises(CleanupFailure):
                    await client.aclose()
            assert first.calls == 1
            assert second.calls == (1 if kind == "identity" else 0)
            await client.retry_cleanup()
            assert first.calls == 2
            assert second.calls == (1 if kind == "identity" else 0)
        else:
            await client.aclose()
            assert first.calls == second.calls == 0
        await client.aclose()
    asyncio.run(scenario())


def test_open_waiter_timeouts_detach_one_and_then_all_without_reinitializing() -> None:
    async def scenario() -> None:
        clock = ManualTiming()
        owner = ResourceLifecycle(timing=clock)
        entered, gate = asyncio.Event(), asyncio.Event()
        calls = 0
        async def initialize() -> None:
            nonlocal calls
            calls += 1
            entered.set()
            await gate.wait()
        first = asyncio.create_task(owner.open(initialize, timeout=5))
        second = asyncio.create_task(owner.open(initialize, timeout=10))
        await entered.wait()
        clock.advance(5)
        with pytest.raises(asyncio.TimeoutError):
            await first
        assert not second.done()
        clock.advance(5)
        with pytest.raises(asyncio.TimeoutError):
            await second
        gate.set()
        await owner.open(initialize)
        assert calls == 1 and owner.is_open
        await owner.close()
    asyncio.run(scenario())


def test_active_operation_outlives_shutdown_deadline_before_zeroization() -> None:
    async def scenario() -> None:
        clock = ManualTiming()
        owner = ResourceLifecycle(opened=True, timing=clock)
        entered, gate = asyncio.Event(), asyncio.Event()
        material = bytearray(b"owned")
        async def operation() -> str:
            entered.set()
            await gate.wait()
            assert material == b"owned"
            return "recorded-result"
        async def erase(_: bool) -> None:
            material[:] = b"\x00" * len(material)
        owner.own(material, erase)
        active = asyncio.create_task(owner.run(operation))
        await entered.wait()
        closing = asyncio.create_task(owner.close(timeout=10))
        await scheduled_turn()
        clock.advance(10)
        with pytest.raises(CleanupFailure):
            await closing
        assert isinstance(owner.state, ClosingOverdue) and material == b"owned"
        gate.set()
        assert await active == "recorded-result"
        assert owner._cleanup is not None
        await owner._cleanup
        assert material == b"\x00" * 5 and isinstance(owner.state, Closed)
    asyncio.run(scenario())


def test_attachment_timeout_keeps_late_child_owned_until_cleanup() -> None:
    async def scenario() -> None:
        clock = ManualTiming()
        owner = ResourceLifecycle(opened=True, timing=clock)
        entered, gate, cleaned = asyncio.Event(), asyncio.Event(), asyncio.Event()
        calls = 0
        async def create() -> object:
            entered.set()
            await gate.wait()
            return object()
        async def destroy(value: object, retry: bool) -> None:
            nonlocal calls
            calls += 1
            cleaned.set()
        pending = asyncio.create_task(owner.publish(create, destroy, timeout=5))
        await entered.wait()
        clock.advance(5)
        with pytest.raises(asyncio.TimeoutError):
            await pending
        assert calls == 0 and owner.is_open
        gate.set()
        await cleaned.wait()
        await owner.close()
        assert calls == 1
    asyncio.run(scenario())


def test_late_cleanup_failure_settles_overdue_owner_before_explicit_safe_retry() -> None:
    async def scenario() -> None:
        clock = ManualTiming()
        owner = ResourceLifecycle(opened=True, timing=clock)
        entered, gate = asyncio.Event(), asyncio.Event()
        calls = 0
        async def destroy(retry: bool) -> None:
            nonlocal calls
            calls += 1
            if not retry:
                entered.set()
                await gate.wait()
                raise ValueError("private adapter failure")
        owner.own(object(), destroy, retry="idempotent")
        closing = asyncio.create_task(owner.close(timeout=10))
        await entered.wait()
        clock.advance(10)
        with pytest.raises(CleanupFailure):
            await closing
        gate.set()
        assert owner._cleanup is not None
        await owner._cleanup
        assert isinstance(owner.state, CleanupFailed)
        with pytest.raises(CleanupFailure):
            await owner.close()
        assert calls == 1
        await owner.retry_cleanup()
        assert isinstance(owner.state, Closed) and calls == 2
    asyncio.run(scenario())
