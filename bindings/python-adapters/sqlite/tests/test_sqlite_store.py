from __future__ import annotations

import asyncio
import gc
import sqlite3
import threading
from pathlib import Path

import pytest

from auths.adapters.reservations import ReservationRecord
from auths.testkit import run_reservation_store_conformance
from auths_sqlite import SQLiteAtomicReservationStore


@pytest.mark.asyncio
async def test_sqlite_store_is_durable_and_conformant(tmp_path: Path) -> None:
    def factory(name: str) -> SQLiteAtomicReservationStore:
        return SQLiteAtomicReservationStore(tmp_path / f"{name}.sqlite3")

    report = await run_reservation_store_conformance(factory)
    assert report.passed

    store = SQLiteAtomicReservationStore(tmp_path / "durable.sqlite3")
    record = ReservationRecord("execution-1", bytes([1]) * 32, b"reserved")
    assert await store.reserve(record) == "acquired"
    reopened = await store.reopen()
    assert await reopened.reserve(record) == "exact-replay"
    assert (
        await reopened.reserve(
            ReservationRecord("execution-1", bytes([2]) * 32, b"different")
        )
        == "conflict"
    )


class CommitBarrierStore(SQLiteAtomicReservationStore):
    """Use a real transaction, held immediately before its commit."""

    def __init__(self, path: Path, *, fail: bool = False) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.fail = fail
        super().__init__(path)

    def _connect(self) -> sqlite3.Connection:
        owner = self

        class Connection(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if sql == "COMMIT":
                    owner.entered.set()
                    if not owner.release.wait(5):
                        raise TimeoutError("test did not release the commit barrier")
                    if owner.fail:
                        raise sqlite3.OperationalError("injected commit failure")
                return super().execute(sql, parameters)

        connection = sqlite3.connect(
            self._path, timeout=5, isolation_level=None, factory=Connection
        )
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    async def wait_for_commit(self) -> None:
        assert await asyncio.wait_for(asyncio.to_thread(self.entered.wait, 5), 6)


@pytest.mark.asyncio
async def test_close_joins_actual_reservation_commit(tmp_path: Path) -> None:
    store = CommitBarrierStore(tmp_path / "closing.sqlite3")
    record = ReservationRecord("owned", bytes([3]) * 32, b"original")
    reserve = asyncio.create_task(store.reserve(record))
    try:
        await store.wait_for_commit()
        first = asyncio.create_task(store.aclose())
        second = asyncio.create_task(store.aclose())
        await asyncio.sleep(0)  # Run both admitted close waiters; no clock delay.
        assert not first.done() and not second.done()
        with pytest.raises(RuntimeError, match="closed"):
            await store.reserve(record)
        store.release.set()
        assert await asyncio.wait_for(reserve, 6) == "acquired"
        await asyncio.wait_for(asyncio.gather(first, second), 6)
        with pytest.raises(RuntimeError, match="closed"):
            await store.reserve(record)
        reopened = await store.reopen()
        try:
            assert await reopened.reserve(record) == "exact-replay"
        finally:
            await reopened.aclose()
    finally:
        store.release.set()
        await store.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("fail", [False, True])
async def test_cancelled_waiters_retain_worker_and_shared_close(
    tmp_path: Path, fail: bool
) -> None:
    store = CommitBarrierStore(tmp_path / "detached.sqlite3", fail=fail)
    record = ReservationRecord("detached", bytes([4]) * 32, b"retained")
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    unhandled = []
    loop.set_exception_handler(lambda _loop, context: unhandled.append(context))
    reserve = asyncio.create_task(store.reserve(record))
    try:
        await store.wait_for_commit()
        reserve.cancel()
        with pytest.raises(asyncio.CancelledError):
            await reserve
        cancelled_close = asyncio.create_task(store.aclose())
        remaining_close = asyncio.create_task(store.aclose())
        await asyncio.sleep(0)
        cancelled_close.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled_close
        assert not remaining_close.done()
        store.release.set()
        await asyncio.wait_for(remaining_close, 6)
        reopened = await store.reopen()
        try:
            assert await reopened.reserve(record) == (
                "acquired" if fail else "exact-replay"
            )
        finally:
            await reopened.aclose()
        gc.collect()
        await asyncio.sleep(0)
        assert unhandled == []
    finally:
        store.release.set()
        await store.aclose()
        loop.set_exception_handler(previous_handler)


@pytest.mark.asyncio
async def test_admitted_worker_retains_private_bounded_record(tmp_path: Path) -> None:
    entered, release = threading.Event(), threading.Event()

    class EntryBarrierStore(SQLiteAtomicReservationStore):
        def _reserve(self, record):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("test did not release the worker barrier")
            return super()._reserve(record)

    store = EntryBarrierStore(tmp_path / "snapshot.sqlite3")
    commitment = bytearray([7]) * 32
    value = bytearray(b"original")
    # Runtime callers can pass mutable bytes despite the frozen dataclass's
    # annotations; its admission snapshot must precede foreign worker code.
    reserve = asyncio.create_task(store.reserve(ReservationRecord("snapshot", commitment, value)))
    try:
        assert await asyncio.wait_for(asyncio.to_thread(entered.wait, 5), 6)
        commitment[:] = bytes([8]) * 32
        value[:] = b"rewritten"
        release.set()
        assert await asyncio.wait_for(reserve, 6) == "acquired"
        await store.aclose()
        reopened = await store.reopen()
        try:
            assert await reopened.reserve(
                ReservationRecord("snapshot", bytes([7]) * 32, b"original")
            ) == "exact-replay"
            assert await reopened.reserve(
                ReservationRecord("snapshot", bytes(commitment), bytes(value))
            ) == "conflict"
        finally:
            await reopened.aclose()
    finally:
        release.set()
        await store.aclose()
