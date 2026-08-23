from __future__ import annotations

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
