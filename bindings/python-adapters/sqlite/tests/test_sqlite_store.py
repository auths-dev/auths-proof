from __future__ import annotations

from pathlib import Path

import pytest

from auths.framework import AtomicReservationRecord
from auths.testkit import ConformanceMetadata, certify_atomic_store
from auths_sqlite import SQLiteAtomicReservationStore


@pytest.mark.asyncio
async def test_sqlite_store_is_durable_and_conformant(tmp_path: Path) -> None:
    sequence = 0

    def factory() -> SQLiteAtomicReservationStore:
        nonlocal sequence
        sequence += 1
        return SQLiteAtomicReservationStore(tmp_path / f"store-{sequence}.sqlite3")

    report = await certify_atomic_store(
        factory,
        ConformanceMetadata(
            "auths.sqlite.atomic-reservation",
            "1",
            capabilities=("durable-reopen",),
        ),
    )
    assert report.passed

    store = SQLiteAtomicReservationStore(tmp_path / "durable.sqlite3")
    record = AtomicReservationRecord("execution-1", bytes([1]) * 32, b"reserved")
    assert await store.reserve(record) == "acquired"
    reopened = await store.reopen()
    assert await reopened.reserve(record) == "exact-replay"
    assert (
        await reopened.reserve(
            AtomicReservationRecord("execution-1", bytes([2]) * 32, b"different")
        )
        == "conflict"
    )
