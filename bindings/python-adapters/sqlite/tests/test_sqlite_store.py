from __future__ import annotations

from pathlib import Path

import pytest

from auths.runtime import CommandState
from auths_sqlite import SQLiteRuntimeStore


@pytest.mark.asyncio
async def test_sqlite_store_persists_atomic_runtime_state(tmp_path: Path) -> None:
    path = tmp_path / "runtime.sqlite3"
    store = SQLiteRuntimeStore(path, budget_ceilings={"numeric-ceiling-v1": 3})
    challenge = bytes([1]) * 32
    assert await store.issue(challenge, expires_at=100)
    assert await store.claim(challenge, now=10) == "claimed"
    assert await store.claim(challenge, now=10) == "duplicate"
    assert await store.reserve(bytes([2]) * 32, "numeric-ceiling-v1", 2) == "reserved"
    assert await store.reserve(bytes([3]) * 32, "numeric-ceiling-v1", 2) == "exhausted"
    state = CommandState(
        "command-1",
        bytes([4]) * 32,
        bytes([5]) * 32,
        bytes([6]) * 32,
        "decision-recorded",
        0,
        "request-1",
        10,
    )
    assert await store.compare_and_swap(None, state) == "stored"
    assert await store.compare_and_swap(None, state) == "conflict"
    assert await SQLiteRuntimeStore(path).load("command-1") == state
    assert await store.put("receipt-1", b"receipt") == "stored"
    assert await store.put("receipt-1", b"receipt") == "duplicate"
