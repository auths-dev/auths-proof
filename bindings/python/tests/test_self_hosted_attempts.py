"""A claimed self-hosted action cannot silently become a second provider call."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from auths.attempts import AttemptRecord, FileAttemptStore

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="reference store is POSIX single-host only"
)


def _commitment(byte: int = 1) -> bytes:
    return bytes([byte]) * 32


def test_claim_is_durable_and_replay_is_rejected_after_restart(tmp_path: Path) -> None:
    store = FileAttemptStore(tmp_path / "attempts")
    assert store.claim_once(_commitment(), "create-task-1")
    assert store.read(_commitment()) == AttemptRecord(
        action_commitment=_commitment(), operation_key="create-task-1", state="attempting"
    )
    reopened = FileAttemptStore(tmp_path / "attempts")
    assert not reopened.claim_once(_commitment(), "create-task-1")
    assert not reopened.claim_once(_commitment(), "different-operation")
    assert not reopened.claim_once(_commitment(2), "create-task-1")
    assert reopened.read(_commitment()).state == "attempting"


def test_competing_claims_have_exactly_one_winner(tmp_path: Path) -> None:
    store = FileAttemptStore(tmp_path / "attempts")
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: store.claim_once(_commitment(), "task"), range(32)))
    assert results.count(True) == 1
    assert results.count(False) == 31


def test_terminal_state_is_append_only_and_unfinished_attempt_is_unknown(
    tmp_path: Path,
) -> None:
    path = tmp_path / "attempts"
    store = FileAttemptStore(path)
    assert store.claim_once(_commitment(), "task")
    assert FileAttemptStore(path).recover(_commitment()).state == "unknown"
    assert not FileAttemptStore(path).claim_once(_commitment(), "task")
    with pytest.raises(ValueError, match="terminal"):
        store.finish(_commitment(), "confirmed")
    assert store.read(_commitment()).state == "unknown"


def test_terminal_outcomes_are_durable_and_cannot_be_changed(tmp_path: Path) -> None:
    store = FileAttemptStore(tmp_path / "attempts")
    assert store.claim_once(_commitment(), "task")
    assert store.finish(_commitment(), "confirmed").state == "confirmed"
    with pytest.raises(ValueError, match="terminal"):
        store.finish(_commitment(), "rejected")
    assert FileAttemptStore(tmp_path / "attempts").read(_commitment()).state == "confirmed"


def test_unclaimed_or_invalid_attempts_fail_closed(tmp_path: Path) -> None:
    store = FileAttemptStore(tmp_path / "attempts")
    with pytest.raises(ValueError, match="claim"):
        store.finish(_commitment(), "unknown")
    with pytest.raises(ValueError, match="commitment"):
        store.claim_once(b"short", "task")
    with pytest.raises(ValueError, match="operation key"):
        store.claim_once(_commitment(), "../bad")
    assert store.read(_commitment()) is None


def test_store_records_are_private(tmp_path: Path) -> None:
    root = tmp_path / "attempts"
    store = FileAttemptStore(root)
    assert store.claim_once(_commitment(), "task")
    assert root.stat().st_mode & 0o077 == 0
    assert all(path.stat().st_mode & 0o077 == 0 for path in root.iterdir())
