"""Single-host, one-use boundary for application-owned provider effects.

This is a local mechanism, not a sandbox or an Auths-qualified executor. It
does not hold a provider credential, perform a request, or prove an effect.
The file implementation requires one POSIX host and a local filesystem; do
not use it on NFS or as a multi-host database substitute.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Literal, Protocol, cast


AttemptState = Literal["attempting", "confirmed", "rejected", "unknown"]
TerminalState = Literal["confirmed", "rejected", "unknown"]


@dataclass(frozen=True)
class AttemptRecord:
    action_commitment: bytes
    operation_key: str
    state: AttemptState


class AttemptStore(Protocol):
    """An atomic claim must precede credential access and provider entry."""

    def claim_once(self, action_commitment: bytes, operation_key: str) -> bool: ...
    def read(self, action_commitment: bytes) -> AttemptRecord | None: ...
    def finish(self, action_commitment: bytes, state: TerminalState) -> AttemptRecord: ...


class FileAttemptStore:
    """Durable, conservative reference store for one POSIX host only.

    The operation key and commitment are both reserved. A crash between their
    two durable files can leave an unused reservation; it cannot authorize a
    second provider entry. `recover` is an explicit operator/startup action
    and must not run concurrently with an active provider call.
    """

    def __init__(self, directory: Path) -> None:
        if os.name != "posix":
            raise OSError("file attempt store requires one POSIX host")
        self.directory = Path(directory)
        if self.directory.is_symlink():
            raise ValueError("attempt directory cannot be a symlink")
        self.directory.mkdir(mode=0o700, parents=False, exist_ok=True)
        if not self.directory.is_dir() or self.directory.stat().st_mode & 0o077:
            raise ValueError("attempt directory must be private")
        lock = self.directory / "lock"
        fd = _open_private(lock, os.O_RDWR | os.O_CREAT)
        os.close(fd)

    def claim_once(self, action_commitment: bytes, operation_key: str) -> bool:
        commitment = _checked_commitment(action_commitment)
        key = _checked_key(operation_key)
        operation = self.directory / f"operation-{hashlib.sha256(key.encode()).hexdigest()}.json"
        claim = self._claim_path(commitment)
        with self._locked():
            if operation.exists() or claim.exists():
                return False
            body = _record_bytes(AttemptRecord(commitment, key, "attempting"))
            # Reserve the logical operation first. An interrupted two-file
            # transition fails closed: an orphan operation blocks reuse.
            _write_exclusive(operation, body)
            _sync_directory(self.directory)
            _write_exclusive(claim, body)
            _sync_directory(self.directory)
            return True

    def read(self, action_commitment: bytes) -> AttemptRecord | None:
        commitment = _checked_commitment(action_commitment)
        with self._locked():
            return self._read_locked(commitment)

    def finish(self, action_commitment: bytes, state: TerminalState) -> AttemptRecord:
        if state not in ("confirmed", "rejected", "unknown"):
            raise ValueError("invalid terminal attempt state")
        commitment = _checked_commitment(action_commitment)
        with self._locked():
            return self._finish_locked(commitment, state)

    def recover(self, action_commitment: bytes) -> AttemptRecord:
        """Mark an abandoned claim unknown; only call after its owner stopped."""
        commitment = _checked_commitment(action_commitment)
        with self._locked():
            return self._finish_locked(commitment, "unknown")

    def _finish_locked(self, commitment: bytes, state: TerminalState) -> AttemptRecord:
        previous = self._read_locked(commitment)
        if previous is None:
            raise ValueError("no attempt claim exists")
        if previous.state != "attempting":
            raise ValueError("attempt already has a terminal state")
        record = AttemptRecord(commitment, previous.operation_key, state)
        _write_exclusive(self._outcome_path(commitment), _record_bytes(record))
        _sync_directory(self.directory)
        return record

    def _read_locked(self, commitment: bytes) -> AttemptRecord | None:
        path = self._claim_path(commitment)
        if not path.exists():
            return None
        claimed = _read_record(path)
        if claimed.action_commitment != commitment or claimed.state != "attempting":
            raise ValueError("attempt claim is corrupt")
        outcome = self._outcome_path(commitment)
        if not outcome.exists():
            return claimed
        final = _read_record(outcome)
        if (
            final.action_commitment != commitment
            or final.operation_key != claimed.operation_key
            or final.state == "attempting"
        ):
            raise ValueError("attempt outcome is corrupt")
        return final

    def _claim_path(self, commitment: bytes) -> Path:
        return self.directory / f"claim-{commitment.hex()}.json"

    def _outcome_path(self, commitment: bytes) -> Path:
        return self.directory / f"outcome-{commitment.hex()}.json"

    @contextmanager
    def _locked(self) -> Iterator[None]:
        import fcntl

        fd = _open_private(self.directory / "lock", os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def _checked_commitment(value: bytes) -> bytes:
    commitment = bytes(value)
    if len(commitment) != 32:
        raise ValueError("action commitment must contain 32 bytes")
    return commitment


def _checked_key(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value):
        raise ValueError("operation key is outside bounds")
    return value


def _record_bytes(record: AttemptRecord) -> bytes:
    return json.dumps(
        {
            "schema": "auths.self-hosted-attempt/1",
            "action_commitment": record.action_commitment.hex(),
            "operation_key": record.operation_key,
            "state": record.state,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _read_record(path: Path) -> AttemptRecord:
    fd = _open_private(path, os.O_RDONLY)
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(513)
    if len(raw) > 512:
        raise ValueError("attempt record exceeds bounds")
    data = json.loads(raw)
    if not isinstance(data, dict) or set(data) != {
        "schema", "action_commitment", "operation_key", "state"
    } or data["schema"] != "auths.self-hosted-attempt/1":
        raise ValueError("invalid attempt record")
    if not isinstance(data["action_commitment"], str):
        raise ValueError("invalid attempt commitment")
    commitment = _checked_commitment(bytes.fromhex(data["action_commitment"]))
    key = _checked_key(data["operation_key"])
    state = data["state"]
    if state not in ("attempting", "confirmed", "rejected", "unknown"):
        raise ValueError("invalid attempt state")
    return AttemptRecord(commitment, key, cast(AttemptState, state))


def _open_private(path: Path, flags: int) -> int:
    fd = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0), 0o600)
    mode = os.fstat(fd).st_mode
    if not stat.S_ISREG(mode) or mode & 0o077:
        os.close(fd)
        raise ValueError("attempt file must be private and regular")
    return fd


def _write_exclusive(path: Path, body: bytes) -> None:
    fd = _open_private(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    with os.fdopen(fd, "wb") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())


def _sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


__all__ = [
    "AttemptRecord",
    "AttemptState",
    "AttemptStore",
    "FileAttemptStore",
    "TerminalState",
]
