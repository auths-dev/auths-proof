"""Durable SQLite atomic reservations for Auths integrations."""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Literal, Optional, Set, Union

from auths.adapters.reservations import ReservationRecord


_Decision = Literal["acquired", "exact-replay", "conflict"]


class SQLiteAtomicReservationStore:
    """Own admitted transactions independently of their callers.

    Cancelling a reserve waiter does not certify rollback: its worker still
    settles. Close stops admission and shares one drain operation; cancelling
    a close waiter leaves that operation running. Closed means quiescent.
    """

    def __init__(self, path: Union[str, Path]) -> None:
        self._path = str(Path(path))
        self._state: Literal["open", "closing", "closed"] = "open"
        self._workers: Set[asyncio.Task[_Decision]] = set()
        self._closing: Optional[asyncio.Task[None]] = None
        self._initialize()

    @property
    def contract(self) -> Literal["atomic-reservation-store/2"]:
        return "atomic-reservation-store/2"

    @property
    def kind(self) -> str:
        return "auths.sqlite.atomic-reservation"

    @property
    def durability(self) -> Literal["single-machine-durable"]:
        return "single-machine-durable"

    async def reserve(
        self, record: ReservationRecord
    ) -> Literal["acquired", "exact-replay", "conflict"]:
        if self._state != "open":
            raise RuntimeError("atomic reservation store is closed")
        if type(record) is not ReservationRecord:
            raise ValueError("invalid atomic reservation")
        key, commitment, value = record.key, record.commitment, record.value
        if (
            type(key) is not str
            or not key
            or len(key) > 256
            or len(key.encode()) > 256
            or type(commitment) not in (bytes, bytearray)
            or len(commitment) != 32
            or type(value) not in (bytes, bytearray)
            or not value
            or len(value) > 262_144
        ):
            raise ValueError("invalid atomic reservation")
        # A frozen record can still contain caller-owned bytearrays. Validate
        # exact bounded builtins before copying; no hostile conversion callback
        # or caller buffer may cross the admitted worker boundary.
        snapshot = ReservationRecord(key, bytes(commitment), bytes(value))
        # Even an eager task factory must wait until ownership is registered
        # before it can submit foreign work to the thread pool.
        start: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        worker = asyncio.create_task(self._reserve_owned(snapshot, start))
        self._workers.add(worker)
        worker.add_done_callback(self._settled)
        start.set_result(None)
        return await asyncio.shield(worker)

    async def _reserve_owned(
        self, record: ReservationRecord, start: asyncio.Future[None]
    ) -> _Decision:
        await start
        return await asyncio.to_thread(self._reserve, record)

    def _settled(self, worker: asyncio.Task[_Decision]) -> None:
        self._workers.discard(worker)
        # Consume failures even after the last reservation waiter detached.
        if not worker.cancelled():
            worker.exception()

    async def reopen(self) -> SQLiteAtomicReservationStore:
        return SQLiteAtomicReservationStore(self._path)

    async def aclose(self) -> None:
        if self._state == "open":
            self._state = "closing"
            self._closing = asyncio.create_task(self._drain())
        closing = self._closing
        if closing is not None:
            await asyncio.shield(closing)

    async def _drain(self) -> None:
        # Closing prevents new admission; this cohort contains every worker
        # that can still mutate the database on behalf of this instance.
        await asyncio.gather(*tuple(self._workers), return_exceptions=True)
        self._state = "closed"

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=5, isolation_level=None)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS atomic_reservations (
                    reservation_key TEXT PRIMARY KEY,
                    commitment BLOB NOT NULL,
                    value BLOB NOT NULL
                );
                """
            )

    def _reserve(
        self, record: ReservationRecord
    ) -> Literal["acquired", "exact-replay", "conflict"]:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT commitment, value FROM atomic_reservations "
                "WHERE reservation_key=?",
                (record.key,),
            ).fetchone()
            if existing is not None:
                connection.execute("COMMIT")
                return (
                    "exact-replay"
                    if existing == (record.commitment, record.value)
                    else "conflict"
                )
            connection.execute(
                "INSERT INTO atomic_reservations VALUES(?, ?, ?)",
                (record.key, record.commitment, record.value),
            )
            connection.execute("COMMIT")
            return "acquired"


__all__ = ["SQLiteAtomicReservationStore"]
