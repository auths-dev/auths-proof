"""Durable SQLite atomic reservations for Auths integrations."""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Literal, Union

from auths.framework import AtomicReservationRecord


class SQLiteAtomicReservationStore:
    def __init__(self, path: Union[str, Path]) -> None:
        self._path = str(Path(path))
        self._closed = False
        self._initialize()

    async def reserve(
        self, record: AtomicReservationRecord
    ) -> Literal["acquired", "exact-replay", "conflict"]:
        if self._closed:
            raise RuntimeError("atomic reservation store is closed")
        if (
            type(record) is not AtomicReservationRecord
            or not record.key
            or len(record.key.encode()) > 256
            or len(record.commitment) != 32
            or not record.value
            or len(record.value) > 262_144
        ):
            raise ValueError("invalid atomic reservation")
        return await asyncio.to_thread(self._reserve, record)

    async def reopen(self) -> SQLiteAtomicReservationStore:
        return SQLiteAtomicReservationStore(self._path)

    async def aclose(self) -> None:
        self._closed = True

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
        self, record: AtomicReservationRecord
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
