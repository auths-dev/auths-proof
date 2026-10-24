"""SQLite-backed task admission and post-fetch release gate."""

from __future__ import annotations

import secrets
import sqlite3
import time
import os
import stat
import fcntl
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .authority import VerifiedRead, native_body_digest
from .contracts import MAX_ATTEMPTS, MAX_METADATA_BYTES, MAX_PROVIDER_RESPONSE_BYTES, TaskDescriptor


class AdmissionDenied(PermissionError):
    pass


@dataclass(frozen=True)
class Reservation:
    challenge: bytes
    task_id: str
    task_revision: int
    connection_generation: int
    max_bytes: int


@dataclass
class BrokerRuntimeLease:
    """Exclusive workbench ownership of one broker database until server close."""

    descriptor: int | None
    abandoned_claims: int

    def close(self) -> None:
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None


class AdmissionStore:
    """One database file shared by all broker workers; never stores content."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if stat.S_IMODE(self.path.parent.stat().st_mode) & 0o077:
            raise PermissionError("broker state directory must be private")
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if self.path.is_symlink() or stat.S_IMODE(self.path.stat().st_mode) & 0o077:
                raise PermissionError("broker state database must be private")
        else:
            os.close(descriptor)
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS connections (
                  id TEXT PRIMARY KEY, company TEXT NOT NULL, employee TEXT NOT NULL,
                  binding_ref TEXT NOT NULL, generation INTEGER NOT NULL,
                  status TEXT NOT NULL DEFAULT 'active'
                );
                CREATE TABLE IF NOT EXISTS tasks (
                  id TEXT PRIMARY KEY, digest TEXT NOT NULL, company TEXT NOT NULL,
                  employee TEXT NOT NULL, agent TEXT NOT NULL, connection TEXT NOT NULL,
                  generation INTEGER NOT NULL, not_before INTEGER NOT NULL,
                  expires INTEGER NOT NULL, max_calls INTEGER NOT NULL,
                  max_bytes INTEGER NOT NULL, calls INTEGER NOT NULL DEFAULT 0,
                  charged_bytes INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
                  reserved_provider_bytes INTEGER NOT NULL DEFAULT 0,
                  in_flight INTEGER NOT NULL DEFAULT 0,
                  challenges_issued INTEGER NOT NULL DEFAULT 0,
                  revision INTEGER NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT 'active'
                );
                CREATE TABLE IF NOT EXISTS challenges (
                  value BLOB PRIMARY KEY, task_id TEXT NOT NULL,
                  body_digest BLOB NOT NULL, expires INTEGER NOT NULL,
                  status TEXT NOT NULL DEFAULT 'issued',
                  FOREIGN KEY(task_id) REFERENCES tasks(id)
                );
                CREATE TABLE IF NOT EXISTS provider_attempts (
                  challenge BLOB NOT NULL, ordinal INTEGER NOT NULL,
                  phase TEXT NOT NULL, status TEXT NOT NULL,
                  response_bytes INTEGER NOT NULL DEFAULT 0,
                  started_at INTEGER NOT NULL, finished_at INTEGER,
                  PRIMARY KEY(challenge, ordinal),
                  FOREIGN KEY(challenge) REFERENCES challenges(value)
                );
            """)
            columns = {row[1] for row in db.execute("PRAGMA table_info(tasks)")}
            if "reserved_provider_bytes" not in columns:
                db.execute("ALTER TABLE tasks ADD COLUMN reserved_provider_bytes INTEGER NOT NULL DEFAULT 0")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def open_runtime(self) -> BrokerRuntimeLease:
        """Acquire one workbench lease and close claims from its dead predecessor.

        The deployed broker must be the only process dispatching reads from
        this database. The OS releases the advisory lock on process death.
        Conservative call, attempt and byte charges are never refunded.
        """
        lock_path = self.path.with_name(self.path.name + ".runtime.lock")
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if stat.S_IMODE(os.fstat(descriptor).st_mode) & 0o077:
                raise PermissionError("broker runtime lock must be private")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise AdmissionDenied("broker runtime already owns this state") from error
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                abandoned = db.execute("""SELECT COUNT(*) FROM challenges
                    WHERE status='claimed'""").fetchone()[0]
                db.execute("UPDATE challenges SET status='abandoned' WHERE status='claimed'")
                db.execute("UPDATE tasks SET in_flight=0 WHERE in_flight>0")
                db.commit()
            return BrokerRuntimeLease(descriptor, abandoned)
        except BaseException:
            os.close(descriptor)
            raise

    def enroll(self, task: TaskDescriptor) -> None:
        """Persist a task after the caller has verified its signed grant chain."""
        task.validate()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT company,employee,binding_ref,generation,status FROM connections WHERE id=?",
                             (task.connection_id,)).fetchone()
            if row != (task.company_id, task.employee_principal, task.identity_binding_ref,
                       task.connection_generation, "active"):
                raise AdmissionDenied("employee connection is unavailable")
            db.execute("""INSERT INTO tasks
              (id,digest,company,employee,agent,connection,generation,not_before,expires,max_calls,max_bytes)
              VALUES (?,?,?,?,?,?,?,?,?,?,?)""", (
                task.task_id, task.digest, task.company_id, task.employee_principal,
                task.agent_principal, task.connection_id, task.connection_generation,
                task.not_before, task.expires_at, task.max_calls, task.max_total_bytes,
            ))
            db.commit()

    def register_connection(self, *, connection_id: str, company: str, employee: str,
                            binding_ref: str, generation: int) -> None:
        """Call only after employee OAuth subject and principal binding are verified."""
        if not connection_id or not company or not employee or not binding_ref or generation < 1:
            raise ValueError("invalid connection metadata")
        with self._connect() as db:
            db.execute("INSERT INTO connections(id,company,employee,binding_ref,generation) VALUES(?,?,?,?,?)",
                       (connection_id, company, employee, binding_ref, generation))

    def issue_challenge(self, task: TaskDescriptor, body_digest: bytes, *, now: int | None = None) -> bytes:
        now = int(time.time()) if now is None else now
        if body_digest not in {native_body_digest(call, task.service) for call in task.calls()}:
            raise AdmissionDenied("body is outside task")
        challenge = secrets.token_bytes(32)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT digest,status,not_before,expires,challenges_issued FROM tasks WHERE id=?", (task.task_id,)).fetchone()
            if (row is None or row[:4] != (task.digest, "active", task.not_before, task.expires_at)
                    or row[4] >= 64 or not task.not_before <= now < task.expires_at):
                raise AdmissionDenied("task is unavailable")
            db.execute("INSERT INTO challenges(value,task_id,body_digest,expires) VALUES(?,?,?,?)",
                       (challenge, task.task_id, body_digest, min(now + 60, task.expires_at)))
            db.execute("UPDATE tasks SET challenges_issued=challenges_issued+1 WHERE id=?", (task.task_id,))
            db.commit()
        return challenge

    def claim(self, task: TaskDescriptor, verified: VerifiedRead, challenge: bytes, *, now: int | None = None) -> Reservation:
        now = int(time.time()) if now is None else now
        if verified.command not in task.calls() or len(challenge) != 32:
            raise AdmissionDenied("read is outside task")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT digest,company,employee,agent,connection,generation,
                not_before,expires,max_calls,max_bytes,calls,charged_bytes,attempts,revision,status,in_flight
                ,reserved_provider_bytes
                FROM tasks WHERE id=?""", (task.task_id,)).fetchone()
            if row is None or row[:6] != (
                task.digest, task.company_id, task.employee_principal,
                task.agent_principal, task.connection_id, task.connection_generation,
            ) or row[14] != "active" or not row[6] <= now < row[7]:
                raise AdmissionDenied("task is unavailable")
            connection = db.execute("SELECT company,employee,generation,status FROM connections WHERE id=?",
                                    (task.connection_id,)).fetchone()
            if connection != (task.company_id, task.employee_principal, task.connection_generation, "active"):
                raise AdmissionDenied("employee connection is unavailable")
            hit = db.execute("SELECT body_digest,expires,status FROM challenges WHERE value=? AND task_id=?",
                             (challenge, task.task_id)).fetchone()
            if hit is None or hit[0] != native_body_digest(verified.command, task.service) or hit[2] != "issued":
                raise AdmissionDenied("challenge is unavailable")
            if now >= hit[1]:
                raise AdmissionDenied("challenge expired")
            # The closed provider adapter performs at most one metadata GET
            # and one content GET. Reserve both before the first dispatch.
            # _get reads at most limit + 1 bytes for each of the fixed metadata
            # and content GETs. Conservatively retain both charges on failure.
            provider_reservation = MAX_METADATA_BYTES + verified.command.max_bytes + 2
            if (row[10] >= row[8] or row[12] + 2 > MAX_ATTEMPTS
                    or row[11] + verified.command.max_bytes > row[9]
                    or row[16] + provider_reservation > MAX_PROVIDER_RESPONSE_BYTES
                    or row[15] >= 2):
                raise AdmissionDenied("task limit exhausted")
            db.execute("UPDATE challenges SET status='claimed' WHERE value=?", (challenge,))
            db.execute("""UPDATE tasks SET calls=calls+1,attempts=attempts+2,
                charged_bytes=charged_bytes+?,reserved_provider_bytes=reserved_provider_bytes+?,
                in_flight=in_flight+1 WHERE id=?""",
                       (verified.command.max_bytes, provider_reservation, task.task_id))
            db.commit()
            return Reservation(challenge, task.task_id, row[13], row[5], verified.command.max_bytes)

    def release(self, reservation: Reservation, content: bytes, *, now: int | None = None,
                on_commit: Callable[[sqlite3.Connection], None] | None = None) -> bytes:
        """Serialize release commitment with revoke; return bytes only on success."""
        now = int(time.time()) if now is None else now
        if len(content) > reservation.max_bytes:
            raise AdmissionDenied("provider body exceeded reservation")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT revision,generation,expires,status FROM tasks WHERE id=?",
                             (reservation.task_id,)).fetchone()
            state = db.execute("SELECT status FROM challenges WHERE value=? AND task_id=?",
                               (reservation.challenge, reservation.task_id)).fetchone()
            if row is None or row[0] != reservation.task_revision or row[1] != reservation.connection_generation or row[3] != "active":
                raise AdmissionDenied("task changed before release")
            connection = db.execute("SELECT generation,status FROM connections WHERE id=(SELECT connection FROM tasks WHERE id=?)",
                                    (reservation.task_id,)).fetchone()
            if connection != (reservation.connection_generation, "active"):
                raise AdmissionDenied("connection changed before release")
            if now >= row[2] or state != ("claimed",):
                raise AdmissionDenied("release is unavailable")
            db.execute("UPDATE challenges SET status='released' WHERE value=?", (reservation.challenge,))
            db.execute("UPDATE tasks SET in_flight=in_flight-1 WHERE id=? AND in_flight>0", (reservation.task_id,))
            if on_commit is not None:
                on_commit(db)
            db.commit()
        return content

    def fail(self, reservation: Reservation) -> None:
        """Close a failed admitted call; its call, attempt and byte charges remain."""
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute("UPDATE challenges SET status='failed' WHERE value=? AND task_id=? AND status='claimed'",
                                 (reservation.challenge, reservation.task_id)).rowcount
            if changed:
                db.execute("UPDATE tasks SET in_flight=in_flight-1 WHERE id=? AND in_flight>0", (reservation.task_id,))
            db.commit()

    def attempt_observer(self, reservation: Reservation) -> ProviderAttemptLedger:
        """Persist every fixed Drive GET before dispatch, then observed bytes/outcome."""
        return ProviderAttemptLedger(self, reservation)

    def attempts_for(self, reservation: Reservation) -> tuple[tuple, ...]:
        """Trusted diagnostic view; a started row may mean the broker crashed."""
        with self._connect() as db:
            return tuple(db.execute("""SELECT ordinal,phase,status,response_bytes
                FROM provider_attempts WHERE challenge=? ORDER BY ordinal""",
                (reservation.challenge,)).fetchall())

    def current(self, reservation: Reservation, *, now: int | None = None) -> bool:
        now = int(time.time()) if now is None else now
        with self._connect() as db:
            row = db.execute("SELECT revision,generation,expires,status FROM tasks WHERE id=?",
                             (reservation.task_id,)).fetchone()
            connection = db.execute("SELECT generation,status FROM connections WHERE id=(SELECT connection FROM tasks WHERE id=?)",
                                    (reservation.task_id,)).fetchone()
            return bool(row and row[0] == reservation.task_revision
                        and row[1] == reservation.connection_generation
                        and now < row[2] and row[3] == "active"
                        and connection == (reservation.connection_generation, "active"))

    def revoke(self, task_id: str) -> None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE tasks SET status='revoked', revision=revision+1 WHERE id=?", (task_id,))
            db.commit()

    def disconnect(self, connection_id: str) -> int:
        """Invalidate token generation and all linked tasks in one transaction."""
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT generation,status FROM connections WHERE id=?", (connection_id,)).fetchone()
            if row is None or row[1] != "active":
                raise AdmissionDenied("connection is unavailable")
            next_generation = row[0] + 1
            db.execute("UPDATE connections SET generation=?,status='disconnected' WHERE id=?",
                       (next_generation, connection_id))
            db.execute("UPDATE tasks SET status='revoked',revision=revision+1 WHERE connection=? AND status='active'",
                       (connection_id,))
            db.commit()
            return next_generation


class ProviderAttemptLedger:
    """Durable per-GET observations tied to one admitted challenge."""

    def __init__(self, store: AdmissionStore, reservation: Reservation) -> None:
        self.store = store
        self.reservation = reservation

    def begin(self, ordinal: int, phase: str) -> None:
        if (ordinal, phase) not in {(1, "metadata"), (2, "content")}:
            raise AdmissionDenied("provider attempt is outside closed read")
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status FROM challenges WHERE value=? AND task_id=?",
                             (self.reservation.challenge, self.reservation.task_id)).fetchone()
            if row != ("claimed",):
                raise AdmissionDenied("provider attempt is unavailable")
            if ordinal == 2 and db.execute("""SELECT status FROM provider_attempts
                WHERE challenge=? AND ordinal=1""", (self.reservation.challenge,)).fetchone() is None:
                raise AdmissionDenied("metadata attempt is missing")
            db.execute("""INSERT INTO provider_attempts
                (challenge,ordinal,phase,status,started_at) VALUES(?,?,?,'started',?)""",
                (self.reservation.challenge, ordinal, phase, int(time.time())))
            db.commit()

    def observed(self, ordinal: int, count: int) -> None:
        if ordinal not in {1, 2} or not 0 < count <= 16_384:
            raise AdmissionDenied("provider byte observation is invalid")
        maximum = MAX_METADATA_BYTES + 1 if ordinal == 1 else self.reservation.max_bytes + 1
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute("""UPDATE provider_attempts
                SET response_bytes=response_bytes+? WHERE challenge=? AND ordinal=?
                AND status='started' AND response_bytes+?<=?""",
                (count, self.reservation.challenge, ordinal, count, maximum)).rowcount
            if changed != 1:
                raise AdmissionDenied("provider byte observation exceeds reservation")
            db.commit()

    def finish(self, ordinal: int, status: str) -> None:
        allowed = {"redirect_refused", "encoding_refused", "limit_refused", "transport_unknown"}
        if status not in allowed and not (status.startswith("http_") and status[5:].isdigit()
                                         and 100 <= int(status[5:]) <= 599):
            raise AdmissionDenied("provider attempt outcome is invalid")
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute("""UPDATE provider_attempts SET status=?,finished_at=?
                WHERE challenge=? AND ordinal=? AND status='started'""",
                (status, int(time.time()), self.reservation.challenge, ordinal)).rowcount
            if changed != 1:
                raise AdmissionDenied("provider attempt is unavailable")
            db.commit()
