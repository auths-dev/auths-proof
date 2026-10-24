"""State and scope checks independent of Google and native proof fixtures."""

from __future__ import annotations

import tempfile
import time
import unittest
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from employee_read_demo.admission import AdmissionDenied, AdmissionStore
from employee_read_demo.authority import VerifiedRead, native_body_digest
from employee_read_demo.contracts import TaskDescriptor
from employee_read_demo.contracts import MAX_METADATA_BYTES


def task(now: int) -> TaskDescriptor:
    return TaskDescriptor(
        "auths.google-read-task/v1", "atlas-studio", "customer-demo-01", "a" * 64,
        "employee-principal", "binding-1", "agent-principal", "atlas-drive",
        "connection-1", 1, ("file-A", "file-B"), "text", 1024, 2, 2048,
        now - 1, now + 600, "task-1", "Summarize project A",
    )


def _claim_in_process(path: str, descriptor: TaskDescriptor, value: bytes,
                      start, outcomes, now: int) -> None:
    start.wait(10)
    store = AdmissionStore(Path(path))
    verified = VerifiedRead(descriptor.calls()[0], b"x" * 32, "authorized")
    try:
        store.claim(descriptor, verified, value, now=now)
        outcomes.put("admitted")
    except AdmissionDenied:
        outcomes.put("denied")


class AdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "admission.sqlite3"
        self.now = int(time.time())
        self.task = task(self.now)
        self.store = AdmissionStore(self.path)
        self.store.register_connection(connection_id="connection-1", company="atlas-studio",
                                       employee="employee-principal", binding_ref="binding-1", generation=1)
        self.store.enroll(self.task)

    def verified(self, index: int = 0) -> VerifiedRead:
        return VerifiedRead(self.task.calls()[index], b"x" * 32, "authorized")

    def test_replay_and_release_after_revocation_are_denied(self) -> None:
        command = self.verified()
        challenge = self.store.issue_challenge(self.task, native_body_digest(command.command), now=self.now)
        reservation = self.store.claim(self.task, command, challenge, now=self.now)
        with self.assertRaises(AdmissionDenied):
            self.store.claim(self.task, command, challenge, now=self.now)
        self.store.revoke(self.task.task_id)
        with self.assertRaises(AdmissionDenied):
            self.store.release(reservation, b"private body", now=self.now)

    def test_two_connections_share_atomic_capacity(self) -> None:
        peer = AdmissionStore(self.path)
        command = self.verified()
        challenges = [self.store.issue_challenge(self.task, native_body_digest(command.command), now=self.now)
                      for _ in range(3)]
        def claim(value: bytes) -> bool:
            try:
                peer.claim(self.task, command, value, now=self.now)
                return True
            except AdmissionDenied:
                return False
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(claim, challenges))
        self.assertEqual(sum(results), 2)

    def test_two_processes_share_atomic_capacity_and_provider_byte_reservations(self) -> None:
        descriptor = TaskDescriptor(**{**self.task.__dict__, "task_id": "process-task"})
        self.store.enroll(descriptor)
        digest = native_body_digest(descriptor.calls()[0])
        challenges = [self.store.issue_challenge(descriptor, digest, now=self.now)
                      for _ in range(3)]
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        outcomes = context.Queue()
        processes = [context.Process(
            target=_claim_in_process,
            args=(str(self.path), descriptor, challenge, start, outcomes, self.now),
        ) for challenge in challenges]
        for process in processes:
            process.start()
        start.set()
        for process in processes:
            process.join(timeout=15)
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
                self.fail("admission worker did not finish")
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(sorted(outcomes.get(timeout=3) for _ in processes),
                         ["admitted", "admitted", "denied"])
        with self.store._connect() as db:
            row = db.execute("""SELECT calls,attempts,charged_bytes,
                reserved_provider_bytes FROM tasks WHERE id=?""", (
                    descriptor.task_id,
                )).fetchone()
        self.assertEqual(row, (2, 4, 2048, 2 * (MAX_METADATA_BYTES + 1024 + 2)))

    def test_two_in_flight_calls_block_third_until_one_closes(self) -> None:
        wide = TaskDescriptor(**{**self.task.__dict__, "task_id": "task-2",
                                 "max_calls": 4, "max_total_bytes": 4096})
        self.store.enroll(wide)
        command = VerifiedRead(wide.calls()[0], b"x" * 32, "authorized")
        digest = native_body_digest(command.command)
        challenges = [self.store.issue_challenge(wide, digest, now=self.now) for _ in range(3)]
        first = self.store.claim(wide, command, challenges[0], now=self.now)
        second = self.store.claim(wide, command, challenges[1], now=self.now)
        with self.assertRaises(AdmissionDenied):
            AdmissionStore(self.path).claim(wide, command, challenges[2], now=self.now)
        self.store.fail(first)
        third = AdmissionStore(self.path).claim(wide, command, challenges[2], now=self.now)
        self.assertEqual(self.store.release(second, b"ok", now=self.now), b"ok")
        self.store.fail(third)

    def test_provider_attempts_survive_restart_with_unknown_outcome(self) -> None:
        command = self.verified()
        challenge = self.store.issue_challenge(self.task, native_body_digest(command.command), now=self.now)
        reservation = self.store.claim(self.task, command, challenge, now=self.now)
        observer = self.store.attempt_observer(reservation)
        with self.assertRaises(AdmissionDenied):
            observer.begin(2, "content")
        observer.begin(1, "metadata")
        observer.observed(1, 17)
        observer.finish(1, "http_200")
        observer.begin(2, "content")
        observer.observed(2, 9)
        with self.assertRaises(AdmissionDenied):
            observer.observed(2, 1024)
        reopened = AdmissionStore(self.path)
        self.assertEqual(reopened.attempts_for(reservation), (
            (1, "metadata", "http_200", 17),
            (2, "content", "started", 9),
        ))
        reopened.fail(reservation)
        self.assertEqual(reopened.attempts_for(reservation)[1][2], "started")

    def test_receipt_write_failure_rolls_back_release_commitment(self) -> None:
        command = self.verified()
        challenge = self.store.issue_challenge(self.task, native_body_digest(command.command), now=self.now)
        reservation = self.store.claim(self.task, command, challenge, now=self.now)

        def refused_write(_db):
            raise RuntimeError("synthetic receipt storage failure")

        with self.assertRaises(RuntimeError):
            self.store.release(reservation, b"approved", now=self.now,
                               on_commit=refused_write)
        with self.store._connect() as db:
            state = db.execute("SELECT status FROM challenges WHERE value=?", (challenge,)).fetchone()
            in_flight = db.execute("SELECT in_flight FROM tasks WHERE id=?", (self.task.task_id,)).fetchone()
        self.assertEqual(state, ("claimed",))
        self.assertEqual(in_flight, (1,))
        self.assertEqual(self.store.release(reservation, b"approved", now=self.now), b"approved")

    def test_outside_task_body_cannot_get_challenge(self) -> None:
        with self.assertRaises(AdmissionDenied):
            self.store.issue_challenge(self.task, b"0" * 32, now=self.now)

    def test_disconnect_invalidates_task_and_generation(self) -> None:
        command = self.verified()
        challenge = self.store.issue_challenge(self.task, native_body_digest(command.command), now=self.now)
        reservation = self.store.claim(self.task, command, challenge, now=self.now)
        self.assertEqual(self.store.disconnect("connection-1"), 2)
        self.assertFalse(self.store.current(reservation, now=self.now))
        with self.assertRaises(AdmissionDenied):
            self.store.release(reservation, b"private", now=self.now)

    def test_task_ids_are_sorted_unique(self) -> None:
        invalid = TaskDescriptor(**{**self.task.__dict__, "file_ids": ("file-B", "file-A")})
        with self.assertRaises(ValueError):
            invalid.validate()


if __name__ == "__main__":
    unittest.main()
