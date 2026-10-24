"""State and scope checks independent of Google and native proof fixtures."""

from __future__ import annotations

import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from employee_read_demo.admission import AdmissionDenied, AdmissionStore
from employee_read_demo.authority import VerifiedRead, native_body_digest
from employee_read_demo.contracts import TaskDescriptor


def task(now: int) -> TaskDescriptor:
    return TaskDescriptor(
        "auths.google-read-task/v1", "atlas-studio", "customer-demo-01", "a" * 64,
        "employee-principal", "binding-1", "agent-principal", "atlas-drive",
        "connection-1", 1, ("file-A", "file-B"), "text", 1024, 2, 2048,
        now - 1, now + 600, "task-1", "Summarize project A",
    )


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
