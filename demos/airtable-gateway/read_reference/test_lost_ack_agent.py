"""The fault peer saves the exact bytes and intentionally withholds the ACK."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from employee_read_agent.release_channel import _receive_frame, _send_frame
from employee_read_agent.run import AgentKey

from lost_ack_agent import receive_without_ack


class LostAckAgentTests(unittest.TestCase):
    def exercise(self, *, bad_hash: bool = False) -> tuple[bytes | None, bool]:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as folder:
            directory = Path(folder)
            key_file = directory / "agent.seed"
            key_file.write_bytes(os.urandom(32))
            os.chmod(key_file, 0o600)
            key = AgentKey.load(key_file)
            channel = directory / "release.sock"
            output = directory / "source.bin"
            task = "task-1"
            commitment = "a" * 64
            operation = "read-1"
            handle = "record-1"
            name = "agent-local"
            content = b"Pending"
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    receive_without_ack,
                    key_file=key_file, socket_path=channel, output_path=output,
                    task_id=task, task_commitment=commitment,
                    operation_id=operation, resource_handle=handle,
                    channel_name=name,
                )
                deadline = time.monotonic() + 5
                while not channel.exists() and time.monotonic() < deadline:
                    if future.done():
                        future.result()
                    time.sleep(0.01)
                self.assertTrue(channel.is_socket())
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.settimeout(3)
                    client.connect(str(channel))
                    shared = {
                        "task_id": task, "task_commitment": commitment,
                        "operation_id": operation, "recipient": key.principal,
                        "delivery_channel": name,
                    }
                    challenge = {
                        "schema": "auths.agent-release-channel-challenge/1",
                        **shared, "nonce": "b" * 64,
                    }
                    _send_frame(client, json.dumps(challenge).encode())
                    self.assertTrue(_receive_frame(client))
                    _send_frame(client, content)
                    acknowledgement = {
                        "schema": "auths.agent-release-ack/1", **shared,
                        "resource_handle": handle,
                        "released_bytes": len(content),
                        "content_sha256": ("c" * 64 if bad_hash
                                           else hashlib.sha256(content).hexdigest()),
                        "commitment_key_version": 1,
                        "content_commitment": "d" * 64,
                    }
                    _send_frame(client, json.dumps(acknowledgement).encode())
                    self.assertEqual(client.recv(1), b"")
                if bad_hash:
                    with self.assertRaises(ValueError):
                        future.result(timeout=5)
                else:
                    future.result(timeout=5)
            return (output.read_bytes() if output.exists() else None,
                    channel.exists())

    def test_exact_bytes_saved_without_acknowledgement(self) -> None:
        content, channel_exists = self.exercise()
        self.assertEqual(content, b"Pending")
        self.assertFalse(channel_exists)

    def test_wrong_content_hash_does_not_save(self) -> None:
        content, channel_exists = self.exercise(bad_hash=True)
        self.assertIsNone(content)
        self.assertFalse(channel_exists)


if __name__ == "__main__":
    unittest.main()
