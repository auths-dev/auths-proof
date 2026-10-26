"""A registered agent process acknowledges only exact delivered content."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from auths.identity import IdentityOk, authenticate_message
from auths.identity.authoring import create_raw_key_ed25519_identity
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat

from employee_read_agent.release_channel import _receive_frame, _send_frame, serve_one_release
from employee_read_agent.run import AgentKey


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class ReleaseChannelTests(unittest.TestCase):
    def test_cli_receives_into_private_file_from_distinct_process(self) -> None:
        private = Ed25519PrivateKey.generate()
        seed = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        key = AgentKey(seed)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            os.chmod(root, 0o700)
            key_file = root / "agent.key"
            key_file.write_bytes(seed)
            os.chmod(key_file, 0o600)
            socket_path, output_path = root / "agent.sock", root / "released.content"
            process = subprocess.Popen([
                sys.executable, "-m", "employee_read_agent.cli", "serve-release",
                "--key-file", str(key_file), "--socket", str(socket_path),
                "--output", str(output_path), "--task-id", "task-2",
                "--task-commitment", "a" * 64, "--operation-id", "read-2",
                "--resource-handle", "record-2", "--channel-name", "agent-channel",
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                until = time.monotonic() + 5
                while not socket_path.exists() and time.monotonic() < until:
                    time.sleep(0.01)
                self.assertTrue(socket_path.exists(), process.stderr.read() if process.poll() is not None else "socket unavailable")
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                    peer.settimeout(5)
                    peer.connect(str(socket_path))
                    common = {"task_id": "task-2", "task_commitment": "a" * 64,
                              "operation_id": "read-2", "recipient": key.principal,
                              "delivery_channel": "agent-channel"}
                    challenge = _canonical({"schema": "auths.agent-release-channel-challenge/1",
                                            **common, "nonce": "d" * 64})
                    _send_frame(peer, challenge)
                    self.assertEqual(len(_receive_frame(peer)), 64)
                    content = b"one private status"
                    acknowledgement = _canonical({
                        "schema": "auths.agent-release-ack/1", **common,
                        "resource_handle": "record-2", "released_bytes": len(content),
                        "content_sha256": hashlib.sha256(content).hexdigest(),
                        "commitment_key_version": 1, "content_commitment": "c" * 64,
                    })
                    _send_frame(peer, content)
                    _send_frame(peer, acknowledgement)
                    self.assertEqual(len(_receive_frame(peer)), 64)
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, stderr)
                self.assertEqual(json.loads(stdout)["status"], "acknowledgement-sent")
                self.assertEqual(output_path.read_bytes(), content)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def test_one_exact_delivery_and_bad_digest_refusal(self) -> None:
        private = Ed25519PrivateKey.generate()
        key = AgentKey(private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        packet = create_raw_key_ed25519_identity(
            private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).to_bytes()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            os.chmod(root, 0o700)
            for incorrect in (False, True):
                socket_path = root / "agent.sock"
                output_path = root / ("bad.content" if incorrect else "good.content")
                result: dict = {}

                def receive() -> None:
                    try:
                        result["value"] = serve_one_release(
                            socket_path=socket_path, output_path=output_path, key=key,
                            task_id="task-1", task_commitment="a" * 64,
                            operation_id="read-1", resource_handle="record-1",
                            channel_name="agent-channel",
                        )
                    except Exception as error:
                        result["error"] = error

                thread = threading.Thread(target=receive)
                thread.start()
                until = time.monotonic() + 5
                while not socket_path.exists() and time.monotonic() < until:
                    time.sleep(0.01)
                self.assertTrue(socket_path.exists(), repr(result))
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                    peer.settimeout(5)
                    peer.connect(str(socket_path))
                    common = {"task_id": "task-1", "task_commitment": "a" * 64,
                              "operation_id": "read-1", "recipient": key.principal,
                              "delivery_channel": "agent-channel"}
                    challenge = _canonical({"schema": "auths.agent-release-channel-challenge/1",
                                            **common, "nonce": "b" * 64})
                    _send_frame(peer, challenge)
                    challenge_signature = _receive_frame(peer)
                    verified = asyncio.run(authenticate_message(
                        packet, message=challenge, signature=challenge_signature))
                    self.assertIsInstance(verified, IdentityOk)
                    content = b"Ready"
                    acknowledgement = _canonical({
                        "schema": "auths.agent-release-ack/1", **common,
                        "resource_handle": "record-1", "released_bytes": len(content),
                        "content_sha256": "0" * 64 if incorrect else hashlib.sha256(content).hexdigest(),
                        "commitment_key_version": 1, "content_commitment": "c" * 64,
                    })
                    _send_frame(peer, content)
                    _send_frame(peer, acknowledgement)
                    if not incorrect:
                        signature = _receive_frame(peer)
                        verified = asyncio.run(authenticate_message(
                            packet, message=acknowledgement, signature=signature))
                        self.assertIsInstance(verified, IdentityOk)
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
                if incorrect:
                    self.assertIsInstance(result.get("error"), ValueError)
                    self.assertFalse(output_path.exists())
                else:
                    self.assertEqual(result["value"]["status"], "acknowledgement-sent")
                    self.assertEqual(output_path.read_bytes(), b"Ready")
                    self.assertEqual(output_path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
