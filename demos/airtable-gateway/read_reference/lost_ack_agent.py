#!/usr/bin/env python3
"""Development fault injector: receive exact release bytes, then lose the ACK.

This runs in the separate agent process during AP-071 installed conformance.
It has no provider credential and sends no provider request.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import socket
from pathlib import Path

from employee_read_agent.release_channel import (
    _message, _private_directory, _receive_frame, _send_frame, _sign,
)
from employee_read_agent.run import AgentKey

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def receive_without_ack(*, key_file: Path, socket_path: Path, output_path: Path,
                        task_id: str, task_commitment: str, operation_id: str,
                        resource_handle: str, channel_name: str) -> None:
    _private_directory(socket_path.parent)
    _private_directory(output_path.parent)
    if (socket_path.exists() or socket_path.is_symlink()
            or output_path.exists() or output_path.is_symlink()
            or not task_id or len(task_id) > 128
            or not operation_id or len(operation_id) > 128
            or not resource_handle or len(resource_handle) > 256
            or not channel_name or len(channel_name) > 256
            or _DIGEST.fullmatch(task_commitment) is None):
        raise ValueError("lossy agent output already exists")
    key = AgentKey.load(key_file)
    previous_umask = os.umask(0o077)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(socket_path))
            os.chmod(socket_path, 0o600)
            listener.listen(1)
            listener.settimeout(15)
            try:
                with listener.accept()[0] as peer:
                    peer.settimeout(5)
                    challenge_bytes = _receive_frame(peer)
                    challenge = _message(
                        challenge_bytes, "auths.agent-release-channel-challenge/1",
                    )
                    expected = {
                        "task_id": task_id, "task_commitment": task_commitment,
                        "operation_id": operation_id, "recipient": key.principal,
                        "delivery_channel": channel_name,
                    }
                    if (set(challenge) != set(expected) | {"schema", "nonce"}
                            or any(challenge.get(k) != v for k, v in expected.items())
                            or type(challenge.get("nonce")) is not str
                            or _DIGEST.fullmatch(challenge["nonce"]) is None
                            or challenge["nonce"] == "0" * 64):
                        raise ValueError("lossy agent challenge differs from task")
                    _send_frame(peer, _sign(key, challenge_bytes))
                    content = _receive_frame(peer)
                    ack_bytes = _receive_frame(peer)
                    acknowledgement = _message(ack_bytes, "auths.agent-release-ack/1")
                    if (set(acknowledgement) != {
                            "schema", *expected, "resource_handle",
                            "released_bytes", "content_sha256",
                            "commitment_key_version", "content_commitment",
                        }
                            or any(acknowledgement.get(k) != v
                                   for k, v in expected.items())
                            or acknowledgement.get("resource_handle") != resource_handle
                            or type(acknowledgement.get("released_bytes")) is not int
                            or acknowledgement["released_bytes"] != len(content)
                            or acknowledgement.get("content_sha256") !=
                            hashlib.sha256(content).hexdigest()
                            or type(acknowledgement.get("commitment_key_version")) is not int
                            or acknowledgement["commitment_key_version"] < 1
                            or type(acknowledgement.get("content_commitment")) is not str
                            or _DIGEST.fullmatch(acknowledgement["content_commitment"]) is None):
                        raise ValueError("lossy agent received mismatched release")
                    descriptor = os.open(
                        output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                    )
                    with os.fdopen(descriptor, "wb") as output:
                        output.write(content)
                        output.flush()
                        os.fsync(output.fileno())
                    # Close without signing the gateway's acknowledgement.
            finally:
                socket_path.unlink(missing_ok=True)
    finally:
        os.umask(previous_umask)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("key-file", "socket", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("task-id", "task-commitment", "operation-id",
                 "resource-handle", "channel-name"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    receive_without_ack(
        key_file=args.key_file, socket_path=args.socket, output_path=args.output,
        task_id=args.task_id, task_commitment=args.task_commitment,
        operation_id=args.operation_id, resource_handle=args.resource_handle,
        channel_name=args.channel_name,
    )
    print("agent-received-without-ack")


if __name__ == "__main__":
    main()
