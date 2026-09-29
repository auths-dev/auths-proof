"""A relay on the gateway's application socket that records every exchange.

    python gateway_witness.py --listen WORK/witness.sock --upstream WORK/app.sock \\
                              --log WORK/witness.jsonl

Both journeys point their submissions at ``--listen``. For each connection
the relay reads one request frame, forwards it to the gateway, reads the
gateway's response frame, appends one JSON line to ``--log``, and only then
writes the response back. A command therefore cannot finish before its
exchange is in the log, and a request the agent's process refused never
appears in it. The relay runs as its own process, so a journey that blocks
on a child process cannot stall it. It uses only the standard library.

Each log line is ``{"schema", "action_sha256", "operation_id", "response"}``:
``action_sha256`` is the SHA-256 of the submitted action for a submit frame,
``operation_id`` the requested operation for an observe frame, and
``response`` the gateway's parsed response, or ``null`` if it sent none.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import struct
import sys
import threading
from pathlib import Path
from typing import Any, Dict, Optional

# The gateway's own bound on either frame.
MAX_FRAME_BYTES = 8 * 1024 * 1024
TIMEOUT_SECONDS = 60


def read_exact(connection: socket.socket, size: int) -> Optional[bytes]:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            return None
        chunks.extend(chunk)
    return bytes(chunks)


def read_frame(connection: socket.socket) -> Optional[bytes]:
    header = read_exact(connection, 4)
    if header is None:
        return None
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > MAX_FRAME_BYTES:
        return None
    return read_exact(connection, length)


def describe(request: bytes) -> Dict[str, Any]:
    try:
        frame = json.loads(request)
    except ValueError:
        return {"schema": None, "action_sha256": None, "operation_id": None}
    if not isinstance(frame, dict):
        return {"schema": None, "action_sha256": None, "operation_id": None}
    action_sha256 = None
    action = frame.get("action_b64")
    if isinstance(action, str):
        try:
            raw = base64.urlsafe_b64decode(action + "=" * (-len(action) % 4))
            action_sha256 = hashlib.sha256(raw).hexdigest()
        except ValueError:
            action_sha256 = None
    inner = frame.get("request")
    operation = inner.get("operation_id") if isinstance(inner, dict) else None
    return {
        "schema": frame.get("schema"),
        "action_sha256": action_sha256,
        "operation_id": operation if isinstance(operation, str) else None,
    }


class Witness:
    def __init__(self, upstream: str, log: Path) -> None:
        self.upstream = upstream
        self.log = log
        self.lock = threading.Lock()

    def record(self, line: Dict[str, Any]) -> None:
        with self.lock, self.log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(line, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def serve(self, client: socket.socket) -> None:
        with client:
            client.settimeout(TIMEOUT_SECONDS)
            try:
                request = read_frame(client)
            except OSError:
                return
            if request is None:
                return
            line = describe(request)
            response: Optional[bytes] = None
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as gateway:
                    gateway.settimeout(TIMEOUT_SECONDS)
                    gateway.connect(self.upstream)
                    gateway.sendall(struct.pack(">I", len(request)) + request)
                    response = read_frame(gateway)
            except OSError:
                response = None
            try:
                line["response"] = json.loads(response) if response is not None else None
            except ValueError:
                line["response"] = None
            self.record(line)
            if response is not None:
                try:
                    client.sendall(struct.pack(">I", len(response)) + response)
                except OSError:
                    return


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", type=Path, required=True)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()
    witness = Witness(str(args.upstream), args.log)
    args.log.touch(mode=0o600)
    args.listen.unlink(missing_ok=True)
    previous = os.umask(0o177)
    try:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(args.listen))
    finally:
        os.umask(previous)
    os.chmod(args.listen, 0o600)
    server.listen(16)
    print("ready", flush=True)
    try:
        while True:
            client, _ = server.accept()
            threading.Thread(target=witness.serve, args=(client,), daemon=True).start()
    except KeyboardInterrupt:
        return 0
    finally:
        server.close()


if __name__ == "__main__":
    sys.exit(main())
