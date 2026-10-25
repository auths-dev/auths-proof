"""One-shot, private Unix socket receiver for a managed Auths read release."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import stat
import struct
from pathlib import Path

from auths.identity.authoring import create_raw_key_ed25519_identity, prepare_identity_message
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .run import AgentKey


_MAX_FRAME = 262_144
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _private_directory(path: Path) -> None:
    if (not path.is_absolute() or path.is_symlink() or not path.is_dir()
            or path.resolve() != path or path.stat().st_uid != os.geteuid()
            or stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise ValueError("agent release directory must be private and canonical")


def _receive_exact(peer: socket.socket, count: int) -> bytes:
    if not 0 <= count <= _MAX_FRAME:
        raise ValueError("agent release frame is outside bounds")
    data = bytearray()
    while len(data) < count:
        part = peer.recv(count - len(data))
        if not part:
            raise ValueError("agent release frame was incomplete")
        data.extend(part)
    return bytes(data)


def _receive_frame(peer: socket.socket) -> bytes:
    count = struct.unpack("!I", _receive_exact(peer, 4))[0]
    if not 1 <= count <= _MAX_FRAME:
        raise ValueError("agent release frame is outside bounds")
    return _receive_exact(peer, count)


def _send_frame(peer: socket.socket, data: bytes) -> None:
    if not 1 <= len(data) <= _MAX_FRAME:
        raise ValueError("agent release frame is outside bounds")
    peer.sendall(struct.pack("!I", len(data)) + data)


def _message(data: bytes, schema: str) -> dict:
    def unique(pairs: list[tuple[str, object]]) -> dict:
        value = {}
        for name, item in pairs:
            if name in value:
                raise ValueError("agent release message has duplicate fields")
            value[name] = item
        return value

    try:
        value = json.loads(data, object_pairs_hook=unique)
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError("agent release message is invalid") from error
    if type(value) is not dict or value.get("schema") != schema:
        raise ValueError("agent release message schema is invalid")
    return value


def _sign(key: AgentKey, message: bytes) -> bytes:
    public = key.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    identity = create_raw_key_ed25519_identity(public)
    preimage = prepare_identity_message(identity, message=message).signing_preimage
    return key.private.sign(preimage)


def serve_one_release(*, socket_path: Path, output_path: Path, key: AgentKey,
                      task_id: str, task_commitment: str, operation_id: str,
                      resource_handle: str, channel_name: str) -> dict:
    """Accept one release; acknowledge only after saving its exact bytes."""
    _private_directory(socket_path.parent)
    _private_directory(output_path.parent)
    if (socket_path.exists() or socket_path.is_symlink() or output_path.exists()
            or output_path.is_symlink() or not task_id or not operation_id
            or not resource_handle or not channel_name
            or len(task_id) > 128 or len(operation_id) > 128
            or len(resource_handle) > 256 or len(channel_name) > 256
            or _DIGEST.fullmatch(task_commitment) is None):
        raise ValueError("agent release installation is invalid")
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
                    challenge = _message(challenge_bytes,
                                         "auths.agent-release-channel-challenge/1")
                    expected = {"task_id": task_id, "task_commitment": task_commitment,
                                "operation_id": operation_id, "recipient": key.principal,
                                "delivery_channel": channel_name}
                    if (set(challenge) != {"schema", "task_id", "task_commitment",
                                           "operation_id", "recipient", "delivery_channel", "nonce"}
                            or any(challenge.get(name) != value for name, value in expected.items())
                            or type(challenge.get("nonce")) is not str
                            or _DIGEST.fullmatch(challenge["nonce"]) is None
                            or challenge["nonce"] == "0" * 64):
                        raise ValueError("agent release challenge does not match task")
                    _send_frame(peer, _sign(key, challenge_bytes))
                    content = _receive_frame(peer)
                    acknowledgement_bytes = _receive_frame(peer)
                    acknowledgement = _message(acknowledgement_bytes,
                                               "auths.agent-release-ack/1")
                    if (set(acknowledgement) != {"schema", "task_id", "task_commitment",
                                                 "operation_id", "recipient", "delivery_channel",
                                                 "resource_handle", "released_bytes",
                                                 "content_sha256", "commitment_key_version",
                                                 "content_commitment"}
                            or any(acknowledgement.get(name) != value
                            for name, value in expected.items())
                            or acknowledgement.get("resource_handle") != resource_handle
                            or type(acknowledgement.get("released_bytes")) is not int
                            or acknowledgement["released_bytes"] != len(content)
                            or acknowledgement.get("content_sha256") != hashlib.sha256(content).hexdigest()
                            or type(acknowledgement.get("commitment_key_version")) is not int
                            or acknowledgement["commitment_key_version"] < 1
                            or type(acknowledgement.get("content_commitment")) is not str
                            or _DIGEST.fullmatch(acknowledgement["content_commitment"]) is None):
                        raise ValueError("agent release acknowledgement differs from received bytes")
                    descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    try:
                        with os.fdopen(descriptor, "wb") as output:
                            output.write(content)
                            output.flush()
                            os.fsync(output.fileno())
                    except BaseException:
                        output_path.unlink(missing_ok=True)
                        raise
                    _send_frame(peer, _sign(key, acknowledgement_bytes))
                    return {"status": "acknowledgement-sent", "output": str(output_path),
                            "released_bytes": len(content), "task_id": task_id,
                            "operation_id": operation_id}
            finally:
                socket_path.unlink(missing_ok=True)
    finally:
        os.umask(previous_umask)
