#!/usr/bin/python3
"""Operator-held Airtable PAT source for the generic AP-071 custody interface."""

import base64
import hashlib
import hmac
import json
import os
import stat
import sys
import time
from pathlib import Path

from launch import credentials


PINS_SCHEMA = "auths.airtable-custody-pins/1"
REQUEST_SCHEMA = "auths.custody-process-request/1"
RESPONSE_SCHEMA = "auths.custody-process-response/1"
DESCRIPTOR_SCHEMA = "auths.custody-process-descriptor/1"


def private_file(path, maximum):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("custody.private-file-refused")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_size > maximum
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError("custody.private-file-refused")
        data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("custody.private-file-refused")
        return data


def pins_from(path):
    pins = json.loads(private_file(path, 16_384))
    expected = {"schema", "connection_id", "connection_generation",
                "source_generation", "source_ref", "account_subject",
                "recipe_digest", "kind", "pat_file", "pat_file_sha256"}
    if (not isinstance(pins, dict) or set(pins) != expected
            or pins["schema"] != PINS_SCHEMA
            or pins["kind"] not in ("read-release", "write-effect")
            or not isinstance(pins["connection_id"], str)
            or not isinstance(pins["account_subject"], str)
            or not isinstance(pins["recipe_digest"], str)
            or not isinstance(pins["source_ref"], str)
            or not pins["source_ref"].startswith("auths.materializer-source/1:")
            or type(pins["connection_generation"]) is not int
            or type(pins["source_generation"]) is not int
            or pins["connection_generation"] < 1
            or pins["source_generation"] < 1
            or pins["source_generation"] > pins["connection_generation"]
            or len(pins["recipe_digest"]) != 64
            or any(char not in "0123456789abcdef" for char in pins["recipe_digest"])
            or len(pins["pat_file_sha256"]) != 64
            or any(char not in "0123456789abcdef" for char in pins["pat_file_sha256"])):
        raise ValueError("custody.invalid-pins")
    raw = private_file(pins["pat_file"], 16_384)
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(),
                               pins["pat_file_sha256"]):
        raise ValueError("custody.changed-pat-file")
    token = json.loads(credentials(pins["pat_file"]))["token"]
    if not isinstance(token, str) or not token.startswith("pat"):
        raise ValueError("custody.invalid-pat")
    return pins, token


def authority_digest(pins):
    digest = hashlib.sha256(b"auths.airtable-custody-authority/1\0")
    for key in ("connection_id", "account_subject", "source_ref",
                "recipe_digest", "kind", "pat_file_sha256"):
        digest.update(pins[key].encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def main():
    if len(sys.argv) != 4 or sys.argv[2] != "--pins":
        raise ValueError("custody.invalid-command")
    command = sys.argv[1]
    if command not in ("--validate", "--describe", "--probe", "--materialize"):
        raise ValueError("custody.invalid-command")
    pins, token = pins_from(sys.argv[3])
    if command in ("--validate", "--probe"):
        return
    authority = authority_digest(pins)
    if command == "--describe":
        print(json.dumps({"schema": DESCRIPTOR_SCHEMA,
                          "connection_id": pins["connection_id"],
                          "authority_digest": authority},
                         sort_keys=True, separators=(",", ":")), end="")
        return
    raw = sys.stdin.buffer.read(16_385)
    if len(raw) > 16_384:
        raise ValueError("custody.invalid-request")
    request = json.loads(raw)
    expected = {"schema", "task_id", "operation_id", "connection_id",
                "connection_generation", "source_generation", "account_subject",
                "recipe_digest", "task_expires_at", "kind", "source_base64"}
    if not isinstance(request, dict) or set(request) != expected:
        raise ValueError("custody.invalid-request")
    encoded = request["source_base64"]
    if not isinstance(encoded, str) or len(encoded) > 2_048:
        raise ValueError("custody.invalid-request")
    source = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    if (request["schema"] != REQUEST_SCHEMA
            or type(request["connection_generation"]) is not int
            or type(request["source_generation"]) is not int
            or not isinstance(request["task_id"], str)
            or not isinstance(request["operation_id"], str)
            or request["connection_id"] != pins["connection_id"]
            or request["connection_generation"] != pins["connection_generation"]
            or request["source_generation"] != pins["source_generation"]
            or request["account_subject"] != pins["account_subject"]
            or request["recipe_digest"] != pins["recipe_digest"]
            or request["kind"] != pins["kind"]
            or type(request["task_expires_at"]) is not int
            or request["task_expires_at"] <= int(time.time())
            or not request["task_id"] or not request["operation_id"]
            or not hmac.compare_digest(source, pins["source_ref"].encode())):
        raise ValueError("custody.context-refused")
    print(json.dumps({
        "schema": RESPONSE_SCHEMA,
        "bearer_base64": base64.urlsafe_b64encode(token.encode()).decode().rstrip("="),
        "account_subject": pins["account_subject"],
        "effective_authority_digest": authority,
        "valid_for_seconds": 20,
    }, sort_keys=True, separators=(",", ":")), end="")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("custody.refused", file=sys.stderr)
        raise SystemExit(2)
