"""Installed SDK process fixture. Its fresh private key never leaves this process.

This is a scripted test role, not a production custody adapter or model sandbox.
Only public keys, native signature results and redacted gateway results are sent
to its trusted orchestration pipe. No provider credential is accepted.
"""
import asyncio
import base64
import dataclasses
import http.client
import json
import os
from pathlib import Path
import sys

import auths
from auths.gateway import GatewayClient, GatewayEndpoint
from auths.testkit import development_ed25519_identity_key

MAX = 8 * 1024 * 1024
key = development_ed25519_identity_key()


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def unb64(value):
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if len(raw) > MAX or b64(raw) != value:
        raise ValueError("actor.invalid-encoding")
    return raw


async def call(value):
    operation = value["operation"]
    if operation == "public":
        return {"public_key": b64(key.public_key), "uid": os.getuid(), "pid": os.getpid(),
                "package": str(Path(auths.__file__).resolve()), "language": "python"}
    if operation == "sign":
        return {"signature": b64(key.sign(unb64(value["message"])))}
    if operation == "probe":
        readable = []
        for filename in value["files"]:
            try:
                with open(filename, "rb") as stream:
                    pass
                readable.append(True)
            except OSError:
                readable.append(False)
        return {"readable": readable}
    if operation == "direct-provider":
        connection = http.client.HTTPConnection("127.0.0.1", value["port"], timeout=5)
        try:
            connection.request("PATCH", "/unauthorized", b"{}", {"Content-Type": "application/json"})
            response = connection.getresponse()
            response.read(1024)
            return {"status": response.status}
        finally:
            connection.close()
    gateway = GatewayClient(GatewayEndpoint(Path(value["socket"])))
    if operation == "control":
        return json.loads(await gateway.participant_control(unb64(value["evidence"])))
    submission = {name: unb64(value[name]) for name in ("proof", "action", "approval")}
    if operation == "submit":
        return dataclasses.asdict(await gateway.submit(**submission))
    if operation == "acquire":
        return json.loads(await gateway.acquire_content(**submission))
    raise ValueError("actor.unsupported-operation")


for line in iter(lambda: sys.stdin.buffer.readline(MAX + 1), b""):
    try:
        if len(line) > MAX or not line.endswith(b"\n"):
            raise ValueError("actor.invalid-frame")
        result = asyncio.run(call(json.loads(line)))
        print(json.dumps(result, separators=(",", ":")), flush=True)
    except Exception:
        # External error messages can carry private request/path contents.
        print('{"actor_error":"request-refused"}', flush=True)
