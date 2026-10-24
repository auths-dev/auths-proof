"""CI-only installed-container probe; no Google or model request is made."""

from __future__ import annotations

import os
import socket
import urllib.error
import urllib.request
from pathlib import Path


def connection_succeeds(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


assert connection_succeeds("agent-relay", 8080)
assert connection_succeeds("model-relay", 8080)
assert not connection_succeeds("broker", 8765)
assert not connection_succeeds("www.googleapis.com", 443)

request = urllib.request.Request(
    "http://agent-relay:8080/api/v1/tasks/challenge",
    data=b"{}",
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    urllib.request.urlopen(request, timeout=5)
    raise AssertionError("unconfigured challenge unexpectedly succeeded")
except urllib.error.HTTPError as error:
    assert error.code == 403
    assert b"agent transport is unavailable" in error.read()

for path, method in (
    ("/api/v1/session", "GET"),
    ("/api/v1/session/logout", "POST"),
    ("/api/v1/receipts/example", "GET"),
):
    request = urllib.request.Request(
        "http://agent-relay:8080" + path,
        data=b"{}" if method == "POST" else None,
        method=method,
    )
    try:
        urllib.request.urlopen(request, timeout=5)
        raise AssertionError(f"agent relay exposed {path}")
    except urllib.error.HTTPError as error:
        assert error.code == 404, (path, error.code)

for path in ("/state", "/private", "/var/run/docker.sock", "/build"):
    assert not Path(path).exists(), path
assert Path("/agent").is_dir()
assert os.statvfs("/agent").f_flag & os.ST_RDONLY
assert Path("/run/secrets/model_api_key").is_file()
print("installed agent isolation probe passed")
