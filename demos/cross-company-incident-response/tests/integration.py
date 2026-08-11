from __future__ import annotations

import json
import os
import urllib.request


AGENT = os.environ.get("AUTHS_INCIDENT_AGENT_API", "http://localhost:7103")


def get(path: str) -> dict:
    with urllib.request.urlopen(f"{AGENT}{path}", timeout=15) as response:
        return json.loads(response.read())


def post(path: str) -> dict:
    request = urllib.request.Request(
        f"{AGENT}{path}",
        data=b"{}",
        method="POST",
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read())


assert get("/healthz")["status"] == "ok"
assert get("/api/proposal")["executionAuthority"] is False
fixture = get("/api/fixture")
assert fixture["python"]["code"] == "verifier-configuration-mismatch"
for attack in (
    "scope-expansion",
    "byte-mutation",
    "replay",
    "expired",
    "compromised-approver",
    "unauthorized-iroh",
    "remote-before",
    "remote-after",
    "remote-unknown",
    "withdraw-approval",
):
    result = post(f"/api/attack/{attack}")
    assert result["blocked"] is True, result

iroh = post("/api/attack/unauthorized-iroh")
assert iroh["evidence"]["transport"]["delivered"] is True
assert iroh["evidence"]["transport"]["authorizationEvaluated"] is False
print("auths-incident-demo integration passed")
