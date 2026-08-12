from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor


AGENT = os.environ.get("AUTHS_INCIDENT_AGENT_API", "http://localhost:7103")


def get(path: str) -> dict:
    with urllib.request.urlopen(f"{AGENT}{path}", timeout=15) as response:
        return json.loads(response.read())


def post(path: str, payload: dict | None = None) -> dict:
    request = urllib.request.Request(
        f"{AGENT}{path}",
        data=json.dumps(payload or {}, separators=(",", ":"), sort_keys=True).encode(),
        method="POST",
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            result = json.loads(response.read())
            result["httpStatus"] = response.status
            return result
    except urllib.error.HTTPError as error:
        result = json.loads(error.read())
        result["httpStatus"] = error.code
        return result


assert get("/healthz")["status"] == "ok"
assert get("/api/proposal")["executionAuthority"] is False
fixture = get("/api/fixture")
assert fixture["python"]["code"] == "verifier-configuration-mismatch"
post("/api/reset")
executed = post(
    "/api/workflow/execute",
    {"incidentId": "INC-2026-0811", "transport": "https"},
)
assert executed.get("kind") == "executed", executed
assert executed["httpStatus"] == 200
assert len(executed["receipts"]) == 2
assert all(value["stateClaim"] == "committed" for value in executed["receipts"])
state = get("/api/state")
assert state["counters"] == {"credential_acquisitions": 2, "provider_calls": 2}
assert len(state["executions"]) == 2
replayed = post(
    "/api/workflow/execute",
    {"incidentId": "INC-2026-0811", "transport": "https"},
)
assert replayed["httpStatus"] == 409, replayed
assert get("/api/state")["counters"] == state["counters"]

post("/api/reset")
with ThreadPoolExecutor(max_workers=2) as executor:
    concurrent = tuple(
        executor.map(
            lambda _: post(
                "/api/workflow/execute",
                {"incidentId": "INC-2026-0811", "transport": "https"},
            ),
            range(2),
        )
    )
assert sum(value.get("kind") == "executed" for value in concurrent) == 1, concurrent
assert get("/api/state")["counters"] == {
    "credential_acquisitions": 2,
    "provider_calls": 2,
}
attack_results = {}
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
    assert result.get("blocked") is True, {"attack": attack, "result": result}
    attack_results[attack] = result

unknown = attack_results["remote-unknown"]
assert unknown["effectBoundary"] == {
    "credentialAcquisitions": 1,
    "providerCalls": 1,
}
assert unknown["evidence"]["state"] == "outcome-unknown"
assert unknown["evidence"]["reconciledState"] == "reconciled-committed"
assert unknown["evidence"]["retryCredentialAcquisitions"] == 0
assert unknown["evidence"]["retryProviderCalls"] == 0

iroh = post("/api/attack/unauthorized-iroh")
assert iroh["evidence"]["transport"]["delivered"] is True
assert iroh["evidence"]["transport"]["authorizationEvaluated"] is False
print("auths-incident-demo integration passed")
