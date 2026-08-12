from __future__ import annotations

import json
import os
import base64
import hashlib
import secrets
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor


AGENT = os.environ.get("AUTHS_INCIDENT_AGENT_API", "http://localhost:7103")
NORTHSTAR = os.environ.get("NORTHSTAR_URL", "http://localhost:7101")


def get(path: str, headers: dict[str, str] | None = None) -> dict:
    request = urllib.request.Request(f"{AGENT}{path}", headers=headers or {})
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


def viewer_token(subject: str) -> str:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    redirect_uri = "http://auths.local/control-room"
    oauth_state = secrets.token_urlsafe(24)
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": "auths-incident-control-room",
            "redirect_uri": redirect_uri,
            "scope": "openid profile",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": oauth_state,
            "login_hint": subject,
        }
    )
    try:
        urllib.request.build_opener(NoRedirect).open(
            f"{NORTHSTAR}/authorize?{query}", timeout=10
        )
    except urllib.error.HTTPError as error:
        assert error.code == 302
        location = error.headers["location"]
    else:
        raise AssertionError("OIDC provider omitted redirect")
    callback = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
    assert callback["state"] == [oauth_state]
    request = urllib.request.Request(
        f"{NORTHSTAR}/token",
        data=urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "client_id": "auths-incident-control-room",
                "redirect_uri": redirect_uri,
                "code": callback["code"][0],
                "code_verifier": verifier,
            }
        ).encode(),
        method="POST",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())["access_token"]


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
assert state["receiptView"] == "opaque"
assert all(receipt["kind"] == "verified-opaque" for receipt in state["receipts"])
public_receipts = json.dumps(state["receipts"])
assert "apply-config" not in public_receipts
assert "fw-185" not in public_receipts

operator = get(
    "/api/receipts",
    {"authorization": f"Bearer {viewer_token('northstar-commander')}"},
)
assert operator["mode"] == "summary"
assert all(receipt["kind"] == "verified-disclosed" for receipt in operator["receipts"])
operator_receipts = json.dumps(operator["receipts"])
assert "apply-config" in operator_receipts
assert "protected_disclosure" not in operator_receipts
assert '"disclosure"' not in operator_receipts
assert '"evidence"' not in operator_receipts

auditor = get(
    "/api/receipts",
    {"authorization": f"Bearer {viewer_token('northstar-security')}"},
)
assert auditor["mode"] == "full"
auditor_receipts = json.dumps(auditor["receipts"])
assert '"disclosure"' in auditor_receipts
assert '"evidence"' in auditor_receipts
assert "protected_disclosure" not in auditor_receipts

invalid_viewer = get("/api/receipts", {"authorization": "Bearer invalid.viewer.token"})
assert invalid_viewer["mode"] == "opaque"
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
