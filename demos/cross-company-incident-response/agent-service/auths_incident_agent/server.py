from __future__ import annotations

import asyncio
import json
import os
import sys
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Literal

from auths._application_profile import ApplicationGatewayError
from auths._workflow import AuthsWorkflowError
from auths.testkit import DevelopmentReceiptAttestor

from . import sdk
from .approval_adapters import verify_oidc_token
from .custody import ProcessEd25519Signer
from .execution import SqliteExecutionStore
from .incident import execute_incident_plan


SCHEMA = "auths-incident-demo/3"
INCIDENT = "INC-2026-0811"
REGION = "eu-west-2"
_configured_repo_root = os.environ.get("AUTHS_REPO_ROOT")
REPO_ROOT = (
    Path(_configured_repo_root)
    if _configured_repo_root
    else Path(__file__).resolve().parents[4]
)
STATE_PATH = Path(
    os.environ.get("AGENT_STATE_PATH", "/tmp/auths-incident-demo/agent-v3.sqlite3")
)
NORTHSTAR_URL = os.environ.get("NORTHSTAR_URL", "http://localhost:7101")
EDGESHIELD_URL = os.environ.get("EDGESHIELD_URL", "http://localhost:7102")
ALLOWED_ORIGIN = os.environ.get(
    "AUTHS_INCIDENT_ALLOWED_ORIGIN", "http://localhost:7100"
)
SERVICE_TOKEN = os.environ.get("AUTHS_INCIDENT_SERVICE_TOKEN", "")
CERT_FINGERPRINT = os.environ.get(
    "EDGESHIELD_CLIENT_CERT_FINGERPRINT",
    "local-client-certificate-fingerprint",
)
STORE = SqliteExecutionStore(STATE_PATH)
ROOT_SIGNER = ProcessEd25519Signer()
AGENT_SIGNER = ProcessEd25519Signer()
RECEIPT_ATTESTOR = DevelopmentReceiptAttestor()


def post_json(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(),
        method="POST",
        headers={"content-type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def get_json(url: str) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=10) as response:
        value = json.loads(response.read())
    return value if type(value) is dict else {}


def edge_headers() -> dict[str, str]:
    return {"x-auths-client-cert-sha256": CERT_FINGERPRINT}


def internal_headers() -> dict[str, str]:
    return {} if not SERVICE_TOKEN else {"authorization": f"Bearer {SERVICE_TOKEN}"}


def state_payload(mode: Literal["opaque", "summary", "full"]) -> dict[str, Any]:
    try:
        northstar = get_json(f"{NORTHSTAR_URL}/api/actors")
        edgeshield = get_json(f"{EDGESHIELD_URL}/api/actors")
        evidence = get_json(f"{NORTHSTAR_URL}/api/evidence")
    except Exception:
        northstar, edgeshield, evidence = {"actors": []}, {"actors": []}, {}
    snapshot = STORE.snapshot()
    executions = snapshot["executions"]
    committed = sum(value["state"] == "committed" for value in executions)
    return {
        "schema": SCHEMA,
        "incident": {
            "id": INCIDENT,
            "tenant": "northstar-fashion",
            "region": REGION,
            "status": "mitigated" if committed == 2 else "active",
        },
        "identityProvider": NORTHSTAR_URL,
        "receiptView": mode,
        "actors": [*northstar.get("actors", []), *edgeshield.get("actors", [])],
        "evidence": evidence,
        "executions": [
            {
                key: value[key]
                for key in (
                    "idempotencyKey",
                    "commandCommitment",
                    "authorityCommitment",
                    "contextCommitment",
                    "planCommitment",
                    "memberIndex",
                    "memberCount",
                    "state",
                    "outcome",
                    "observedAt",
                    "completedAt",
                )
            }
            for value in executions
        ],
        "receipts": STORE.receipt_views(mode),
        "counters": snapshot["counters"],
        "timeline": snapshot["timeline"],
    }


def viewer_mode(
    authorization: str | None,
) -> Literal["opaque", "summary", "full"]:
    if authorization is None or not authorization.startswith("Bearer "):
        return "opaque"
    try:
        claims = verify_oidc_token(
            authorization[7:],
            get_json(f"{NORTHSTAR_URL}/jwks.json"),
            issuer=NORTHSTAR_URL,
            audience="auths-incident-control-room",
            subjects=("northstar-commander", "northstar-security"),
        )
    except Exception:
        return "opaque"
    return "full" if claims["sub"] == "northstar-security" else "summary"


def execute_workflow(payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    if payload.get("incidentId") != INCIDENT:
        return HTTPStatus.BAD_REQUEST, {
            "schema": SCHEMA,
            "code": "closed-incident-mismatch",
        }
    transport = payload.get("transport", "https")
    if transport not in ("https", "iroh"):
        return HTTPStatus.BAD_REQUEST, {
            "schema": SCHEMA,
            "code": "unsupported-transport",
        }
    if transport == "iroh":
        envelope = json.dumps(
            {"incidentId": INCIDENT, "operation": "execute-closed-plan"},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        status, delivery = post_json(
            f"{EDGESHIELD_URL}/api/iroh/exchange",
            {"envelopeHex": envelope.hex()},
        )
        if status != HTTPStatus.OK:
            return status, delivery
    try:
        result = asyncio.run(
            execute_incident_plan(
                store=STORE,
                northstar_url=NORTHSTAR_URL,
                edgeshield_url=EDGESHIELD_URL,
                service_token=SERVICE_TOKEN,
                certificate_fingerprint=CERT_FINGERPRINT,
                root_signer=ROOT_SIGNER,
                agent_signer=AGENT_SIGNER,
                receipt_attestor=RECEIPT_ATTESTOR,
            )
        )
        return HTTPStatus.OK, {
            "schema": SCHEMA,
            "requestTransport": transport,
            **result,
        }
    except ApplicationGatewayError as error:
        return HTTPStatus.CONFLICT, {
            "schema": SCHEMA,
            "code": error.code,
            "outcome": error.receipt.outcome,
            "stateClaim": error.receipt.state_claim,
            "completed": len(error.completed_receipts),
        }
    except AuthsWorkflowError as error:
        status = {
            "gateway-exact-replay": HTTPStatus.CONFLICT,
            "gateway-conflict": HTTPStatus.CONFLICT,
            "gateway-out-of-order": HTTPStatus.CONFLICT,
            "gateway-expired": HTTPStatus.GONE,
            "gateway-unavailable": HTTPStatus.SERVICE_UNAVAILABLE,
        }.get(error.code, HTTPStatus.FORBIDDEN)
        return status, {
            "schema": SCHEMA,
            "code": error.code,
            "stage": error.stage,
            "effectState": error.effect_state,
        }


def reset_demo() -> None:
    for service, status in (
        (
            "northstar",
            post_json(f"{NORTHSTAR_URL}/api/reset", {}, internal_headers())[0],
        ),
        (
            "edgeshield",
            post_json(f"{EDGESHIELD_URL}/api/reset", {}, edge_headers())[0],
        ),
    ):
        if status != HTTPStatus.OK:
            raise RuntimeError(f"{service} reset failed")
    STORE.reset()


class Handler(BaseHTTPRequestHandler):
    server_version = "auths-incident-demo-agent/3"

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self._headers()
        self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/healthz":
            return self.respond(
                HTTPStatus.OK,
                {"schema": SCHEMA, "status": "ok", "service": "agent"},
            )
        if self.path == "/api/fixture":
            return self.respond(HTTPStatus.OK, sdk.portable_fixture(REPO_ROOT))
        if self.path == "/api/state":
            return self.respond(
                HTTPStatus.OK,
                state_payload(viewer_mode(self.headers.get("authorization"))),
            )
        if self.path == "/api/proposal":
            return self.respond(
                HTTPStatus.OK,
                {
                    "schema": SCHEMA,
                    "diagnosticAuthority": "read-only metrics/logs for northstar-fashion/eu-west-2",
                    "executionAuthority": False,
                    "cause": "stale cache deny metadata and firewall revision 184 conflict",
                    "plan": [
                        {
                            "id": "firewall-eu-west-2",
                            "command": "apply-config",
                            "transport": "https",
                            "exact": "allow checkout signed-assets in eu-west-2",
                        },
                        {
                            "id": "cache-eu-west-2",
                            "command": "execute",
                            "transport": "iroh",
                            "exact": "purge tenant northstar-fashion generation 991 in eu-west-2",
                        },
                    ],
                },
            )
        if self.path == "/api/receipts":
            mode = viewer_mode(self.headers.get("authorization"))
            return self.respond(
                HTTPStatus.OK,
                {
                    "schema": SCHEMA,
                    "mode": mode,
                    "receipts": STORE.receipt_views(mode),
                },
            )
        return self.respond(
            HTTPStatus.NOT_FOUND, {"schema": SCHEMA, "code": "not-found"}
        )

    def do_POST(self) -> None:
        try:
            payload = self.read_json()
            if self.path == "/api/workflow/execute":
                status, result = execute_workflow(payload)
                return self.respond(status, result)
            if self.path == "/api/reset":
                reset_demo()
                return self.respond(HTTPStatus.OK, {"schema": SCHEMA, "reset": True})
            if self.path.startswith("/api/attack/"):
                return self.respond(
                    HTTPStatus.OK, self.attack(self.path.rsplit("/", 1)[-1])
                )
            return self.respond(
                HTTPStatus.NOT_FOUND, {"schema": SCHEMA, "code": "not-found"}
            )
        except ValueError as error:
            return self.respond(
                HTTPStatus.BAD_REQUEST,
                {"schema": SCHEMA, "code": "invalid-request", "detail": str(error)},
            )
        except Exception as error:
            sys.stderr.write(f"agent request failed: {type(error).__name__}: {error}\n")
            return self.respond(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"schema": SCHEMA, "code": "agent-internal"},
            )

    def attack(self, attack: str) -> dict[str, Any]:
        if attack == "remote-unknown":
            return self.unknown_outcome_attack()
        before = STORE.snapshot()["counters"]
        if attack == "scope-expansion":
            result = sdk.scope_attack()
        elif attack == "byte-mutation":
            result = sdk.mutation_attack(REPO_ROOT)
        elif attack == "replay":
            result = sdk.replay_attack()
        elif attack == "expired":
            result = sdk.expired_attack()
        elif attack == "compromised-approver":
            result = sdk.compromise_attack()
        elif attack == "rotate-key":
            actors = get_json(f"{EDGESHIELD_URL}/api/actors")
            previous = actors["rotation"]["current"]
            status, rotated = post_json(
                f"{EDGESHIELD_URL}/api/key/rotate", {}, edge_headers()
            )
            if status != HTTPStatus.OK:
                raise RuntimeError("rotation failed")
            result = sdk.rotation_attack(previous, rotated["current"]["principal"])
        elif attack == "unauthorized-iroh":
            delivery_status, delivery = post_json(
                f"{EDGESHIELD_URL}/api/iroh/exchange",
                {"envelopeHex": b'{"authorized":false}'.hex()},
            )
            result = sdk.mutation_attack(REPO_ROOT)
            result.update(
                {
                    "attack": "unauthorized-iroh",
                    "code": "delivered-but-unauthorized",
                    "detail": "Iroh delivered bytes, but no opaque command reached the effect gateway.",
                    "evidence": {
                        "deliveryStatus": delivery_status,
                        "transport": delivery,
                        "authorization": result["evidence"],
                    },
                }
            )
        elif attack in ("remote-before", "remote-after"):
            result = sdk.remote_failure_attack(attack.removeprefix("remote-"))
        elif attack == "withdraw-approval":
            result = sdk.withdrawal_attack()
        else:
            raise ValueError("unknown closed attack case")
        after = STORE.snapshot()["counters"]
        result["effectBoundary"] = {
            "credentialAcquisitions": after["credential_acquisitions"]
            - before["credential_acquisitions"],
            "providerCalls": after["provider_calls"] - before["provider_calls"],
        }
        result["blocked"] = result.get("blocked") is True and result[
            "effectBoundary"
        ] == {
            "credentialAcquisitions": 0,
            "providerCalls": 0,
        }
        return result

    def unknown_outcome_attack(self) -> dict[str, Any]:
        reset_demo()
        try:
            asyncio.run(
                execute_incident_plan(
                    store=STORE,
                    northstar_url=NORTHSTAR_URL,
                    edgeshield_url=EDGESHIELD_URL,
                    service_token=SERVICE_TOKEN,
                    certificate_fingerprint=CERT_FINGERPRINT,
                    root_signer=ROOT_SIGNER,
                    agent_signer=AGENT_SIGNER,
                    receipt_attestor=RECEIPT_ATTESTOR,
                    provider_fault="unknown-after-firewall",
                )
            )
        except ApplicationGatewayError as error:
            first = error
        else:
            return {
                "attack": "remote-unknown",
                "blocked": False,
                "code": "unexpected-success",
            }
        before_retry = STORE.snapshot()["counters"]
        try:
            asyncio.run(
                execute_incident_plan(
                    store=STORE,
                    northstar_url=NORTHSTAR_URL,
                    edgeshield_url=EDGESHIELD_URL,
                    service_token=SERVICE_TOKEN,
                    certificate_fingerprint=CERT_FINGERPRINT,
                    root_signer=ROOT_SIGNER,
                    agent_signer=AGENT_SIGNER,
                    receipt_attestor=RECEIPT_ATTESTOR,
                )
            )
        except AuthsWorkflowError as error:
            retry_code = error.code
        else:
            retry_code = "unexpected-success"
        snapshot = STORE.snapshot()
        counters = snapshot["counters"]
        unknown = [
            value
            for value in snapshot["executions"]
            if value["state"] == "outcome-unknown"
        ]
        reconciled = (
            STORE.reconcile(unknown[0]["idempotencyKey"], "effect")
            if len(unknown) == 1
            else "missing"
        )
        retry_blocked = retry_code in (
            "gateway-conflict",
            "gateway-exact-replay",
        )
        no_retry_effect = counters == before_retry
        result = {
            "attack": "remote-unknown",
            "blocked": first.receipt.outcome == "outcome-unknown"
            and len(unknown) == 1
            and retry_blocked
            and no_retry_effect
            and reconciled == "reconciled-committed",
            "stage": "provider",
            "code": "provider-outcome-unknown",
            "detail": "The provider applied the firewall change, its response was lost, and Auths blocked retry pending reconciliation.",
            "effectBoundary": {
                "credentialAcquisitions": counters["credential_acquisitions"],
                "providerCalls": counters["provider_calls"],
            },
            "evidence": {
                "state": unknown[0]["state"] if unknown else "missing",
                "reconciledState": reconciled,
                "outcome": first.receipt.outcome,
                "retryCode": retry_code,
                "retryCredentialAcquisitions": counters["credential_acquisitions"]
                - before_retry["credential_acquisitions"],
                "retryProviderCalls": counters["provider_calls"]
                - before_retry["provider_calls"],
            },
        }
        reset_demo()
        return result

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("content-length", "0"))
        if length < 0 or length > 64 * 1024:
            raise ValueError("request body outside bounds")
        if length == 0:
            return {}
        value = json.loads(self.rfile.read(length))
        if type(value) is not dict:
            raise ValueError("request body must be an object")
        return value

    def respond(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(
            sdk.json_safe(payload), separators=(",", ":"), sort_keys=True
        ).encode()
        self.send_response(status)
        self._headers()
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _headers(self) -> None:
        self.send_header("access-control-allow-origin", ALLOWED_ORIGIN)
        self.send_header("access-control-allow-methods", "GET, POST, OPTIONS")
        self.send_header("access-control-allow-headers", "content-type, authorization")
        self.send_header("cache-control", "no-store")

    def log_message(self, format: str, *args: object) -> None:
        sys.stdout.write(f"agent {format % args}\n")


def main() -> None:
    port = int(os.environ.get("PORT", "7103"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"auths-incident-demo agent listening on http://0.0.0.0:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
