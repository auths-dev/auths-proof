from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from . import sdk


SCHEMA = "auths-incident-demo/1"
INCIDENT = "INC-2026-0811"
REGION = "eu-west-2"
_configured_repo_root = os.environ.get("AUTHS_REPO_ROOT")
REPO_ROOT = (
    Path(_configured_repo_root)
    if _configured_repo_root
    else Path(__file__).resolve().parents[4]
)
STATE_PATH = Path(os.environ.get("AGENT_STATE_PATH", "/tmp/auths-incident-demo/agent.sqlite3"))
NORTHSTAR_URL = os.environ.get("NORTHSTAR_URL", "http://localhost:7101")
EDGESHIELD_URL = os.environ.get("EDGESHIELD_URL", "http://localhost:7102")
ALLOWED_ORIGIN = os.environ.get("AUTHS_INCIDENT_ALLOWED_ORIGIN", "http://localhost:7100")
SERVICE_TOKEN = os.environ.get("AUTHS_INCIDENT_SERVICE_TOKEN", "")
CERT_FINGERPRINT = os.environ.get(
    "EDGESHIELD_CLIENT_CERT_FINGERPRINT", "local-client-certificate-fingerprint"
)


def database() -> sqlite3.Connection:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(STATE_PATH)
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS plans (
          commitment TEXT PRIMARY KEY,
          northstar_approved INTEGER NOT NULL DEFAULT 0,
          edgeshield_approved INTEGER NOT NULL DEFAULT 0,
          ticket TEXT,
          created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS executions (
          operation TEXT PRIMARY KEY,
          commitment TEXT NOT NULL,
          idempotency_key TEXT NOT NULL,
          outcome TEXT NOT NULL,
          receipt TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS timeline (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          at INTEGER NOT NULL,
          company TEXT NOT NULL,
          kind TEXT NOT NULL,
          detail TEXT NOT NULL
        );
        """
    )
    return connection


def post_json(url: str, payload: dict[str, Any], headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
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
        return json.loads(response.read())


def edge_headers() -> dict[str, str]:
    return {"x-auths-client-cert-sha256": CERT_FINGERPRINT}


def internal_headers() -> dict[str, str]:
    return {} if not SERVICE_TOKEN else {"authorization": f"Bearer {SERVICE_TOKEN}"}


def plan_row(commitment: str) -> sqlite3.Row | None:
    with database() as connection:
        return connection.execute(
            "SELECT * FROM plans WHERE commitment = ?", (commitment,)
        ).fetchone()


def record_approval(commitment: str, company: str) -> dict[str, Any]:
    if len(commitment) != 64:
        raise ValueError("plan commitment must be a 32-byte lowercase hex digest")
    with database() as connection:
        connection.execute(
            "INSERT OR IGNORE INTO plans(commitment, created_at) VALUES (?, ?)",
            (commitment, int(time.time())),
        )
        column = "northstar_approved" if company == "northstar" else "edgeshield_approved"
        connection.execute(f"UPDATE plans SET {column} = 1 WHERE commitment = ?", (commitment,))
        row = connection.execute("SELECT * FROM plans WHERE commitment = ?", (commitment,)).fetchone()
        if row["northstar_approved"] and row["edgeshield_approved"] and not row["ticket"]:
            ticket = secrets.token_urlsafe(32)
            connection.execute("UPDATE plans SET ticket = ? WHERE commitment = ?", (ticket, commitment))
        row = connection.execute("SELECT * FROM plans WHERE commitment = ?", (commitment,)).fetchone()
        connection.execute(
            "INSERT INTO timeline(at, company, kind, detail) VALUES (?, ?, ?, ?)",
            (int(time.time()), company, "approval", f"{company} approved plan {commitment[:12]}"),
        )
        return dict(row)


def execute_operation(payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    operation = str(payload.get("operation", ""))
    commitment = str(payload.get("planCommitment", ""))
    ticket = str(payload.get("ticket", ""))
    idempotency_key = str(payload.get("idempotencyKey", ""))
    if operation not in ("firewall-eu-west-2", "cache-eu-west-2"):
        return HTTPStatus.FORBIDDEN, {"schema": SCHEMA, "code": "closed-operation-mismatch"}
    row = plan_row(commitment)
    if row is None or not row["northstar_approved"] or not row["edgeshield_approved"] or not secrets.compare_digest(str(row["ticket"] or ""), ticket):
        return HTTPStatus.FORBIDDEN, {"schema": SCHEMA, "code": "threshold-approval-required"}
    with database() as connection:
        existing = connection.execute("SELECT receipt FROM executions WHERE operation = ?", (operation,)).fetchone()
        if existing is not None:
            receipt = json.loads(existing["receipt"])
            return HTTPStatus.CONFLICT, {**receipt, "code": "exact-replay", "replayed": True}

    if operation == "firewall-eu-west-2":
        transport = {"family": "https", "authorizationEvaluated": False}
        status, provider = post_json(
            f"{NORTHSTAR_URL}/api/firewall/apply",
            {"incidentId": INCIDENT, "region": REGION, "operation": "apply-config"},
            internal_headers(),
        )
    else:
        envelope = json.dumps(
            {
                "schema": SCHEMA,
                "incidentId": INCIDENT,
                "region": REGION,
                "operation": "execute",
                "planCommitment": commitment,
                "idempotencyKey": idempotency_key,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        delivery_status, transport = post_json(
            f"{EDGESHIELD_URL}/api/iroh/exchange", {"envelope": envelope}
        )
        if delivery_status != 200:
            return delivery_status, transport
        status, provider = post_json(
            f"{EDGESHIELD_URL}/api/cache/purge",
            {"incidentId": INCIDENT, "region": REGION, "operation": "execute"},
            edge_headers(),
        )
    outcome = "executed" if status == 200 else "failed"
    receipt = {
        "schema": SCHEMA,
        "receiptId": hashlib.sha256(f"{commitment}:{operation}".encode()).hexdigest(),
        "operation": operation,
        "planCommitment": commitment,
        "idempotencyKey": idempotency_key,
        "authority": {"region": REGION, "expiresInSeconds": 600, "uses": 1},
        "transport": transport,
        "provider": provider,
        "outcome": outcome,
        "observedAt": int(time.time()),
        "verifiable": True,
    }
    with database() as connection:
        connection.execute(
            "INSERT INTO executions(operation, commitment, idempotency_key, outcome, receipt, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (operation, commitment, idempotency_key, outcome, json.dumps(receipt), int(time.time())),
        )
        connection.execute(
            "INSERT INTO timeline(at, company, kind, detail) VALUES (?, ?, ?, ?)",
            (
                int(time.time()),
                "northstar" if operation.startswith("firewall") else "edgeshield",
                "execution",
                f"{operation} {outcome}",
            ),
        )
    return status, receipt


class Handler(BaseHTTPRequestHandler):
    server_version = "auths-incident-demo-agent/1"

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self._headers()
        self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/healthz":
            return self.respond(HTTPStatus.OK, {"schema": SCHEMA, "status": "ok", "service": "agent"})
        if self.path == "/api/fixture":
            return self.respond(HTTPStatus.OK, sdk.portable_fixture(REPO_ROOT))
        if self.path == "/api/state":
            try:
                northstar = get_json(f"{NORTHSTAR_URL}/api/actors")
                edgeshield = get_json(f"{EDGESHIELD_URL}/api/actors")
                evidence = get_json(f"{NORTHSTAR_URL}/api/evidence")
            except Exception:
                northstar, edgeshield, evidence = {"actors": []}, {"actors": []}, {}
            with database() as connection:
                receipts = [json.loads(row["receipt"]) for row in connection.execute("SELECT receipt FROM executions ORDER BY created_at")]
                timeline = [dict(row) for row in connection.execute("SELECT * FROM timeline ORDER BY id")]
            return self.respond(
                HTTPStatus.OK,
                {
                    "schema": SCHEMA,
                    "incident": {
                        "id": INCIDENT,
                        "tenant": "northstar-fashion",
                        "region": REGION,
                        "status": "mitigated" if len(receipts) == 2 else "active",
                    },
                    "actors": [*northstar.get("actors", []), *edgeshield.get("actors", [])],
                    "evidence": evidence,
                    "receipts": receipts,
                    "timeline": timeline,
                },
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
                        {"id": "firewall-eu-west-2", "command": "apply-config", "transport": "https", "exact": "allow checkout signed-assets in eu-west-2"},
                        {"id": "cache-eu-west-2", "command": "execute", "transport": "iroh", "exact": "purge tenant northstar-fashion generation 991 in eu-west-2"},
                    ],
                },
            )
        if self.path == "/api/receipts":
            with database() as connection:
                receipts = [json.loads(row["receipt"]) for row in connection.execute("SELECT receipt FROM executions ORDER BY created_at")]
            return self.respond(HTTPStatus.OK, {"schema": SCHEMA, "receipts": receipts})
        return self.respond(HTTPStatus.NOT_FOUND, {"schema": SCHEMA, "code": "not-found"})

    def do_POST(self) -> None:
        try:
            payload = self.read_json()
            if self.path == "/api/approval/northstar":
                status, result = post_json(f"{NORTHSTAR_URL}/api/approve", payload)
                if status == 200 and payload.get("objectKind") == "action":
                    result["plan"] = record_approval(str(payload.get("planCommitment", "")), "northstar")
                return self.respond(status, result)
            if self.path == "/api/approval/edgeshield":
                status, result = post_json(f"{EDGESHIELD_URL}/api/approve", payload, edge_headers())
                if status == 200 and payload.get("objectKind") == "action":
                    result["plan"] = record_approval(str(payload.get("planCommitment", "")), "edgeshield")
                return self.respond(status, result)
            if self.path == "/api/plan/ticket":
                row = plan_row(str(payload.get("planCommitment", "")))
                if row is None or not row["ticket"]:
                    return self.respond(HTTPStatus.FORBIDDEN, {"schema": SCHEMA, "code": "threshold-approval-required"})
                return self.respond(HTTPStatus.OK, {"schema": SCHEMA, "ticket": row["ticket"]})
            if self.path == "/api/execute":
                status, result = execute_operation(payload)
                return self.respond(status, result)
            if self.path == "/api/reset":
                with database() as connection:
                    connection.execute("DELETE FROM executions")
                    connection.execute("DELETE FROM plans")
                    connection.execute("DELETE FROM timeline")
                post_json(f"{NORTHSTAR_URL}/api/reset", {}, internal_headers())
                post_json(f"{EDGESHIELD_URL}/api/reset", {}, edge_headers())
                return self.respond(HTTPStatus.OK, {"schema": SCHEMA, "reset": True})
            if self.path.startswith("/api/attack/"):
                attack = self.path.rsplit("/", 1)[-1]
                return self.respond(HTTPStatus.OK, self.attack(attack))
            return self.respond(HTTPStatus.NOT_FOUND, {"schema": SCHEMA, "code": "not-found"})
        except ValueError as error:
            return self.respond(HTTPStatus.BAD_REQUEST, {"schema": SCHEMA, "code": "invalid-request", "detail": str(error)})
        except Exception as error:
            sys.stderr.write(f"agent request failed: {type(error).__name__}\n")
            return self.respond(HTTPStatus.INTERNAL_SERVER_ERROR, {"schema": SCHEMA, "code": "agent-internal"})

    def attack(self, attack: str) -> dict[str, Any]:
        if attack == "scope-expansion":
            return sdk.scope_attack()
        if attack == "byte-mutation":
            return sdk.mutation_attack(REPO_ROOT)
        if attack == "replay":
            return sdk.replay_attack()
        if attack == "expired":
            return sdk.expired_attack()
        if attack == "compromised-approver":
            return sdk.compromise_attack()
        if attack == "rotate-key":
            before = get_json(f"{EDGESHIELD_URL}/api/actors")["rotation"]["current"]
            status, rotated = post_json(f"{EDGESHIELD_URL}/api/key/rotate", {}, edge_headers())
            if status != 200:
                raise RuntimeError("rotation failed")
            return sdk.rotation_attack(before, rotated["current"]["principal"])
        if attack == "unauthorized-iroh":
            delivery_status, delivery = post_json(
                f"{EDGESHIELD_URL}/api/iroh/exchange",
                {"envelope": json.dumps({"authorized": False, "operation": "cache-purge"})},
            )
            denied = sdk.mutation_attack(REPO_ROOT)
            denied.update(
                {
                    "attack": "unauthorized-iroh",
                    "stage": "authority",
                    "code": "delivered-but-unauthorized",
                    "detail": "Iroh delivered the bytes successfully; Auths still denied the mutated action.",
                    "evidence": {"deliveryStatus": delivery_status, "transport": delivery, "authorization": denied["evidence"]},
                }
            )
            return denied
        if attack in ("remote-before", "remote-after", "remote-unknown"):
            return sdk.remote_failure_attack(attack.removeprefix("remote-"))
        if attack == "withdraw-approval":
            return sdk.withdrawal_attack()
        raise ValueError("unknown closed attack case")

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("content-length", "0"))
        if length < 0 or length > 64 * 1024:
            raise ValueError("request body outside bounds")
        if length == 0:
            return {}
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict):
            raise ValueError("request body must be an object")
        return value

    def respond(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(sdk.json_safe(payload), separators=(",", ":")).encode()
        self.send_response(status)
        self._headers()
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _headers(self) -> None:
        self.send_header("access-control-allow-origin", ALLOWED_ORIGIN)
        self.send_header("access-control-allow-methods", "GET, POST, OPTIONS")
        self.send_header("access-control-allow-headers", "content-type")
        self.send_header("cache-control", "no-store")

    def log_message(self, format: str, *args: object) -> None:
        sys.stdout.write(f"agent {format % args}\n")


def main() -> None:
    port = int(os.environ.get("PORT", "7103"))
    database().close()
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"auths-incident-demo agent listening on http://0.0.0.0:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
