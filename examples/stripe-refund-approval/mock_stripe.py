"""A Stripe-compatible counting double for the refund recipe.

It listens on 127.0.0.1 only and answers every request the recipe makes:

- ``GET /v1/balance`` (``livemode: false``) and ``GET /v1/account`` (the
  platform account), which the gateway reads to test the key;
- ``GET /v1/customers`` and ``GET /v1/payouts``, refused with 403 as Stripe
  refuses a restricted key without those permissions;
- ``GET /v1/payment_intents/<id>``, ``POST /v1/refunds``, and
  ``GET /v1/refunds/<id>`` in the connected account that ``Stripe-Account``
  names.

Like Stripe, it requires ``Stripe-Version`` on every request (400 without
it) and echoes it on every response; it keeps PaymentIntents and refunds per
connected account, so a request without ``Stripe-Account`` or for another
account finds none; it stores refund metadata and returns it on the refund
and its read-back; it refuses a refund of a PaymentIntent it does not hold
(``400 resource_missing``) or whose charge is already fully refunded
(``400 charge_already_refunded``); and it keeps the response to an
authorized, well-formed refund under the request's ``Idempotency-Key``. A
later request with the same key and parameters gets that response back
instead of creating a second refund; the same key with other parameters is
refused. Stored responses last only as long as this process.

It appends one ledger line per request, so a test can count provider reads
and writes, and it reads ``--control`` (JSON, optional) on every request so a
test can make it misbehave: ``{"account": "acct_..."}`` reports another
account at ``/v1/account``, and ``{"denied_status": 200}`` answers the
denied reads with that status. The expected secret is given as its SHA-256,
so this process never needs the key itself.

    python mock_stripe.py --ledger ledger.jsonl --token-sha256 HEX \\
        [--control control.json] [--payment-intent pi_mock_journey] [--port 0]

The chosen port is printed on the first stdout line.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs

MAX_BODY = 16_384
STRIPE_VERSION = "2025-03-31.basil"
PLATFORM_ACCOUNT = "acct_1AuthsPlatform0"
CONNECTED_ACCOUNT = "acct_1AuthsConnected"
# A PaymentIntent the connected account holds whose charge is already fully
# refunded: its amount received still counts toward the ratio, but Stripe
# refuses another refund of it.
REFUNDED_PAYMENT_INTENT = "pi_mock_refunded"
METADATA_KEY = re.compile(r"^metadata\[([A-Za-z0-9_.-]{1,40})\]$")


def _error(kind: str, message: str, code: Optional[str] = None) -> Dict[str, Any]:
    error: Dict[str, Any] = {"type": kind, "message": message}
    if code is not None:
        error["code"] = code
    return {"error": error}


def serve(
    ledger: Path, token_sha256: str, port: int, payment_intent: str, control: Optional[Path]
) -> ThreadingHTTPServer:
    lock = threading.Lock()
    expected = bytes.fromhex(token_sha256)
    sequence = [0]
    # Connected account -> PaymentIntent id -> [amount received, currency,
    # amount refunded].
    intents: Dict[str, Dict[str, List[Any]]] = {
        CONNECTED_ACCOUNT: {
            payment_intent: [6_000, "usd", 0],
            REFUNDED_PAYMENT_INTENT: [10_000, "usd", 10_000],
        }
    }
    refunds: Dict[str, Dict[str, Dict[str, Any]]] = {CONNECTED_ACCOUNT: {}}
    # Idempotency-Key -> (request parameters, the response first returned).
    stored: Dict[str, Tuple[Any, Dict[str, Any]]] = {}

    def controls() -> Dict[str, Any]:
        if control is None or not control.exists():
            return {}
        return json.loads(control.read_text())

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_: object) -> None:
            return None

        def _reply(self, status: int, body: dict, replayed: bool = False) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            version = self.headers.get("Stripe-Version")
            if version is not None:
                self.send_header("Stripe-Version", version)
            if replayed:
                self.send_header("Idempotent-Replayed", "true")
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self) -> bool:
            header = self.headers.get("Authorization", "")
            token = header[len("Bearer ") :].encode() if header.startswith("Bearer ") else b""
            return hmac.compare_digest(hashlib.sha256(token).digest(), expected)

        def _record(self, entry: Dict[str, Any]) -> None:
            with ledger.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")

        def _handle(self, method: str) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(min(length, MAX_BODY)) if length else b""
            account = self.headers.get("Stripe-Account")
            version = self.headers.get("Stripe-Version")
            authorized = self._authorized()
            write = method == "POST" and self.path == "/v1/refunds"
            entry: Dict[str, Any] = {
                "method": method,
                "path": self.path,
                "kind": "write" if write else "read",
                "authorized": authorized,
                "stripe_version": version,
                "stripe_account": account,
            }
            with lock:
                sequence[0] += 1
                entry["sequence"] = sequence[0]
                if write:
                    status, answer, replayed = self._refund(body, account, entry)
                else:
                    status, answer, replayed = self._read(method, account)
                if not authorized:
                    status, answer, replayed = 401, _error(
                        "invalid_request_error", "Invalid API Key provided"
                    ), False
                elif version != STRIPE_VERSION:
                    status, answer, replayed = 400, _error(
                        "invalid_request_error", "Stripe-Version is required"
                    ), False
                entry["status"] = status
                self._record(entry)
            self._reply(status, answer, replayed)

        def _read(self, method: str, account: Optional[str]) -> Tuple[int, dict, bool]:
            if method != "GET":
                return 405, _error("invalid_request_error", "Unsupported method"), False
            settings = controls()
            if self.path == "/v1/balance" and account is None:
                return 200, {"object": "balance", "livemode": False, "available": []}, False
            if self.path == "/v1/account" and account is None:
                reported = settings.get("account", PLATFORM_ACCOUNT)
                return 200, {"id": reported, "object": "account"}, False
            if self.path in ("/v1/customers", "/v1/payouts"):
                status = int(settings.get("denied_status", 403))
                if 200 <= status < 300:
                    return status, {"object": "list", "data": [], "has_more": False}, False
                return status, _error(
                    "invalid_request_error",
                    "The provided key does not have the required permissions for this endpoint.",
                    "permission_error",
                ), False
            scope = intents.get(account or "")
            if scope is None:
                return 403, _error(
                    "invalid_request_error",
                    "The provided key does not have access to the account in Stripe-Account.",
                ), False
            if self.path.startswith("/v1/payment_intents/"):
                identifier = self.path[len("/v1/payment_intents/") :]
                held = scope.get(identifier)
                if held is None:
                    return 404, _error(
                        "invalid_request_error",
                        f"No such payment_intent: '{identifier}'",
                        "resource_missing",
                    ), False
                return 200, {
                    "id": identifier,
                    "object": "payment_intent",
                    "amount": held[0],
                    "amount_received": held[0],
                    "currency": held[1],
                    "livemode": False,
                    "status": "succeeded",
                }, False
            if self.path.startswith("/v1/refunds/"):
                refund = refunds[account or ""].get(self.path[len("/v1/refunds/") :])
                if refund is None:
                    return 404, _error(
                        "invalid_request_error", "No such refund", "resource_missing"
                    ), False
                return 200, refund, False
            return 404, _error("invalid_request_error", "Unrecognized request URL"), False

        def _refund(
            self, body: bytes, account: Optional[str], entry: Dict[str, Any]
        ) -> Tuple[int, dict, bool]:
            form = parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
            metadata = {
                match.group(1): values[0]
                for key, values in form.items()
                if (match := METADATA_KEY.match(key)) is not None
            }
            well_formed = (
                self.headers.get("Content-Type") == "application/x-www-form-urlencoded"
                and {"amount", "payment_intent"} <= set(form)
                and all(key in ("amount", "payment_intent") or METADATA_KEY.match(key) for key in form)
                and all(len(values) == 1 for values in form.values())
                and form["amount"][0].isdigit()
            )
            key: Optional[str] = self.headers.get("Idempotency-Key")
            entry.update(
                well_formed=well_formed,
                payment_intent=form.get("payment_intent", [None])[0],
                amount=int(form["amount"][0]) if well_formed else None,
                echo=metadata.get("auths_echo"),
                idempotency_key=key,
                replayed=False,
                refund=None,
            )
            if not (self._authorized() and self.headers.get("Stripe-Version") == STRIPE_VERSION):
                return 400, {}, False
            if not well_formed:
                return 400, _error("invalid_request_error", "Malformed refund"), False
            scope = intents.get(account or "")
            if scope is None:
                return 403, _error(
                    "invalid_request_error",
                    "The provided key does not have access to the account in Stripe-Account.",
                ), False
            parameters = (account, sorted(form.items()))
            previous = stored.get(key) if key is not None else None
            if previous is not None:
                if previous[0] != parameters:
                    return 400, _error(
                        "idempotency_error", "Idempotency-Key reused with different parameters"
                    ), False
                entry.update(replayed=True, refund=previous[1]["id"])
                return 200, previous[1], True
            identifier = form["payment_intent"][0]
            amount = int(form["amount"][0])
            held = scope.get(identifier)
            if held is None:
                return 400, _error(
                    "invalid_request_error",
                    f"No such payment_intent: '{identifier}'",
                    "resource_missing",
                ), False
            if held[2] >= held[0]:
                return 400, _error(
                    "invalid_request_error",
                    f"Charge for PaymentIntent {identifier} has already been refunded.",
                    "charge_already_refunded",
                ), False
            if held[2] + amount > held[0]:
                return 400, _error(
                    "invalid_request_error",
                    "Refund amount is greater than the unrefunded amount.",
                    "amount_too_large",
                ), False
            held[2] += amount
            created = sum(len(items) for items in refunds.values()) + 1
            refund = {
                "id": f"re_mock_{created:06d}",
                "object": "refund",
                "amount": amount,
                "currency": held[1],
                "payment_intent": identifier,
                "metadata": metadata,
                "status": "succeeded",
            }
            refunds[account or ""][refund["id"]] = refund
            if key is not None:
                stored[key] = (parameters, refund)
            entry["refund"] = refund["id"]
            return 200, refund, False

        def do_GET(self) -> None:
            self._handle("GET")

        def do_HEAD(self) -> None:
            self._handle("HEAD")

        def do_POST(self) -> None:
            self._handle("POST")

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--token-sha256", required=True)
    parser.add_argument("--control", type=Path)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--payment-intent", default="pi_mock_journey")
    args = parser.parse_args()
    args.ledger.touch()
    server = serve(args.ledger, args.token_sha256, args.port, args.payment_intent, args.control)
    print(server.server_address[1], flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
