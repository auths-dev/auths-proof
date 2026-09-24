"""A Stripe-compatible counting double for ``POST /v1/refunds``.

It listens on 127.0.0.1 only, accepts exactly the form body the recipe sends
(``payment_intent`` and ``amount``), answers with a Stripe-shaped refund
object, and appends one line per request to a ledger so a test can count
provider entries. The expected secret is given as its SHA-256, so this
process never needs the key itself.

    python mock_stripe.py --ledger ledger.jsonl --token-sha256 HEX [--port 0]

The chosen port is printed on the first stdout line.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

MAX_BODY = 16_384


def serve(ledger: Path, token_sha256: str, port: int) -> ThreadingHTTPServer:
    lock = threading.Lock()
    expected = bytes.fromhex(token_sha256)
    sequence = [0]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_: object) -> None:
            return None

        def _reply(self, status: int, body: dict) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(min(length, MAX_BODY))
            header = self.headers.get("Authorization", "")
            token = header[len("Bearer ") :].encode() if header.startswith("Bearer ") else b""
            authorized = hmac.compare_digest(hashlib.sha256(token).digest(), expected)
            form = {
                key: values for key, values in parse_qs(body.decode("utf-8", "replace")).items()
            }
            well_formed = (
                self.path == "/v1/refunds"
                and self.headers.get("Content-Type") == "application/x-www-form-urlencoded"
                and sorted(form) == ["amount", "payment_intent"]
                and all(len(values) == 1 for values in form.values())
                and form["amount"][0].isdigit()
            )
            with lock:
                sequence[0] += 1
                entry = {
                    "sequence": sequence[0],
                    "path": self.path,
                    "authorized": authorized,
                    "well_formed": well_formed,
                    "payment_intent": form.get("payment_intent", [None])[0],
                    "amount": int(form["amount"][0]) if well_formed else None,
                }
                with ledger.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(entry) + "\n")
            if not authorized:
                self._reply(
                    401,
                    {
                        "error": {
                            "type": "invalid_request_error",
                            "message": "Invalid API Key provided",
                        }
                    },
                )
            elif not well_formed:
                self._reply(
                    400, {"error": {"type": "invalid_request_error", "message": "Malformed refund"}}
                )
            else:
                self._reply(
                    200,
                    {
                        "id": f"re_mock_{entry['sequence']:06d}",
                        "object": "refund",
                        "amount": entry["amount"],
                        "currency": "usd",
                        "payment_intent": entry["payment_intent"],
                        "status": "succeeded",
                    },
                )

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--token-sha256", required=True)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    args.ledger.touch()
    server = serve(args.ledger, args.token_sha256, args.port)
    print(server.server_address[1], flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
