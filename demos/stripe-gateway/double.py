"""Counting platform-refund double. Never used as live or qualification evidence."""
import hashlib
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import threading
from urllib.parse import parse_qs

from demo_common import canonical, require

PLATFORM = 'acct_AuthsPlatformDemo'
VERSION = '2025-03-31.basil'


def serve(key_digest, ledger, *, port=0):
    lock = threading.Lock()
    payments = {f'pi_demo_{index:02}': {'amount_received': 2000, 'currency': 'usd', 'refunded': 0}
                for index in range(16)}
    refunds, idempotency = {}, {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, value):
            body = canonical(value)
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def handle_request(self, method):
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 <= length <= 16384:
                return self.reply(400, {'error': 'body-bound'})
            body = self.rfile.read(length)
            header = self.headers.get('Authorization', '')
            authorized = hmac.compare_digest(hashlib.sha256(header.removeprefix('Bearer ').encode()).hexdigest(), key_digest)
            if not authorized or not header.startswith('Bearer '):
                return self.reply(401, {'error': 'credential-refused'})
            if self.headers.get('Stripe-Version') != VERSION or self.headers.get('Stripe-Account'):
                return self.reply(400, {'error': 'wrong-contract'})
            status, value, drop = 404, {'error': 'missing-resource'}, False
            with lock:
                if method == 'GET':
                    if self.path == '/v1/balance':
                        status, value = 200, {'livemode': False}
                    elif self.path == '/v1/account':
                        status, value = 200, {'id': PLATFORM}
                    elif self.path in ('/v1/customers', '/v1/payouts'):
                        status, value = 403, {'error': 'restricted-key'}
                    elif self.path.startswith('/v1/payment_intents/'):
                        identifier = self.path.split('/')[-1]
                        if identifier in payments:
                            status, value = 200, {'id': identifier, 'livemode': False, **payments[identifier]}
                    elif self.path.startswith('/v1/refunds/'):
                        identifier = self.path.split('/')[-1]
                        if identifier in refunds:
                            status, value = 200, refunds[identifier]
                elif method == 'POST' and self.path == '/v1/refunds':
                    fields = parse_qs(body.decode(), strict_parsing=True)
                    required = {'amount', 'payment_intent', 'metadata[auths_echo]'}
                    key = self.headers.get('Idempotency-Key', '')
                    if set(fields) != required or any(len(v) != 1 for v in fields.values()) or not key.startswith('auths-i1-'):
                        status, value = 400, {'error': 'mapping-refused'}
                    elif key in idempotency:
                        previous, value = idempotency[key]
                        status = 200 if previous == body else 400
                    else:
                        identifier = fields['payment_intent'][0]
                        amount = int(fields['amount'][0])
                        if identifier not in payments or not 0 < amount <= 2000 - payments[identifier]['refunded']:
                            status, value = 400, {'error': 'refund-refused'}
                        else:
                            refund = 're_demo_' + str(len(refunds) + 1)
                            value = {'id': refund, 'object': 'refund', 'payment_intent': identifier,
                                     'amount': amount, 'currency': 'usd', 'status': 'succeeded',
                                     'metadata': {'auths_echo': fields['metadata[auths_echo]'][0]}}
                            refunds[refund] = value
                            idempotency[key] = (body, value)
                            payments[identifier]['refunded'] += amount
                            status, drop = 200, identifier == 'pi_demo_09'
                entry = {'method': method, 'path': self.path, 'status': status,
                         'kind': 'write' if method == 'POST' else 'read',
                         'body_sha256': hashlib.sha256(body).hexdigest(),
                         'body': body.decode() if method == 'POST' else None,
                         'idempotency_key': self.headers.get('Idempotency-Key'),
                         'stripe_version': self.headers.get('Stripe-Version'),
                         'stripe_account': self.headers.get('Stripe-Account'),
                         'response_dropped_after_effect': drop,
                         'refund': value.get('id') if method == 'POST' and status == 200 else None}
                with ledger.open('ab') as output:
                    output.write(canonical(entry) + b'\n')
            if drop:
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
            else:
                self.reply(status, value)

        def do_GET(self):
            self.handle_request('GET')

        def do_POST(self):
            self.handle_request('POST')

    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, payments, refunds
