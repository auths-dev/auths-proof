"""Independent counting HTTP provider; simulation faults never claim live evidence."""
import hashlib
import hmac
import json
import socket
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from demo_common import canonical, decode

BASE = 'appQD3Qf0YFBCW9bV'
TABLE = 'tblBx2jwe0IsPYRKT'
PREFIX = '/v0/' + BASE + '/' + TABLE + '/'


def record_ids():
    return ['rec' + str(index).zfill(14) for index in range(16)]


class Fixture:
    def __init__(self, ledger, fixture_token):
        self.lock, self.ledger, self.token = threading.Lock(), ledger, fixture_token
        self.records = {record: {'DemoStatus': 'Pending', 'auths_echo': ''} for record in record_ids()}
        self.hidden_until = {}
        self.port = None

    def release_visibility(self, record):
        with self.lock:
            self.hidden_until.pop(record, None)

    def append(self, value):
        with self.ledger.open('ab') as output:
            output.write(canonical(value) + b'\n')

    def compete(self, record):
        # Another actual HTTP actor writes the same value with a different echo.
        request = urllib.request.Request('http://127.0.0.1:' + str(self.port) + PREFIX + record,
            data=canonical({'fields': {'DemoStatus': 'Approved', 'auths_echo': 'external-writer-echo'}}),
            method='PATCH', headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=5) as response:
            response.read(16385)


def serve(runtime_digest, ledger, fixture_token):
    fixture = Fixture(ledger, fixture_token)
    fixture_digest = hashlib.sha256(fixture_token.encode()).hexdigest()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, value, raw=None):
            body = canonical(value) if raw is None else raw
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
            key = hashlib.sha256(header.removeprefix('Bearer ').encode()).hexdigest()
            external = hmac.compare_digest(key, fixture_digest)
            if not header.startswith('Bearer ') or not (external or hmac.compare_digest(key, runtime_digest)):
                return self.reply(401, {'error': 'credential-refused'})
            record = self.path[len(PREFIX):] if self.path.startswith(PREFIX) else None
            status, value, raw, drop, compete = 404, {'error': 'missing-record'}, None, False, False
            with fixture.lock:
                fields = fixture.records.get(record)
                if fields is not None:
                    if method == 'GET' and not external:
                        if record == record_ids()[14]:
                            status, raw = 200, b'{malformed'
                        elif record == record_ids()[15]:
                            status, raw = 200, b' ' * 17000
                        else:
                            visible = {'DemoStatus': 'Pending', 'auths_echo': ''} if time.monotonic() < fixture.hidden_until.get(record, 0) else fields
                            status, value = 200, {'id': record, 'fields': dict(visible)}
                    elif method == 'PATCH':
                        try:
                            request = decode(body)
                            valid = (set(request) == {'fields'} and set(request['fields']) == {'DemoStatus', 'auths_echo'}
                                and request['fields']['DemoStatus'] in ['Approved', 'Pending']
                                and type(request['fields']['auths_echo']) is str
                                and self.headers.get('Content-Type') == 'application/json'
                                and self.headers.get('Idempotency-Key') is None)
                        except (ValueError, TypeError):
                            valid = False
                        if external:
                            valid = valid and record == record_ids()[11] and request['fields']['auths_echo'] == 'external-writer-echo'
                        else:
                            valid = valid and request['fields']['auths_echo'].startswith('auths-e1-')
                        if not valid:
                            status, value = 400, {'error': 'mapping-refused'}
                        elif not external and record in [record_ids()[12], record_ids()[13]]:
                            status, value = (429 if record == record_ids()[12] else 500), {'error': 'simulated-provider-refusal'}
                        else:
                            fixture.records[record] = dict(request['fields'])
                            status, value = 200, {'id': record, 'fields': dict(request['fields'])}
                            if not external and record in [record_ids()[10], record_ids()[11]]:
                                drop = True
                                if record == record_ids()[10]:
                                    fixture.hidden_until[record] = time.monotonic() + 3
                                else:
                                    compete = True
                            elif not external and record == record_ids()[14]:
                                raw = b'{malformed'
                            elif not external and record == record_ids()[15]:
                                raw = b' ' * 66000
                fixture.append({'method': method, 'path': self.path, 'status': status,
                    'kind': 'fixture-write' if external else 'write' if method == 'PATCH' else 'read',
                    'body': body.decode() if method == 'PATCH' else None,
                    'body_sha256': hashlib.sha256(body).hexdigest(),
                    'idempotency_key': self.headers.get('Idempotency-Key'),
                    'response_dropped_after_effect': drop})
            if compete:
                fixture.compete(record)
            if drop:
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
            else:
                self.reply(status, value, raw)

        def do_GET(self):
            self.handle_request('GET')

        def do_PATCH(self):
            self.handle_request('PATCH')

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    fixture.port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, fixture
