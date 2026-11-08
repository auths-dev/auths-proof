"""Lab-only conventional refund adapter for AP075, not shipping Auths code.

Uses locally issued HS256 JWTs, exact server-side approval records, SQLite
transactions and provider idempotency. This is not an OAuth server or a reviewed
production gateway, and makes no delegated-chain/offline-public-proof claim.
"""
import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def encode(data):
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def decode(data):
    return base64.urlsafe_b64decode(data + '=' * (-len(data) % 4))


class Baseline:
    def __init__(self, path, provider, credential, *, ceiling=2000, count=2, total=1000):
        self.path, self.provider, self.credential = str(path), provider, credential
        self.issuer_key = secrets.token_bytes(32)
        self.ceiling, self.count, self.total = ceiling, count, total
        with self.connection() as db:
            db.executescript('''
              CREATE TABLE state(enabled INTEGER NOT NULL);
              INSERT INTO state VALUES(1);
              CREATE TABLE approvals(action TEXT, manager TEXT, at INTEGER,
                                     PRIMARY KEY(action,manager));
              CREATE TABLE attempts(operation TEXT PRIMARY KEY, action TEXT, amount INTEGER,
                                    currency TEXT, window INTEGER, stage TEXT);
            ''')

    def connection(self):
        db = sqlite3.connect(self.path, timeout=20, isolation_level=None)
        db.execute('PRAGMA synchronous=FULL')
        return db

    def token(self, subject, scope):
        head = encode(canonical({'alg': 'HS256', 'typ': 'JWT'}))
        body = encode(canonical({'iss': 'ap075-local-issuer', 'aud': 'refund-baseline',
                                 'sub': subject, 'scope': scope, 'exp': int(time.time()) + 1800}))
        signed = (head + '.' + body).encode()
        return signed.decode() + '.' + encode(hmac.digest(self.issuer_key, signed, 'sha256'))

    def principal(self, token, scope):
        head, body, signature = token.split('.')
        if json.loads(decode(head)) != {'alg': 'HS256', 'typ': 'JWT'}:
            raise ValueError('pinned algorithm required')
        signed = (head + '.' + body).encode()
        if not hmac.compare_digest(decode(signature), hmac.digest(self.issuer_key, signed, 'sha256')):
            raise ValueError('invalid signature')
        value = json.loads(decode(body))
        if (value.get('iss') != 'ap075-local-issuer' or value.get('aud') != 'refund-baseline'
                or value.get('scope') != scope or type(value.get('exp')) is not int
                or value['exp'] <= time.time()):
            raise ValueError('invalid claims')
        return value['sub']

    @staticmethod
    def action(value):
        if (set(value) != {'operation', 'payment_intent', 'amount', 'currency'}
                or type(value['amount']) is not int or not 0 < value['amount'] <= 2000
                or value['currency'] != 'usd' or not isinstance(value['operation'], str)
                or not 1 <= len(value['operation']) <= 64
                or value['payment_intent'] not in {f'pi_demo_{n:02}' for n in range(16)}):
            raise ValueError('closed action required')
        return hashlib.sha256(canonical(value)).hexdigest()

    def approve(self, token, value):
        manager = self.principal(token, 'approve')
        if manager not in {'manager-a', 'manager-b', 'manager-c'}:
            raise ValueError('unauthorized approver')
        commitment = self.action(value)
        with self.connection() as db:
            db.execute('INSERT OR IGNORE INTO approvals VALUES(?,?,?)',
                       (commitment, manager, int(time.time())))
        return {'outcome': 'approval-recorded'}

    def disable(self):
        # Trusted operator method, not an application request parameter.
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('UPDATE state SET enabled=0')
            db.execute('COMMIT')

    def provider_get(self, path):
        request = Request(self.provider + path, headers={
            'Authorization': 'Bearer ' + self.credential, 'Stripe-Version': '2025-03-31.basil'})
        with urlopen(request, timeout=3) as response:
            data = response.read(16385)
        if len(data) > 16384:
            raise ValueError('provider response bound')
        return json.loads(data)

    def submit(self, token, value):
        if self.principal(token, 'refund') != 'agent':
            raise ValueError('unknown actor')
        commitment = self.action(value)
        # One transaction owns equality, approval, revocation, budget and entry.
        db = self.connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT action,stage FROM attempts WHERE operation=?',
                             (value['operation'],)).fetchone()
            if old:
                db.execute('ROLLBACK')
                return {'outcome': old[1] if old[0] == commitment else 'denied'}
            approved = db.execute('SELECT count(*) FROM approvals WHERE action=? AND at>=?',
                                  (commitment, int(time.time()) - 1800)).fetchone()[0]
            window = int(time.time()) // 259200
            used, amount = db.execute('SELECT count(*),coalesce(sum(amount),0) FROM attempts '
                                     'WHERE currency=? AND window=?', (value['currency'], window)).fetchone()
            if (not db.execute('SELECT enabled FROM state').fetchone()[0] or approved < 2
                    or value['amount'] > self.ceiling or used + 1 > self.count
                    or amount + value['amount'] > self.total):
                db.execute('ROLLBACK')
                return {'outcome': 'denied'}
            # Same gross-payment relative ceiling exercised by the Auths fixture.
            payment = self.provider_get('/v1/payment_intents/' + value['payment_intent'])
            if payment['currency'] != value['currency'] or value['amount'] > payment['amount_received'] // 2:
                db.execute('ROLLBACK')
                return {'outcome': 'denied'}
            db.execute('INSERT INTO attempts VALUES(?,?,?,?,?,?)',
                       (value['operation'], commitment, value['amount'], value['currency'], window, 'unknown'))
            db.execute('COMMIT')
        except Exception:
            if db.in_transaction:
                db.execute('ROLLBACK')
            raise
        finally:
            db.close()
        body = urlencode([('amount', str(value['amount'])), ('metadata[auths_echo]', commitment),
                          ('payment_intent', value['payment_intent'])]).encode()
        request = Request(self.provider + '/v1/refunds', data=body, method='POST', headers={
            'Authorization': 'Bearer ' + self.credential, 'Stripe-Version': '2025-03-31.basil',
            'Idempotency-Key': 'auths-i1-' + hashlib.sha256(value['operation'].encode()).hexdigest(),
            'Content-Type': 'application/x-www-form-urlencoded'})
        try:
            with urlopen(request, timeout=3) as response:
                raw = response.read(16385)
                if response.status != 200 or len(raw) > 16384:
                    raise ValueError('provider response incomplete')
            stage = 'response-recorded'
        except Exception:
            stage = 'unknown'
        with self.connection() as db:
            db.execute('UPDATE attempts SET stage=? WHERE operation=?', (stage, value['operation']))
        return {'outcome': stage}

    def accounting(self):
        with self.connection() as db:
            count, total = db.execute('SELECT count(*),coalesce(sum(amount),0) FROM attempts').fetchone()
        return {'count': count, 'amount': total}


def serve(gateway):
    """One bounded local HTTP ingress; the issuer key stays behind this boundary."""
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 16384:
                    raise ValueError('request bound')
                value = json.loads(self.rfile.read(size))
                header = self.headers.get('Authorization', '')
                if not header.startswith('Bearer '):
                    raise ValueError('identity required')
                token = header.removeprefix('Bearer ')
                if self.path == '/approve':
                    result = gateway.approve(token, value)
                elif self.path == '/submit':
                    result = gateway.submit(token, value)
                elif self.path == '/disable' and gateway.principal(token, 'admin') == 'operator':
                    gateway.disable()
                    result = {'outcome': 'disabled'}
                else:
                    raise ValueError('unsupported route')
            except (ValueError, KeyError, TypeError):
                result = {'outcome': 'denied'}
            body = canonical(result)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
