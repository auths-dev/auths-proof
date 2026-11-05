"""Private owner consent transport over complete native review output.

This demo service holds no signing key and constructs no effect or approval.
The operator signs the retained native request only after authenticated consent.
"""
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import secrets
import threading
import time

from demo_common import canonical, decode, require, write

RENDERER = 'auths.literal-complete-review/1'
MAX_REVIEW = 131072  # Native MAX_PRIVATE_EFFECT_REVIEW_BYTES, including envelope.
MAX_COMMAND = 1024
SESSION_SECONDS = 900
CONSENT_SECONDS = 600


def native_review(packet):
    """Preserve native presentation; refuse an unsupported/incomplete envelope."""
    require(type(packet) is dict, 'demo.owner-review-envelope-refused')
    raw = canonical(packet)
    require(len(raw) <= MAX_REVIEW and set(packet) == {
        'schema', 'renderer', 'literal_review', 'approval_request', 'signing_message_hex'},
        'demo.owner-review-envelope-refused')
    require(packet['schema'] == 'auths.private-effect-signing/2'
            and packet['renderer'] == RENDERER
            and type(packet['literal_review']) is str and packet['literal_review'].isascii(),
            'demo.owner-review-renderer-refused')
    literal = decode(packet['literal_review'].encode('ascii'))
    require(type(literal) is dict and literal.get('schema') == 'auths.private-effect-review/2'
            and all(key in literal for key in ('effect_id_hex', 'binding_canonical', 'native', 'semantic')),
            'demo.owner-review-incomplete')
    request = packet['approval_request']
    require(type(request) is dict and set(request) == {'schema', 'effect', 'approver', 'not_before', 'expires_at'}
            and request['schema'] == 'auths.exact-effect-approval/1'
            and type(request['not_before']) is int and type(request['expires_at']) is int
            and type(request['approver']) is list and len(request['approver']) == 32
            and type(request.get('effect')) is list
            and len(request['effect']) == 32
            and all(type(value) is int and 0 <= value <= 255 for value in request['effect'])
            and literal['effect_id_hex'] == bytes(request['effect']).hex(),
            'demo.owner-review-effect-mismatch')
    # This is native output correlation, not a second effect hash/signing codec.
    return decode(raw)


@dataclass
class Pending:
    packet: dict
    identifier: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    event: threading.Event = field(default_factory=threading.Event)
    accepted: bool = False


class OwnerReviewServer:
    def __init__(self, directory, port):
        directory = Path(directory)
        require(directory.is_dir() and not directory.is_symlink()
                and directory.stat().st_uid == os.getuid()
                and directory.stat().st_mode & 0o077 == 0, 'demo.owner-private-directory-required')
        self.credential = secrets.token_urlsafe(32)
        write(directory / 'owner-login', self.credential.encode('ascii'), new=True)
        self.lock = threading.Lock()
        self.pending = None
        self.session = None
        self.assets = Path(__file__).resolve().parent / 'web'
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass  # Login, bearer, native private review and decisions stay private.

            def setup(self):
                self.request.settimeout(5)
                super().setup()

            def reply(self, status, value, *, kind='application/json'):
                raw = value if isinstance(value, bytes) else canonical(value)
                self.send_response(status)
                self.send_header('Content-Type', kind)
                self.send_header('Content-Length', str(len(raw)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Referrer-Policy', 'no-referrer')
                self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
                self.end_headers()
                self.wfile.write(raw)

            def host(self):
                return self.headers.get('Host') in owner.hosts

            def authenticated(self):
                offered = self.headers.get('Authorization', '')
                session = owner.session
                return (session is not None and offered.isascii() and len(offered) <= 80
                        and time.monotonic() < session['until']
                        and secrets.compare_digest(offered, 'Bearer ' + session['bearer']))

            def do_GET(self):
                if not self.host():
                    return self.reply(403, {'code': 'demo.owner-host-refused'})
                assets = {'/': ('owner.html', 'text/html; charset=utf-8'),
                          '/owner.js': ('owner.js', 'text/javascript; charset=utf-8'),
                          '/owner.css': ('owner.css', 'text/css; charset=utf-8')}
                if self.path in assets:
                    name, kind = assets[self.path]
                    return self.reply(200, (owner.assets / name).read_bytes(), kind=kind)
                with owner.lock:
                    if not self.authenticated():
                        return self.reply(401, {'code': 'demo.owner-authentication-required'})
                    if self.path == '/api/session':
                        return self.reply(200, {'renderer': RENDERER, 'csrf': owner.session['csrf']})
                    if self.path == '/api/review':
                        pending = owner.pending
                        return self.reply(200, None if pending is None or pending.event.is_set() else {
                            'review_id': pending.identifier, 'native': pending.packet})
                return self.reply(404, {'code': 'demo.owner-route-unavailable'})

            def do_POST(self):
                self.connection.settimeout(5)
                if (not self.host() or self.headers.get('Origin') not in owner.origins
                        or self.headers.get('Content-Type') != 'application/json'
                        or self.headers.get('Transfer-Encoding') is not None):
                    return self.reply(403, {'code': 'demo.owner-channel-refused'})
                try:
                    require(len(self.headers.get_all('Content-Length', [])) == 1,
                            'demo.owner-command-framing')
                    length = int(self.headers.get('Content-Length', '0'))
                    require(0 < length <= MAX_COMMAND, 'demo.owner-command-bound')
                    raw = self.rfile.read(length)
                    require(len(raw) == length, 'demo.owner-command-incomplete')
                    value = decode(raw)
                    require(type(value) is dict, 'demo.owner-command-refused')
                except (ValueError, OSError):
                    return self.reply(400, {'code': 'demo.owner-command-refused'})
                with owner.lock:
                    if self.path == '/api/login':
                        valid = (set(value) == {'credential'} and type(value['credential']) is str
                                 and value['credential'].isascii() and len(value['credential']) <= 64
                                 and secrets.compare_digest(value['credential'], owner.credential))
                        if not valid:
                            return self.reply(403, {'code': 'demo.owner-login-refused'})
                        owner.session = {'bearer': secrets.token_urlsafe(32), 'csrf': secrets.token_urlsafe(32),
                                         'until': time.monotonic() + SESSION_SECONDS}
                        # Cookies ignore ports and would leak to the untrusted
                        # application on the same localhost hostname. This bearer
                        # stays in owner-page memory and explicit same-origin headers.
                        return self.reply(200, {'bearer': owner.session['bearer'],
                                                'csrf': owner.session['csrf'], 'renderer': RENDERER})
                    csrf = self.headers.get('X-Owner-CSRF', '')
                    if (not self.authenticated() or not csrf.isascii() or len(csrf) > 64
                            or not secrets.compare_digest(csrf, owner.session['csrf'])):
                        return self.reply(403, {'code': 'demo.owner-session-refused'})
                    if self.path != '/api/decision':
                        return self.reply(404, {'code': 'demo.owner-route-unavailable'})
                    pending = owner.pending
                    if (set(value) != {'review_id', 'decision', 'renderer'} or pending is None
                            or pending.event.is_set() or value['review_id'] != pending.identifier
                            or value['decision'] not in ('approve', 'decline') or value['renderer'] != RENDERER):
                        return self.reply(409, {'code': 'demo.owner-review-changed'})
                    pending.accepted = value['decision'] == 'approve'
                    pending.event.set()
                    return self.reply(200, {'decision': value['decision']})

        class BoundedServer(ThreadingHTTPServer):
            daemon_threads = True
            request_queue_size = 8
            capacity = threading.BoundedSemaphore(8)

            def process_request(self, request, address):
                if not self.capacity.acquire(blocking=False):
                    self.shutdown_request(request)
                    return
                try:
                    super().process_request(request, address)
                except Exception:
                    self.capacity.release()
                    raise

            def process_request_thread(self, request, address):
                try:
                    super().process_request_thread(request, address)
                finally:
                    self.capacity.release()

        self.server = BoundedServer(('0.0.0.0', port), Handler)
        actual = self.server.server_address[1]
        self.hosts = {f'localhost:{actual}', f'127.0.0.1:{actual}'}
        self.origins = {'http://' + host for host in self.hosts}
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def request(self, packet):
        pending = Pending(native_review(packet))
        with self.lock:
            require(self.pending is None, 'demo.owner-review-busy')
            self.pending = pending
        try:
            require(pending.event.wait(CONSENT_SECONDS) and pending.accepted,
                    'demo.owner-review-declined-or-expired')
        finally:
            with self.lock:
                if self.pending is pending:
                    self.pending = None

    def stop(self):
        with self.lock:
            if self.pending:
                self.pending.event.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
