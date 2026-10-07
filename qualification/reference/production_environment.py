"""Ephemeral hosted PostgreSQL/TLS, synchronized clock and actual OIDC inputs.

This source owns no IAM grant and never uploads a credential. Only a manual
main run in the existing protected custody environment may provision it.
"""

import base64
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

from common import Refusal, require
from expand import decode
from production_setup import GATEWAY_UID
from resource_io import NoRedirect, write_bytes

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'run'))
import artifact_wait

SUBJECT = 'repo:auths-dev@260513770/auths-proof@1310728509:environment:gateway-custody-live'
POSTGRES_IMAGE = 'postgres:17.10-bookworm'
COMMAND_ENVIRONMENT = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                       'DOCKER_CONFIG': '/nonexistent-auths-docker-config'}


def checked_token(raw, environment):
    require(type(raw) is str and 32 <= len(raw) <= 16384 and raw.count('.') == 2,
            'qualification.infrastructure.identity-token')
    try:
        encoded = raw.split('.')[1]
        claims = decode(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
    except (ValueError, UnicodeError):
        raise Refusal('qualification.infrastructure.identity-token') from None
    run, attempt, commit = artifact_wait.identity(environment)
    now = int(time.time())
    require(type(claims) is dict and claims.get('iss') == 'https://token.actions.githubusercontent.com'
            and claims.get('aud') == 'sts.amazonaws.com' and claims.get('sub') == SUBJECT
            and claims.get('repository_id') == '1310728509' and claims.get('repository_owner_id') == '260513770'
            and claims.get('repository') == 'auths-dev/auths-proof'
            and claims.get('event_name') == 'workflow_dispatch' and claims.get('ref') == 'refs/heads/main'
            and claims.get('sha') == commit and claims.get('run_id') == run and claims.get('run_attempt') == attempt
            and type(claims.get('iat')) is int and type(claims.get('exp')) is int
            and now - 120 <= claims['iat'] <= now + 30 and now + 60 < claims['exp'] <= now + 900,
            'qualification.infrastructure.identity-binding')
    # These are source preconditions, not signature verification. The actual
    # AWS role assumption separately authenticates the signed token.
    return raw.encode()


def token_url(value):
    require(type(value) is str and len(value) <= 8192, 'qualification.infrastructure.identity-url')
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        raise Refusal('qualification.infrastructure.identity-url') from None
    require(parsed.scheme == 'https' and parsed.hostname is not None
            and parsed.hostname.endswith('.actions.githubusercontent.com')
            and port is None and parsed.username is None and parsed.password is None
            and not parsed.fragment, 'qualification.infrastructure.identity-url')
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    require(not any(name == 'audience' for name, _ in query), 'qualification.infrastructure.identity-url')
    return urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode([*query, ('audience', 'sts.amazonaws.com')])))


def command(arguments, timeout=60):
    result = subprocess.run(list(map(str, arguments)), stdin=subprocess.DEVNULL, capture_output=True,
        timeout=timeout, env=COMMAND_ENVIRONMENT)
    require(result.returncode == 0 and len(result.stdout) <= 65536 and len(result.stderr) <= 65536,
            'qualification.infrastructure.command-refused')
    return result.stdout


class Infrastructure:
    def __init__(self, private, environment, canaries):
        require(sys.platform == 'linux' and os.getuid() == 0
                and environment.get('GITHUB_ACTIONS') == 'true'
                and environment.get('RUNNER_ENVIRONMENT') == 'github-hosted',
                'qualification.infrastructure.host')
        self.run, self.attempt, self.commit = artifact_wait.identity(environment)
        self.url = token_url(environment.get('ACTIONS_ID_TOKEN_REQUEST_URL'))
        self.request_token = environment.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN')
        require(type(self.request_token) is str and 8 <= len(self.request_token) <= 16384
                and all(33 <= ord(character) <= 126 for character in self.request_token),
                'qualification.infrastructure.identity-request')
        self.private, self.environment, self.canaries = Path(private).absolute(), dict(environment), canaries
        require(not self.private.exists() and self.private.resolve() == self.private,
                'qualification.infrastructure.private-directory')
        self.private.mkdir(mode=0o711)
        os.chmod(self.private, 0o711)
        self.root = self.private / 'operator'
        self.root.mkdir(mode=0o700)
        self.tokens = self.private / 'tokens'
        self.tokens.mkdir(mode=0o700)
        os.chown(self.tokens, GATEWAY_UID, GATEWAY_UID)
        self.canaries.append(self.request_token.encode())
        self.stopping = threading.Event()
        self.refresher, self.refusal, self.container = None, None, None

    def refresh(self):
        request = urllib.request.Request(self.url,
            headers={'Authorization': 'bearer ' + self.request_token, 'Accept': 'application/json'})
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect).open(request, timeout=20) as response:
                raw = response.read(65537)
                require(response.status == 200 and 0 < len(raw) <= 65536,
                        'qualification.infrastructure.identity-response')
        except (OSError, ValueError):
            raise Refusal('qualification.infrastructure.identity-unavailable') from None
        response = decode(raw)
        require(type(response) is dict, 'qualification.infrastructure.identity-response')
        token = checked_token(response.get('value'), self.environment)
        self.canaries.append(token)
        for name in ['operator.jwt', 'runtime.jwt']:
            temporary = self.tokens / (name + '.next')
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.fchmod(fd, 0o600)
                os.fchown(fd, GATEWAY_UID, GATEWAY_UID)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(token)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.tokens / name)
            finally:
                temporary.unlink(missing_ok=True)

    def start_identity(self):
        self.refresh()
        def renew():
            while not self.stopping.wait(60):
                try:
                    self.refresh()
                except (Refusal, OSError, ValueError):
                    self.refusal = True
                    return
        self.refresher = threading.Thread(target=renew, name='auths-oidc-refresh', daemon=True)
        self.refresher.start()

    def check_identity(self):
        require(self.refresher is not None and self.refresher.is_alive() and self.refusal is None,
                'qualification.infrastructure.identity-refresh-refused')

    def synchronize_clock(self):
        directory = Path('/etc/systemd/timesyncd.conf.d')
        directory.mkdir(mode=0o755, exist_ok=True)
        path = directory / ('90-auths-qualification-' + self.run + '-' + self.attempt + '.conf')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(b'[Time]\nPollIntervalMinSec=32s\nPollIntervalMaxSec=5min\n')
        self.clock_configuration = path
        command(['systemctl', 'enable', '--now', 'systemd-timesyncd'])
        command(['systemctl', 'restart', 'systemd-timesyncd'])
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                info = os.lstat('/run/systemd/timesync/synchronized')
                if stat.S_ISREG(info.st_mode) and not info.st_mode & 0o022 and 0 <= time.time() - info.st_mtime <= 900:
                    require(command(['timedatectl', 'show', '--property=NTPSynchronized', '--value']).strip() == b'yes',
                            'qualification.infrastructure.clock-untrusted')
                    return
            except FileNotFoundError:
                pass
            time.sleep(0.25)
        require(False, 'qualification.infrastructure.clock-untrusted')

    def start_database(self):
        certificates = self.root / 'certificates'
        certificates.mkdir(mode=0o700)
        command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=auths-qualification-ephemeral-ca', '-keyout', certificates / 'ca.key',
            '-out', certificates / 'ca.pem'])
        command(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
            '-keyout', certificates / 'server.key', '-out', certificates / 'server.csr'])
        write_bytes(certificates / 'server.ext', b'subjectAltName=DNS:localhost,IP:127.0.0.1\n', new=True)
        command(['openssl', 'x509', '-req', '-days', '1', '-in', certificates / 'server.csr',
            '-CA', certificates / 'ca.pem', '-CAkey', certificates / 'ca.key', '-CAcreateserial',
            '-extfile', certificates / 'server.ext', '-out', certificates / 'server.pem'])
        server = self.root / 'postgres-tls'
        server.mkdir(mode=0o700)
        for source, name in [('server.key', 'server.key'), ('server.pem', 'server.pem'), ('ca.pem', 'ca.pem')]:
            write_bytes(server / name, (certificates / source).read_bytes(), new=True)
            os.chown(server / name, 999, 999)
        os.chown(server, 999, 999)
        password = secrets.token_hex(24)
        self.canaries.append(password.encode())
        configuration = self.root / 'postgres.env'
        write_bytes(configuration, ('POSTGRES_USER=auths\nPOSTGRES_DB=auths_qualification\nPOSTGRES_PASSWORD=' + password + '\n').encode(), new=True)
        # A closed name is retained before Docker starts, so cleanup can remove
        # an ambiguously started container without listing unrelated resources.
        self.container = 'auths-qualification-' + secrets.token_hex(8)
        command(['docker', 'run', '--detach', '--name', self.container, '--env-file', configuration,
            '--publish', '127.0.0.1::5432', '--mount', 'type=bind,src=' + str(server) + ',dst=/tls,readonly',
            POSTGRES_IMAGE, 'postgres', '-c', 'ssl=on', '-c', 'ssl_cert_file=/tls/server.pem',
            '-c', 'ssl_key_file=/tls/server.key', '-c', 'ssl_ca_file=/tls/ca.pem', '-c', 'synchronous_commit=on'], timeout=120)
        port = command(['docker', 'port', self.container, '5432/tcp']).decode().strip()
        require(port.startswith('127.0.0.1:') and port.removeprefix('127.0.0.1:').isdigit(),
                'qualification.infrastructure.database-port')
        number = int(port.removeprefix('127.0.0.1:'))
        require(1 <= number <= 65535, 'qualification.infrastructure.database-port')
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            result = subprocess.run(['docker', 'exec', self.container, 'pg_isready', '-U', 'auths', '-d', 'auths_qualification'],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
                env=COMMAND_ENVIRONMENT)
            if result.returncode == 0:
                return {'AUTHS_POSTGRES_URL': 'host=127.0.0.1 port=' + str(number)
                    + ' dbname=auths_qualification user=auths password=' + password + ' sslmode=require',
                    'AUTHS_POSTGRES_CA_PEM': str(certificates / 'ca.pem'), 'AUTHS_POSTGRES_SERVER_NAME': 'localhost',
                    'AUTHS_QUALIFICATION_OPERATOR_TOKEN_FILE': str(self.tokens / 'operator.jwt'),
                    'AUTHS_QUALIFICATION_RUNTIME_TOKEN_FILE': str(self.tokens / 'runtime.jwt'),
                    'AUTHS_QUALIFICATION_CREDENTIAL_NAMESPACE': 'live-' + self.run + '-' + self.attempt}
            time.sleep(0.25)
        require(False, 'qualification.infrastructure.database-unavailable')

    def stop_database(self):
        if self.container is not None:
            # The exact-name filter never lists unrelated user containers.
            found = command(['docker', 'container', 'ls', '--all', '--filter',
                'name=^/' + self.container + '$', '--format', '{{.Names}}']).strip()
            require(found in [b'', self.container.encode()], 'qualification.infrastructure.cleanup-binding')
            if found:
                command(['docker', 'rm', '--force', '--volumes', self.container])
            self.container = None

    def close(self):
        # The caller must first collect its native credential journal. Keep
        # attempting local cleanup even when one owned resource cannot retire.
        failures = []
        def attempt(action):
            try:
                action()
            except (Refusal, OSError, ValueError, subprocess.SubprocessError):
                failures.append(True)
        self.stopping.set()
        if self.refresher is not None:
            self.refresher.join(timeout=30)
            if self.refresher.is_alive():
                failures.append(True)
        attempt(self.stop_database)
        if hasattr(self, 'clock_configuration'):
            attempt(lambda: self.clock_configuration.unlink(missing_ok=True))
        for name in ['operator.jwt', 'runtime.jwt']:
            attempt(lambda name=name: (self.tokens / name).unlink(missing_ok=True))
        self.request_token = None
        require(not failures, 'qualification.infrastructure.cleanup-incomplete')
