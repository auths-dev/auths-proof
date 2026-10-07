"""Source-owned production installation and process custody for qualification.

This controller requires a real TLS database and existing web-identity token
files. It provisions no IAM grants and offers no development-store fallback.
Provider arguments, recipe identity and results remain owned by the two family
references and the shipping gateway. Nothing here issues an observation.
"""

import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time

from author_operator import ALIAS
from common import closed, require, sha256
from expand import decode, read
from resource_io import write_bytes

GATEWAY_UID = 62001
APPLICATION_UID = 62004
REGION = 'eu-west-1'
ROLE_PREFIX = 'arn:aws:iam::585985124542:role/auths-gateway-custody-'
OPERATOR_ROLE = ROLE_PREFIX + 'operator'
RUNTIME_ROLE = ROLE_PREFIX + 'runtime'
KMS_KEY = 'arn:aws:kms:eu-west-1:585985124542:key/1e1c85ae-7d9c-4f2d-978f-bd672b597907'
DATABASE_ENV = ['AUTHS_POSTGRES_URL', 'AUTHS_POSTGRES_CA_PEM', 'AUTHS_POSTGRES_SERVER_NAME']


def private_file(path, owner):
    path = Path(path).absolute()
    info = os.lstat(path)
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == owner
            and stat.S_IMODE(info.st_mode) == 0o600,
            'qualification.production.private-input')
    # Native state paths reject symlinked ancestors as well as symlinked files.
    require(all(not parent.is_symlink() for parent in [path, *path.parents]),
            'qualification.production.private-input')
    return path


def native_output(result, canaries, *, required=True, json_output=True):
    require(len(result.stdout) <= 65536 and len(result.stderr) <= 65536,
            'qualification.production.output-bound')
    require(all(value not in result.stdout + result.stderr for value in canaries),
            'qualification.production.secret-exposed')
    if required and result.returncode != 0:
        # A native refusal keeps its stable code, never its external details.
        match = re.match(rb'(gateway\.[a-z0-9.-]{1,128})(?:\s|$)', result.stderr)
        require(False, 'qualification.production.' + (match[1].decode() if match else 'native-refused'))
    if result.returncode != 0:
        return None
    return decode(result.stdout) if json_output else result.stdout


class Deployment:
    def __init__(self, binary, work, private, environment, canaries):
        require(os.name == 'posix' and os.getuid() == 0,
                'qualification.production.controller-identity')
        self.binary, self.work, self.private = Path(binary).absolute(), Path(work).absolute(), Path(private).absolute()
        self.tuple = decode(read(self.work / 'tuple.json', 65536))
        require(sha256(read(self.binary, 256 * 1024 * 1024)) == self.tuple['target']['gateway_build_sha256'],
                'qualification.production.candidate-bytes')
        require(not self.private.exists() and not self.private.is_relative_to(self.work),
                'qualification.production.private-directory')
        self.private.mkdir(mode=0o711)
        self.gateway = self.private / 'gateway'
        self.gateway.mkdir(mode=0o700)
        self.sockets = self.private / 'sockets'
        self.sockets.mkdir(mode=0o750)
        os.chown(self.sockets, GATEWAY_UID, GATEWAY_UID)
        self.canaries = list(canaries)
        require(self.canaries and all(type(value) is bytes and len(value) >= 8 for value in self.canaries),
                'qualification.production.canaries')
        self.database = {}
        for name in DATABASE_ENV:
            value = environment[name]
            require(type(value) is str and 0 < len(value) <= 8192 and '\n' not in value and '\0' not in value,
                    'qualification.production.database-input')
            self.database[name] = value
        require('sslmode=require' in self.database['AUTHS_POSTGRES_URL'],
                'qualification.production.database-tls')
        ca = Path(self.database['AUTHS_POSTGRES_CA_PEM']).absolute()
        write_bytes(self.gateway / 'postgres-ca.pem', read(ca, 65536), new=True)
        os.chown(self.gateway / 'postgres-ca.pem', GATEWAY_UID, GATEWAY_UID)
        self.database['AUTHS_POSTGRES_CA_PEM'] = str(self.gateway / 'postgres-ca.pem')
        self.operator_token = private_file(environment['AUTHS_QUALIFICATION_OPERATOR_TOKEN_FILE'], GATEWAY_UID)
        self.runtime_token = private_file(environment['AUTHS_QUALIFICATION_RUNTIME_TOKEN_FILE'], GATEWAY_UID)
        require(not self.operator_token.is_relative_to(self.work)
                and not self.runtime_token.is_relative_to(self.work),
                'qualification.production.private-input')
        self.namespace = environment['AUTHS_QUALIFICATION_CREDENTIAL_NAMESPACE']
        require(re.fullmatch(r'live-[1-9][0-9]{0,19}-[1-9][0-9]{0,9}', self.namespace) is not None,
                'qualification.production.namespace')
        carrier = decode(read(self.work / 'public-packets.json', 65536))
        require(carrier['trusted_contexts'] == ['context-0.cbor', 'context-1.cbor'],
                'qualification.production.contexts')
        family = self.tuple['recipe_family']
        require(family in ['stripe-platform-refund-v1', 'airtable-record-update-v1'],
                'qualification.production.family')
        self.provider = 'stripe' if family == 'stripe-platform-refund-v1' else 'airtable'
        for name in ['recipe.json', 'profile.lock.json', *carrier['trusted_contexts'],
                     *[context + '.operator.json' for context in carrier['trusted_contexts']]]:
            path = self.gateway / name
            write_bytes(path, read(self.work / name, 4 * 1024 * 1024), new=True)
            os.chown(path, GATEWAY_UID, GATEWAY_UID)
        os.chown(self.gateway, GATEWAY_UID, GATEWAY_UID)
        self.processes = {}

    def environment(self, administrative=False):
        return {'PATH': '/usr/bin:/bin', **self.database,
            'AWS_ROLE_ARN': OPERATOR_ROLE if administrative else RUNTIME_ROLE,
            'AWS_WEB_IDENTITY_TOKEN_FILE': str(self.operator_token if administrative else self.runtime_token),
            **({'AUTHS_GATEWAY_RUNTIME_ROLE_ARN': RUNTIME_ROLE,
                'AUTHS_GATEWAY_RUNTIME_TOKEN_FILE': str(self.runtime_token)} if administrative else {})}

    def command(self, arguments, *, administrative=False, secret=b'', required=True, json_output=True):
        result = subprocess.run([str(self.binary), *map(str, arguments)],
            input=secret, capture_output=True, timeout=90, cwd=self.gateway,
            user=GATEWAY_UID, group=GATEWAY_UID, extra_groups=[], env=self.environment(administrative))
        return native_output(result, self.canaries, required=required, json_output=json_output)

    def state(self, host, context=0):
        require(host in [0, 1] and context in [0, 1], 'qualification.production.host')
        return self.gateway / ('host-' + str(host) + '-context-' + str(context))

    def app_socket(self, host, context=0):
        self.state(host, context)
        return self.sockets / ('h' + str(host) + 'c' + str(context) + '.sock')

    def install(self, credential, account):
        require(type(credential) is bytes and credential in self.canaries
                and b'\n' not in credential and b'\0' not in credential,
                'qualification.production.credential-input')
        for context in [0, 1]:
            for host in [0, 1]:
                state = self.state(host, context)
                state.mkdir(mode=0o700)
                os.chown(state, GATEWAY_UID, GATEWAY_UID)
                trust = 'context-' + str(context) + '.cbor'
                arguments = ['install', '--state-dir', state,
                    '--recipe', self.gateway / 'recipe.json', '--profile-lock', self.gateway / 'profile.lock.json',
                    '--trusted-context', self.gateway / trust, '--approve-digest', self.tuple['compiled_recipe_sha256'],
                    '--provider', self.provider, '--alias', ALIAS, '--credential-stdin',
                    '--deployment', 'production', '--operator-attestation', self.gateway / (trust + '.operator.json'),
                    '--credential-store', 'aws-secrets-manager-v1', '--credential-namespace', self.namespace,
                    '--aws-region', REGION, '--aws-kms-key', KMS_KEY, '--aws-identity', 'web-identity',
                    '--qualification-policy', 'required', '--recipe-family', self.tuple['recipe_family'],
                    '--provider-contract-id', self.tuple['provider_contract_id']]
                arguments += ['--account-label', account] if host == context == 0 else ['--join']
                output = self.command(arguments, administrative=True, secret=credential + b'\n', json_output=False)
                expected = ('installed' if host == context == 0 else 'joined') + ' recipe ' \
                    + self.tuple['compiled_recipe_sha256'] + ' with separate gateway credential custody\n'
                require(output == expected.encode(), 'qualification.production.install-output')
                actual = self.command(['qualification-status', '--state-dir', state, '--tuple'])
                require(actual == self.tuple, 'qualification.production.installed-tuple')

    def start(self, host, context=0):
        key = (host, context)
        require(key not in self.processes, 'qualification.production.host-running')
        state, endpoint = self.state(host, context), self.app_socket(host, context)
        require(len(str(endpoint).encode()) <= 107, 'qualification.production.socket-bound')
        process = subprocess.Popen([str(self.binary), 'serve', '--state-dir', str(state),
            '--app-socket', str(endpoint)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=self.gateway, user=GATEWAY_UID, group=GATEWAY_UID, extra_groups=[], env=self.environment())
        self.processes[key] = process
        deadline = time.monotonic() + 30
        while process.poll() is None and time.monotonic() < deadline:
            if endpoint.exists():
                self.witness(host, context)
                return
            time.sleep(0.05)
        require(False, 'qualification.production.gateway-not-ready')

    def stop(self, host, context=0, *, crash=False):
        process = self.processes.pop((host, context), None)
        require(process is not None and process.poll() is None, 'qualification.production.gateway-not-running')
        process.send_signal(signal.SIGKILL if crash else signal.SIGTERM)
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            require(False, 'qualification.production.gateway-stop-timeout')
        require(process.returncode == (-signal.SIGKILL if crash else 0),
                'qualification.production.gateway-stop-result')

    def witness(self, host, context=0):
        from measure import snapshot
        result = self.command(['execution-witness', '--state-dir', self.state(host, context)])
        closed(result, ['schema', 'ok', 'code', 'execution_witness'])
        require(result['ok'] is True, 'qualification.production.witness-unavailable')
        return snapshot(result['execution_witness'])

    def close(self):
        for host, context in list(self.processes):
            self.stop(host, context)
