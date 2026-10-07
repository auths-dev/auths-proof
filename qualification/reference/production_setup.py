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
from common import closed, Refusal, require, sha256
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
        executable = read(self.binary, 256 * 1024 * 1024)
        require(sha256(executable) == self.tuple['target']['gateway_build_sha256'],
                'qualification.production.candidate-bytes')
        require(not self.private.exists() and not self.private.is_relative_to(self.work),
                'qualification.production.private-directory')
        self.private.mkdir(mode=0o711)
        os.chmod(self.private, 0o711)
        # Runner temp ancestors may exclude the gateway/application UIDs.
        # Copy these exact checked executable bytes into a traversable parent.
        self.binary = self.private / 'auths-gateway'
        fd = os.open(self.binary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755)
        os.fchmod(fd, 0o755)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(executable)
            stream.flush()
            os.fsync(stream.fileno())
        self.gateway = self.private / 'gateway'
        self.gateway.mkdir(mode=0o700)
        self.sockets = self.private / 'sockets'
        self.sockets.mkdir(mode=0o750)
        os.chmod(self.sockets, 0o750)
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
        for name in ['recipe.json', 'profile.lock.json', 'resources.json', *carrier['trusted_contexts'],
                     *[context + '.operator.json' for context in carrier['trusted_contexts']]]:
            path = self.gateway / name
            write_bytes(path, read(self.work / name, 4 * 1024 * 1024), new=True)
            os.chown(path, GATEWAY_UID, GATEWAY_UID)
        os.chown(self.gateway, GATEWAY_UID, GATEWAY_UID)
        require(len(str(self.state(0) / 'admin.sock').encode()) <= 107,
                'qualification.production.socket-bound')
        self.processes = {}
        self.handoff_generation = 0
        self.permit = None

    def owned_inputs(self, name, values, owner):
        require(re.fullmatch(r'[a-z][a-z0-9-]{0,63}', name) is not None
                and owner in [GATEWAY_UID, APPLICATION_UID], 'qualification.production.private-directory')
        directory = self.private / name
        directory.mkdir(mode=0o700)
        for filename, payload in values.items():
            require(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}', filename) is not None,
                    'qualification.production.private-input')
            path = directory / filename
            write_bytes(path, payload, new=True)
            os.chown(path, owner, GATEWAY_UID)
        os.chown(directory, owner, GATEWAY_UID)
        return directory

    def packet_inputs(self, handoff, packet, owner):
        closed(packet, ['label', 'proof', 'action', 'trusted_context', 'arguments'])
        require(re.fullmatch(r'[a-z][a-z0-9-]{0,63}', packet['label']) is not None
                and packet['proof'] == packet['label'] + '.proof'
                and packet['action'] == packet['label'] + '.action'
                and packet['trusted_context'] in ['context-0.cbor', 'context-1.cbor'],
                'qualification.production.packet-binding')
        self.handoff_generation += 1
        values = {name: read(Path(handoff) / name, bound) for name, bound in [
            (packet['proof'], 4 * 1024 * 1024), (packet['action'], 65536)]}
        return self.owned_inputs('packet-' + str(self.handoff_generation), values, owner)

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

    def application_submit(self, handoff, packet, host=0, context=0):
        inputs = self.packet_inputs(handoff, packet, APPLICATION_UID)
        result = subprocess.run([str(self.binary), 'submit', '--app-socket', str(self.app_socket(host, context)),
            '--proof', str(inputs / packet['proof']), '--action', str(inputs / packet['action'])],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=90, cwd=inputs,
            user=APPLICATION_UID, group=GATEWAY_UID, extra_groups=[], env={'PATH': '/usr/bin:/bin'})
        return native_output(result, self.canaries)

    def installed_python_submit(self, python, kit, handoff, packet, host=0, context=0):
        inputs = self.packet_inputs(handoff, packet, APPLICATION_UID)
        result = subprocess.run([str(python), '-B', str(Path(kit) / 'installed_submit.py'),
            '--endpoint', str(self.app_socket(host, context)), '--proof', str(inputs / packet['proof']),
            '--action', str(inputs / packet['action'])], stdin=subprocess.DEVNULL,
            capture_output=True, timeout=90, cwd=inputs, user=APPLICATION_UID,
            group=GATEWAY_UID, extra_groups=[], env={'PATH': '/usr/bin:/bin', 'PYTHONNOUSERSITE': '1'})
        return native_output(result, self.canaries)

    def register_commissioning(self, source):
        require(self.permit is None, 'qualification.production.permit-already-registered')
        names = ['commissioning-permit.json', 'signer-certificate.json', 'revocation-list.json']
        permit = self.owned_inputs('permit', {name: read(Path(source) / name, 2 * 1024 * 1024)
                                            for name in names}, GATEWAY_UID)
        result = self.command(self.commission_arguments('commissioning-init', permit, 0, 0))
        require(result == {'outcome': 'commissioning-registered', 'qualification': 'required'},
                'qualification.production.permit-not-registered')
        self.permit = permit

    def commission_arguments(self, operation, permit, host, context):
        require(operation in ['commissioning-init', 'commissioning-submit'],
                'qualification.production.operation')
        resources = decode(read(self.work / 'resources.json', 65536))
        return [operation, '--state-dir', self.state(host, context), '--from', permit,
                '--protected-run', resources['protected_run'], '--resource-binding', self.gateway / 'resources.json']

    def commissioning_arguments_for_packet(self, handoff, packet, host, context, witness=None):
        require(self.permit is not None, 'qualification.production.permit-not-registered')
        inputs = self.packet_inputs(handoff, packet, GATEWAY_UID)
        arguments = [*self.commission_arguments('commissioning-submit', self.permit, host, context),
            '--proof', inputs / packet['proof'], '--action', inputs / packet['action']]
        if witness is not None:
            require(Path(witness).parent == self.state(host, context) and not Path(witness).exists(),
                    'qualification.production.private-input')
            arguments += ['--witness-file', witness]
        return arguments

    @staticmethod
    def commissioning_execution(execution):
        closed(execution, ['schema', 'result', 'before', 'after'])
        require(execution['schema'] == 'auths.gateway-commissioning-execution/1',
                'qualification.production.execution')
        return execution

    def commissioning_submit(self, handoff, packet, host=0, context=0, witness=None):
        arguments = self.commissioning_arguments_for_packet(handoff, packet, host, context, witness)
        return self.commissioning_execution(self.command(arguments))

    def commissioning_child(self, handoff, packet, host=0, context=0):
        # This private native process owns the entered operation during the
        # commissioning phase. Killing an unrelated serving process would not
        # exercise loss of the actual owner.
        witness = self.state(host, context) / ('witness-' + str(self.handoff_generation + 1) + '.jsonl')
        arguments = self.commissioning_arguments_for_packet(handoff, packet, host, context, witness)
        return CommissioningChild(self, arguments, witness)

    def reobserve(self, operation, host=0, context=0):
        require(re.fullmatch(r'qlf-[0-9a-f]{48}', operation) is not None,
                'qualification.production.operation')
        result = subprocess.run([str(self.binary), 'reobserve', '--state-dir', str(self.state(host, context)),
            '--operation-id', operation], stdin=subprocess.DEVNULL, capture_output=True, timeout=90,
            cwd=self.gateway, user=GATEWAY_UID, group=GATEWAY_UID, extra_groups=[], env=self.environment())
        # Native admin refusals still have a closed response on stdout. Read
        # that response only for its exact normal refusal exit, after scanning.
        native_output(result, self.canaries, required=False)
        require(result.returncode == 0 or (result.returncode == 1 and result.stderr == b'gateway.admin.refused\n'),
                'qualification.production.reobserve')
        response = decode(result.stdout)
        closed(response, ['schema', 'ok', 'code', 'result'] if result.returncode == 0 else ['schema', 'ok', 'code'])
        require(response['schema'] == 'auths.gateway-admin-response/1'
                and response['ok'] is (result.returncode == 0)
                and response['code'] == ('gateway.admin.reobserved' if result.returncode == 0
                                         else 'gateway.reobserve.not-observable'),
                'qualification.production.reobserve')
        return response

    def rotate(self, credential):
        require(type(credential) is bytes and credential in self.canaries,
                'qualification.production.credential-input')
        result = self.command(['rotate', '--state-dir', self.state(0), '--credential-stdin', '--operator-process'],
                              administrative=True, secret=credential + b'\n')
        require(result.get('ok') is True and result.get('code') == 'gateway.admin.rotated',
                'qualification.production.rotation')
        return result

    def import_release(self, source):
        # Artifact transport already bounds the archive. Here only native
        # release members are copied; no script or binary can enter custody.
        names = ['signer-certificate.json', 'revocation-list.json', 'release-index.json']
        release = self.owned_inputs('first-release', {name: read(Path(source) / name, 2 * 1024 * 1024)
                                                      for name in names}, GATEWAY_UID)
        for group in ['records', 'attestations']:
            # Temporarily root-own the new directory while using owner-only I/O.
            directory = release / group
            directory.mkdir(mode=0o700)
            entries = sorted((Path(source) / group).iterdir())
            require(1 <= len(entries) <= 64 and all(path.suffix == '.json' for path in entries),
                    'qualification.production.release-bound')
            for index, path in enumerate(entries):
                destination = directory / (str(index).zfill(4) + '.json')
                write_bytes(destination, read(path, 2 * 1024 * 1024), new=True)
                os.chown(destination, GATEWAY_UID, GATEWAY_UID)
            os.chown(directory, GATEWAY_UID, GATEWAY_UID)
        for context in [0, 1]:
            for host in [0, 1]:
                # Import verifies the certificate, revocations, index and
                # record closure under this shipping build's pinned root.
                self.command(['qualification-import', '--state-dir', self.state(host, context),
                              '--from', release], json_output=False)

    def support(self, host=0, context=0):
        return self.command(['support-bundle', '--state-dir', self.state(host, context)])

    def doctor(self, host=0, context=0):
        # Only root can actually drop privileges to the application UID. The
        # native doctor itself runs runtime checks as the gateway owner.
        result = subprocess.run([str(self.binary), 'doctor', '--state-dir', str(self.state(host, context)),
            '--app-socket', str(self.app_socket(host, context)), '--app-uid', str(APPLICATION_UID),
            '--app-gid', str(GATEWAY_UID)], stdin=subprocess.DEVNULL, capture_output=True,
            timeout=90, cwd=self.gateway, env=self.environment())
        raw = native_output(result, self.canaries, json_output=False)
        return decode(raw), raw

    def close(self):
        for host, context in list(self.processes):
            self.stop(host, context)

    def retire_credentials(self):
        require(not self.processes, 'qualification.production.host-running')
        result = self.command(['revoke', '--state-dir', self.state(0), '--store-only'])
        require(result.get('state') == 'revoked' and result.get('credential_deletion') == 'not-attempted',
                'qualification.production.revoke')
        for context in [0, 1]:
            for host in [0, 1]:
                result = self.command(['credential-collect', '--state-dir', self.state(host, context)], administrative=True)
                closed(result, ['schema', 'deleted'])
                require(result['schema'] == 'auths.gateway-credential-collection/1'
                        and type(result['deleted']) is int and result['deleted'] >= 0,
                        'qualification.production.credential-collection')


class CommissioningChild:
    def __init__(self, deployment, arguments, witness):
        self.deployment, self.arguments, self.witness = deployment, arguments, witness
        self.canaries, self.process = deployment.canaries, None
        self.consumed = False

    def start(self):
        require(self.process is None and not self.consumed, 'qualification.production.child-consumed')
        self.deadline = time.monotonic() + 90
        self.process = subprocess.Popen([str(self.deployment.binary), *map(str, self.arguments)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=self.deployment.gateway, user=GATEWAY_UID, group=GATEWAY_UID, extra_groups=[],
            env=self.deployment.environment())

    def finish(self):
        require(self.process is not None and not self.consumed, 'qualification.production.child-consumed')
        try:
            stdout, stderr = self.process.communicate(timeout=max(0.01, self.deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            self.abort()
            raise Refusal('qualification.production.child-timeout') from None
        self.consumed = True
        result = subprocess.CompletedProcess([], self.process.returncode, stdout, stderr)
        return Deployment.commissioning_execution(native_output(result, self.canaries))

    def crash(self):
        require(self.process is not None and not self.consumed and self.process.poll() is None,
                'qualification.production.child-not-running')
        self.process.kill()
        stdout, stderr = self.process.communicate(timeout=10)
        self.consumed = True
        require(self.process.returncode == -signal.SIGKILL, 'qualification.production.child-crash')
        require(len(stdout) <= 65536 and len(stderr) <= 65536
                and all(value not in stdout + stderr for value in self.canaries),
                'qualification.production.secret-exposed')

    def abort(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.kill()
        if not self.consumed:
            self.process.communicate(timeout=10)
            self.consumed = True
