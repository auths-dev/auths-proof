"""Disposable AWS custody drift under the retained operator identity.

Only the current secret derived from this installation's native journal can be
changed. The shared connection, host floors, qualification and attempt state
remain untouched. No remote enumeration or caller-selected name is accepted.
"""

from contextlib import contextmanager
import base64
import os
from pathlib import Path
import re
import subprocess
import time

from common import closed, Refusal, require, sha256
from expand import decode, read
from production_setup import GATEWAY_UID, KMS_KEY, REGION, private_file, native_output
from resource_io import write, write_bytes


def coordinates(namespace, connection, generation):
    require(type(namespace) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,63}', namespace)
            and type(connection) is str and re.fullmatch(r'conn_[A-Za-z0-9_-]{22}', connection)
            and type(generation) is int and 1 <= generation < 1 << 64, 'qualification.custody.reference')
    decoded = base64.urlsafe_b64decode(connection[5:] + '==')
    require(len(decoded) == 16 and base64.urlsafe_b64encode(decoded).rstrip(b'=').decode() == connection[5:],
            'qualification.custody.reference')
    number = generation.to_bytes(8, 'big')
    name = 'auths-gateway/' + sha256(b'auths.gateway-secret-name/1\0' + namespace.encode()
                                  + b'\0' + connection.encode() + b'\0' + number)
    return name, number


def reference(namespace, connection, generation, secret):
    require(type(secret) is bytes and 0 < len(secret) <= 65536, 'qualification.custody.reference')
    name, number = coordinates(namespace, connection, generation)
    commitment = sha256(b'auths.connection-credential-store/1\0' + connection.encode() + number + secret)
    version = sha256(b'auths.gateway-secret-version/1\0' + connection.encode() + b'\0'
                     + number + bytes.fromhex(commitment))
    return name, version, commitment


class Faults:
    def __init__(self, deployment):
        require(os.getuid() == 0, 'qualification.custody.identity')
        self.deployment = deployment
        self.root = deployment.private / 'custody-faults'
        require(not self.root.exists(), 'qualification.custody.directory')
        self.root.mkdir(mode=0o700)
        self.generation = 0

    def api(self, operation, arguments, *, required=True):
        require(operation in ['describe-secret', 'delete-secret', 'create-secret'],
                'qualification.custody.operation')
        supplied = self.deployment.environment(administrative=True)
        environment = {'PATH': '/usr/local/bin:/usr/bin:/bin',
            'AWS_ROLE_ARN': supplied['AWS_ROLE_ARN'],
            'AWS_WEB_IDENTITY_TOKEN_FILE': supplied['AWS_WEB_IDENTITY_TOKEN_FILE'],
            'AWS_REGION': REGION, 'AWS_DEFAULT_REGION': REGION, 'AWS_EC2_METADATA_DISABLED': 'true',
            'AWS_CONFIG_FILE': '/nonexistent-auths-aws-config',
            'AWS_SHARED_CREDENTIALS_FILE': '/nonexistent-auths-aws-credentials',
            'AWS_PAGER': '', 'AWS_CLI_AUTO_PROMPT': 'off', 'AWS_MAX_ATTEMPTS': '1'}
        result = subprocess.run(['aws', '--no-cli-pager', '--region', REGION,
            '--cli-connect-timeout', '5', '--cli-read-timeout', '10', 'secretsmanager', operation,
            *map(str, arguments)], cwd='/', stdin=subprocess.DEVNULL, capture_output=True,
            timeout=30, env=environment)
        require(len(result.stdout) <= 65536 and len(result.stderr) <= 65536
                and all(canary not in result.stdout + result.stderr for canary in self.deployment.canaries),
                'qualification.custody.private-output')
        if result.returncode != 0:
            require(not required, 'qualification.custody.aws-refused')
            if b'(ResourceNotFoundException)' in result.stderr:
                return {'missing': True}
            return None
        return decode(result.stdout)

    def present(self, name, version):
        value = self.api('describe-secret', ['--secret-id', name])
        require(value.get('Name') == name and type(value.get('VersionIdsToStages')) is dict
                and version in value['VersionIdsToStages'] and not value.get('DeletedDate'),
                'qualification.custody.exact-version')

    def delete(self, name):
        value = self.api('delete-secret', ['--secret-id', name, '--force-delete-without-recovery'], required=False)
        require(value is not None and (value.get('Name') == name or value == {'missing': True}),
                'qualification.custody.exact-name')

    def create(self, name, version, payload):
        # AWS may retain a force-deleted name briefly. Retries select identical
        # immutable bytes and the same explicit version, never another secret.
        for attempt in range(4):
            value = self.api('create-secret', ['--name', name, '--client-request-token', version,
                '--kms-key-id', KMS_KEY, '--secret-binary', 'fileb://' + str(payload)], required=False)
            if value is not None and value != {'missing': True}:
                require(value.get('Name') == name and value.get('VersionId') == version,
                        'qualification.custody.exact-version')
                self.present(name, version)
                return
            if attempt < 3:
                time.sleep(2)
        raise Refusal('qualification.custody.restore-required')

    def current(self, credential):
        state = self.deployment.state(0)
        notes = decode(read(private_file(state / 'credential-journal.json', GATEWAY_UID), 4096))
        closed(notes, ['schema', 'connection_id', 'generations'])
        require(notes['schema'] == 'auths.gateway-credential-journal/1'
                and type(notes['generations']) is list and 1 <= len(notes['generations']) <= 64
                and all(type(value) is int and 1 <= value < 1 << 64 for value in notes['generations'])
                and notes['generations'] == sorted(set(notes['generations'])), 'qualification.custody.journal')
        response = self.deployment.command(['status', '--state-dir', state])
        require(response.get('ok') is True and response.get('code') == 'gateway.admin.status',
                'qualification.custody.native-status')
        status = response['status']
        generation = status['credential_generation']
        require(status['state'] == 'active' and status['credential_held'] is True and status['in_flight'] == 0
                and generation in notes['generations'] and status['generation'] >= generation,
                'qualification.custody.current-credential')
        name, version, commitment = reference(self.deployment.namespace, notes['connection_id'], generation, credential)
        self.present(name, version)
        return notes['connection_id'], generation, name, version, commitment

    @contextmanager
    def drift(self, kind, credential, successor):
        require(kind in ['generation', 'commitment', 'version'] and credential != successor
                and credential in self.deployment.canaries and successor in self.deployment.canaries,
                'qualification.custody.fault')
        connection, generation, name, version, _commitment = self.current(credential)
        self.generation += 1
        private = self.root / str(self.generation)
        private.mkdir(mode=0o700)
        original, altered = private / 'original', private / 'altered'
        write_bytes(original, credential, new=True)
        replacement_version = version
        if kind == 'generation':
            response = self.deployment.command(['rotate-prepare', '--state-dir', self.deployment.state(0),
                '--credential-stdin', '--operator-process'], administrative=True, secret=successor + b'\n')
            next_name, next_version, next_commitment = reference(self.deployment.namespace, connection,
                                                                generation + 1, successor)
            require(response.get('ok') is True and response.get('code') == 'gateway.admin.rotation-prepared'
                    and response.get('commitment') == next_commitment, 'qualification.custody.prepared-generation')
            self.present(next_name, next_version)
        elif kind == 'commitment':
            write_bytes(altered, b'qualification-fixture-incorrect-credential-bytes', new=True)
        else:
            # The same authorized bytes under a different actual immutable
            # version cannot satisfy the exact recorded version request.
            replacement_version = ('0' if version[0] != '0' else '1') + version[1:]
            write_bytes(altered, credential, new=True)
        # Retain the exact restoration obligation before the first deletion.
        write(private / 'obligation.json', {'schema': 'auths.qualification-custody-restoration/1',
            'connection_id': connection, 'generation': generation, 'name': name, 'version': version,
            'kind': kind, 'restored': False}, new=True)
        deleted = False
        try:
            # A transport exception can follow an accepted delete, so every
            # attempted deletion creates an unconditional restoration duty.
            deleted = True
            self.delete(name)
            if kind != 'generation':
                self.create(name, replacement_version, altered)
            yield
        finally:
            if deleted:
                if kind != 'generation':
                    self.delete(name)
                self.create(name, version, original)
                restored = self.current(credential)
                require(restored[:4] == (connection, generation, name, version),
                        'qualification.custody.restoration-binding')
                write(private / 'obligation.json', {'schema': 'auths.qualification-custody-restoration/1',
                    'connection_id': connection, 'generation': generation, 'name': name, 'version': version,
                    'kind': kind, 'restored': True})
            original.unlink(missing_ok=True)
            altered.unlink(missing_ok=True)

    def kind(self):
        state = self.deployment.gateway / 'refused-plaintext-install'
        require(not state.exists(), 'qualification.custody.directory')
        arguments = ['install', '--state-dir', state,
            '--recipe', self.deployment.gateway / 'recipe.json',
            '--profile-lock', self.deployment.gateway / 'profile.lock.json',
            '--trusted-context', self.deployment.gateway / 'context-0.cbor',
            '--approve-digest', self.deployment.tuple['compiled_recipe_sha256'],
            '--provider', self.deployment.provider, '--alias', 'qualification',
            '--join',
            '--credential-stdin', '--deployment', 'production', '--credential-store', 'local-file-v1']
        result = subprocess.run([str(self.deployment.binary), *map(str, arguments)], input=b'',
            capture_output=True, timeout=30, cwd='/', user=GATEWAY_UID, group=GATEWAY_UID,
            extra_groups=[], env=self.deployment.environment())
        native_output(result, self.deployment.canaries, required=False)
        require(result.returncode == 1 and result.stdout == b''
                and result.stderr == b'gateway.credential.production-plaintext-refused\n'
                and not state.exists(), 'qualification.custody.kind-not-refused')

    def retire_partial(self, infrastructure):
        # This source reference owns the entire disposable database. Removing
        # it first makes an ambiguously committed incomplete install unusable.
        # A complete cohort must use native revocation and collection instead.
        require(not self.deployment.processes and len(self.deployment.installations) < 4
                and infrastructure.container is None, 'qualification.custody.partial-not-stopped')
        names, connections = set(), set()
        for context in [0, 1]:
            for host in [0, 1]:
                path = self.deployment.state(host, context) / 'credential-journal.json'
                if not path.exists() and not path.is_symlink():
                    # Native source registers this journal before any create.
                    continue
                notes = decode(read(private_file(path, GATEWAY_UID), 4096))
                closed(notes, ['schema', 'connection_id', 'generations'])
                require(notes['schema'] == 'auths.gateway-credential-journal/1'
                        and type(notes['connection_id']) is str
                        and type(notes['generations']) is list and len(notes['generations']) <= 16
                        and all(type(generation) is int and 1 <= generation < 1 << 64
                                for generation in notes['generations'])
                        and notes['generations'] == sorted(set(notes['generations'])),
                        'qualification.custody.journal')
                connections.add(notes['connection_id'])
                coordinates(self.deployment.namespace, notes['connection_id'], 1)
                for generation in notes['generations']:
                    names.add(coordinates(self.deployment.namespace, notes['connection_id'], generation)[0])
        require(len(connections) <= 1 and len(names) <= 16, 'qualification.custody.partial-bound')
        failures = []
        for name in sorted(names):
            try:
                self.delete(name)
            except (Refusal, OSError, subprocess.SubprocessError):
                failures.append(True)
        require(not failures, 'qualification.custody.partial-cleanup-incomplete')
