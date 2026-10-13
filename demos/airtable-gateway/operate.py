#!/usr/bin/env python3
"""Separate operator: disposable resources, independent trust, gateway installation."""
import argparse
import asyncio
import base64
import json
import os
import re
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time

from auths.self_hosted import (AssurancePolicy, AssuranceRequirement, Permission, Profile,
                              TrustAnchor, TrustedContextRequest, author_root_grant,
                              compile_trusted_context, load_signer_file)
from demo_common import Refusal, b64, canonical, decode, digest, read, require, write
from app import LABELS

HERE = Path(__file__).resolve().parent
HOME = Path('/run/demo')
APP_UID, APP_GID = 62004, 62005
ENVIRONMENT = {'PATH': '/opt/consumer/bin:/usr/local/bin:/usr/bin:/bin', 'PYTHONNOUSERSITE': '1'}


def input_credentials():
    raw = sys.stdin.buffer.read(8193)
    require(0 < len(raw) <= 8192, 'demo.credential-input-bound')
    values = decode(raw)
    require(type(values) is dict and set(values) == {'token'}, 'demo.development-pat-required')
    value = values['token']
    require(type(value) is str and value.startswith('pat') and 20 <= len(value) <= 2048
            and all(33 <= ord(char) <= 126 for char in value), 'demo.development-pat-required')
    # One owner-provided development PAT is shared by setup and gateway.
    # The app never receives it; this is explicitly not rotation/separation proof.
    return {'setup': value, 'runtime': value}



def cleanup_existing():
    require(os.getuid() == 0 and HOME.is_dir() and not HOME.is_symlink()
            and HOME.stat().st_uid == 0, 'demo.operator-private-session-required')
    require((HOME / 'resources.json').is_file(), 'demo.resource-journal-unavailable')
    keys = input_credentials()
    sys.path.insert(0, str(HERE / 'reference'))
    from airtable_resources import Resources
    Resources(keys['setup']).cleanup(HOME / 'resources.json')
    print('{"status":"run-owned-records-retired","table_and_base_retained":true}')


def child(command, *, stdin=b'', check=True):
    completed = subprocess.run(list(map(str, command)), input=stdin, capture_output=True,
                               timeout=90, env=ENVIRONMENT)
    if check:
        # Never forward provider/private diagnostic output to the web/app.
        require(completed.returncode == 0, 'demo.operator-command-refused:' + str(command[1]))
    return completed


def gateway(binary, *arguments):
    return child([binary, *arguments]).stdout


async def authority(binary, resources, directory, mode):
    app = directory / 'app'
    private = directory / 'private'
    for path in [app, private]:
        path.mkdir(mode=0o700)
    for name, parent in [('root', private), ('actor', app)]:
        write(parent / (name + '.seed'), secrets.token_bytes(32), new=True)
        write(parent / (name + '.json'), canonical({'schema': 'auths.approval-signer/1',
              'custody': 'development-ed25519', 'seed_file': name + '.seed'}), new=True)
    root = load_signer_file(private / 'root.json').signer
    actor = load_signer_file(app / 'actor.json').signer
    review = decode(gateway(binary, 'review', '--recipe', HERE / 'recipe.json',
                            '--profile-lock', HERE / 'profile.lock.json'))
    now, expires = int(time.time()), int(time.time()) + 3600
    audience = 'mcp://airtable-gateway-demo'
    permission = Permission('tools/call', audience + '/tools/set_demo_status_v1')
    policy = AssurancePolicy('raw-key-baseline', tuple(AssuranceRequirement(*row) for row in [
        ('root', 'every', 'self-certifying-identifier'),
        ('actor', 'every', 'self-certifying-identifier'),
        ('actor', 'every', 'offline-verifiable')]))
    grants = {}
    try:
        grant = await author_root_grant(signer=root, subject=actor.descriptor.principal,
            profile=Profile('auths.mcp', 2), permissions=[permission], audiences=[audience],
            not_before=now - 3600, expires_at=expires, remaining_depth=0,
            assurance_floor='raw-key-baseline', requested_at=now)
        grants['default'] = {'bytes': b64(grant.signed_grant), 'evidence': [
            {'type': item.evidence_type, 'media_type': item.media_type, 'bytes': b64(item.bytes)}
            for item in grant.evidence]}
        anchors = [TrustAnchor('operator-root', root.descriptor.principal, ('raw-key-v1',),
                   (Profile('auths.mcp', 2),), (permission,), (audience,), (audience,),
                   now - 3600, expires, 1, 'raw-key-baseline')]
        options = {'anchors': anchors, 'assurance': policy,
                   'configuration': bytes.fromhex(review['verifier_configuration']),
                   'evidence_types': ('raw-key-v1',), 'critical_extensions': ()}
        template = compile_trusted_context(**options)
        challenges = [secrets.token_bytes(32), secrets.token_bytes(32)]
        contexts = [compile_trusted_context(**options,
                    request=TrustedContextRequest(audience, challenge, now)) for challenge in challenges]
        cases = {}
        for index, label in enumerate(LABELS):
            cases[label] = {'arguments': {'operator_namespace': 'airtable-demo',
                'operation_id': label, 'recipe_digest': '0' * 64 if label == 'wrong-recipe' else review['recipe_digest'],
                'record_id': '..' if label == 'path-injection' else 'rec../other-record' if label == 'encoded-segment' else resources['records'][{'typescript-positive': 8, 'crash-before': 3, 'crash-after': 7}.get(label, index)],
                'replacement': 'Pending' if label == 'pending' else 'Rejected' if label == 'unsupported-value' else 'Approved'}}
        plan = {'schema': 'auths.airtable-gateway-demo/1', 'mode': mode,
                'trust': 'separate operator-issued development root and actor; no production trust claim',
                'expires_at': expires, 'recipe_digest': review['recipe_digest'],
                'base': resources['base'], 'table': resources['table'], 'view': resources['view'], 'grants': grants,
                'provider_credential_model': 'one owner-provided development PAT for operator and gateway' if mode == 'live' else 'independent simulation runtime and fixture credentials',
                'template': b64(template), 'contexts': list(map(b64, contexts)),
                'challenges': list(map(b64, challenges)), 'cases': cases}
        write(app / 'application.json', canonical(plan), new=True)
        for index, context in enumerate(contexts):
            write(private / ('context-' + str(index) + '.cbor'), context, new=True)
        for path in app.iterdir():
            os.chown(path, APP_UID, APP_GID)
        os.chown(app, APP_UID, APP_GID)
        return plan
    finally:
        await root.aclose()
        await actor.aclose()


class Operator:
    def __init__(self, mode):
        require(os.getuid() == 0, 'demo.operator-root-required')
        require(not HOME.exists(), 'demo.fresh-container-required')
        HOME.mkdir(mode=0o755)
        self.mode, self.processes, self.double, self.resources = mode, [], None, None
        self.binary = HERE / 'bin' / ('auths-gateway-simulation' if mode == 'simulation' else 'auths-gateway')
        self.keys, self.sockets = {}, HOME / 'sockets'
        self.sockets.mkdir(mode=0o750)
        os.chown(self.sockets, 0, APP_GID)
        self.port = None

    def start_gateway(self, host):
        socket_path = self.sockets / ('app' + str(host) + '.sock')
        socket_path.unlink(missing_ok=True)
        state = HOME / ('gateway' + str(host))
        (state / 'admin.sock').unlink(missing_ok=True)
        args = [self.binary, 'serve', '--state-dir', state, '--app-socket', socket_path]
        if self.port is not None:
            args.extend(['--loopback-provider', self.port])
        log = open(HOME / 'private' / ('gateway-' + str(host) + '.log'), 'ab')
        process = subprocess.Popen(list(map(str, args)), env=ENVIRONMENT, stdout=log, stderr=log)
        self.processes.append((process, log, host))
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            require(process.poll() is None, 'demo.gateway-start-refused')
            if socket_path.exists():
                os.chown(socket_path, 0, APP_GID)
                os.chmod(socket_path, 0o660)
                return
            time.sleep(0.05)
        raise Refusal('demo.gateway-start-timeout')

    def restart(self, host):
        for process, log, number in list(self.processes):
            if number == host:
                process.terminate()
                process.wait(timeout=10)
                log.close()
                self.processes.remove((process, log, number))
        self.start_gateway(host)

    def prepare(self):
        if self.mode == 'simulation':
            from double import BASE, TABLE, record_ids, serve
            token = 'pat_simulation_' + secrets.token_hex(24)
            self.keys = {'runtime': token}
            self.keys['fixture'] = 'pat_fixture_' + secrets.token_hex(24)
            self.double, self.fixture = serve(digest(token.encode()), HOME / 'provider.jsonl', self.keys['fixture'])
            self.port = self.double.server_address[1]
            resources = {'base': BASE, 'table': TABLE, 'view': None, 'records': record_ids()}
        else:
            self.keys = input_credentials()
            sys.path.insert(0, str(HERE / 'reference'))
            from airtable_resources import Resources
            from airtable_record import BASE, TABLE
            from resource_io import request
            schema = request('https://api.airtable.com', 'GET', '/v0/meta/bases/' + BASE + '/tables', self.keys['setup'])
            tables = [table for table in schema.get('tables', []) if table.get('id') == TABLE]
            require(len(tables) == 1, 'demo.disposable-table-unavailable')
            fields = {field.get('name'): field.get('type') for field in tables[0].get('fields', [])}
            require(all(fields.get(name) in ('singleLineText', 'multilineText')
                        for name in ['Name', 'DemoStatus', 'auths_echo']), 'demo.required-text-fields-unavailable')
            self.resources = Resources(self.keys['setup'])
            session = 'airtable-demo/' + str(int(time.time())) + '/1'
            self.resources.prepare(session, 16, HOME / 'resources.json', HOME / 'resource-pool.json')
            pool = decode(read(HOME / 'resource-pool.json'))
            resources = {'base': pool['base'], 'table': pool['table'], 'view': next((view.get('id') for view in tables[0].get('views', []) if re.fullmatch(r'viw[A-Za-z0-9]{14}', str(view.get('id')))), None), 'records': [value['id'] for value in pool['records']]}
            # Fresh runtime access checks precede any gateway application effect.
            for record in resources['records']:
                value = request('https://api.airtable.com', 'GET', '/v0/' + BASE + '/' + TABLE + '/' + record,
                                self.keys['runtime'])
                require(value.get('id') == record and value.get('fields', {}).get('DemoStatus') == 'Pending',
                        'demo.runtime-resource-access-refused')
        plan = asyncio.run(authority(self.binary, resources, HOME, self.mode))
        attempts = HOME / 'attempts'
        attempts.mkdir(mode=0o700)
        for host in range(3):
            state = HOME / ('gateway' + str(host))
            args = [self.binary, 'install', '--state-dir', state, '--recipe', HERE / 'recipe.json',
                    '--profile-lock', HERE / 'profile.lock.json', '--trusted-context',
                    HOME / 'private' / ('context-' + str(1 if host == 2 else 0) + '.cbor'), '--approve-digest', plan['recipe_digest'],
                    '--provider', 'airtable', '--alias', 'demo' + str(host), '--credential-stdin',
                    '--attempt-store', attempts, '--account-label', resources['base']]
            # All three share operation claims. Airtable has no recipe account
            # guard; live resource access is checked separately during setup.
            if self.port is not None:
                args.extend(['--loopback-provider', self.port])
            child(args, stdin=(self.keys['runtime'] + '\n').encode())
        # A shared software observer exists only in this labeled development
        # deployment. It is never a production signing-custody claim.
        gateway(self.binary, 'observer-init', '--state-dir', HOME / 'gateway0')
        for host in [1, 2]:
            write(HOME / ('gateway' + str(host)) / 'observer.seed', read(HOME / 'gateway0' / 'observer.seed'), new=True)
        self.observer = decode(gateway(self.binary, 'observer-show', '--state-dir', HOME / 'gateway0'))
        write(HOME / 'private' / 'pins.json', canonical({'trusted_context_sha256':
            digest(read(HOME / 'private' / 'context-0.cbor')), 'observer': self.observer}), new=True)
        for host in range(3):
            self.start_gateway(host)
        return plan

    def application(self, *arguments):
        return subprocess.run(['/opt/consumer/bin/python', str(HERE / 'app.py'), *arguments],
            env=ENVIRONMENT, capture_output=True, user=APP_UID, group=APP_GID, extra_groups=[], timeout=90)

    def witnesses(self):
        values = []
        for host in range(3):
            result = decode(gateway(self.binary, 'execution-witness', '--state-dir', HOME / ('gateway' + str(host))))
            require(result['ok'] is True, 'demo.execution-witness-refused')
            witness = result['execution_witness']
            require(witness['schema'] == 'auths.gateway-execution-witness/1', 'demo.execution-witness-invalid')
            values.append(witness)
        return values

    def stop(self):
        for process, log, _ in self.processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            log.close()
        self.processes.clear()
        if self.double:
            self.double.shutdown()
        if self.resources and (HOME / 'resources.json').exists():
            self.resources.cleanup(HOME / 'resources.json')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--live', action='store_true', help='Use the real provider with operator-only stdin credentials')
    parser.add_argument('--port', type=int, default=8081)
    parser.add_argument('--selftest', action='store_true')
    parser.add_argument('--cleanup', action='store_true')
    args = parser.parse_args()
    if args.cleanup:
        require(args.live and not args.selftest, 'demo.live-cleanup-required')
        cleanup_existing()
        return
    require(not args.selftest or not args.live, 'demo.selftest-simulation-only')
    operator = Operator('live' if args.live else 'simulation')
    def interrupted(*_):
        raise Refusal('demo.interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        operator.prepare()
        if args.selftest:
            from selftest import run
            run(operator)
        else:
            process = subprocess.Popen(['/opt/consumer/bin/python', str(HERE / 'app.py'),
                       'serve', '--port', str(args.port)], env=ENVIRONMENT,
                       user=APP_UID, group=APP_GID, extra_groups=[])
            operator.processes.append((process, open(os.devnull, 'wb'), -1))
            require(process.wait() == 0, 'demo.application-exited')
    except Refusal as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
    finally:
        operator.stop()


if __name__ == '__main__':
    main()
