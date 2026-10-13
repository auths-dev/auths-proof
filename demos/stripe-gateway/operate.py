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
PRIVATE = HOME / 'private'
JOURNAL = PRIVATE / 'resources.json'
POOL = PRIVATE / 'resource-pool.json'
APP_UID, APP_GID = 62004, 62005
ENVIRONMENT = {'PATH': '/opt/consumer/bin:/usr/local/bin:/usr/bin:/bin', 'PYTHONNOUSERSITE': '1'}


def input_credentials():
    raw = sys.stdin.buffer.read(8193)
    require(0 < len(raw) <= 8192, 'demo.credential-input-bound')
    values = decode(raw)
    require(type(values) is dict and set(values) == {'setup', 'runtime'}, 'demo.test-keys-required')
    for name, prefix in [('setup', 'sk_test_'), ('runtime', 'rk_test_')]:
        value = values[name]
        require(type(value) is str and value.startswith(prefix) and 20 <= len(value) <= 2048
                and all(33 <= ord(char) <= 126 for char in value), 'demo.test-keys-required')
    return values


def cleanup_existing():
    require(os.getuid() == 0 and HOME.is_dir() and not HOME.is_symlink()
            and HOME.stat().st_uid == 0, 'demo.operator-private-session-required')
    require(JOURNAL.is_file(), 'demo.resource-journal-unavailable')
    keys = input_credentials()
    sys.path.insert(0, str(HERE / 'reference'))
    from stripe_resources import Resources
    Resources(keys).cleanup(JOURNAL)
    print('{"status":"run-owned-test-payments-retired","stripe_records_retained":true}')


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
    app.mkdir(mode=0o700)
    require(private.is_dir() and not private.is_symlink() and private.stat().st_uid == 0
            and private.stat().st_mode & 0o777 == 0o700, 'demo.operator-private-directory-required')
    for name, parent in [('root', private), ('actor', app)]:
        write(parent / (name + '.seed'), secrets.token_bytes(32), new=True)
        write(parent / (name + '.json'), canonical({'schema': 'auths.approval-signer/1',
              'custody': 'development-ed25519', 'seed_file': name + '.seed'}), new=True)
    root = load_signer_file(private / 'root.json').signer
    actor = load_signer_file(app / 'actor.json').signer
    review = decode(gateway(binary, 'review', '--recipe', HERE / 'recipe.json',
                            '--profile-lock', HERE / 'profile.lock.json'))
    now, expires = int(time.time()), int(time.time()) + 3600
    audience = 'mcp://stripe-platform-refunds'
    permission = Permission('tools/call', audience + '/tools/create_refund_v1')
    policy = AssurancePolicy('raw-key-baseline', tuple(AssuranceRequirement(*row) for row in [
        ('root', 'every', 'self-certifying-identifier'),
        ('actor', 'every', 'self-certifying-identifier'),
        ('actor', 'every', 'offline-verifiable')]))
    grants, limits, extension_id = {}, {}, None
    try:
        for name, window, count, capacity in [('default', 86400, 32, 32000),
                                               ('count', 172800, 1, 4000), ('sum', 259200, 4, 1000)]:
            bound = decode(gateway(binary, 'bound-extension', '--argument', 'amount', '--ceiling', '2000',
                '--window-seconds', window, '--max-count', count, '--sum-limit', capacity,
                '--partition', 'currency=eur,usd', '--scope', 'payment_intent=' + ','.join(resources['payments'])))
            extension_id = bound['extension_id']
            grant = await author_root_grant(signer=root, subject=actor.descriptor.principal,
                profile=Profile('auths.mcp', 2), permissions=[permission], audiences=[audience],
                not_before=now - 3600, expires_at=expires, remaining_depth=0,
                assurance_floor='raw-key-baseline', requested_at=now,
                critical_extensions=[(extension_id, bytes.fromhex(bound['extension_body_hex']))])
            grants[name] = {'bytes': b64(grant.signed_grant), 'evidence': [
                {'type': item.evidence_type, 'media_type': item.media_type, 'bytes': b64(item.bytes)}
                for item in grant.evidence]}
            limits[name] = {'count': count, 'sum': capacity, 'ceiling': 2000, 'window_seconds': window}
        anchors = [TrustAnchor('operator-root', root.descriptor.principal, ('raw-key-v1',),
                   (Profile('auths.mcp', 2),), (permission,), (audience,), (audience,),
                   now - 3600, expires, 1, 'raw-key-baseline')]
        options = {'anchors': anchors, 'assurance': policy,
                   'configuration': bytes.fromhex(review['verifier_configuration']),
                   'evidence_types': ('raw-key-v1',), 'critical_extensions': (extension_id,)}
        template = compile_trusted_context(**options)
        challenges = [secrets.token_bytes(32), secrets.token_bytes(32)]
        contexts = [compile_trusted_context(**options,
                    request=TrustedContextRequest(audience, challenge, now)) for challenge in challenges]
        cases = {}
        for index, label in enumerate(LABELS):
            grant = 'count' if label.startswith('count-') else 'sum' if label.startswith('sum-') else 'default'
            amount = 2001 if label == 'above-grant' else 1001 if label == 'above-boundary' else \
                     500 if label == 'count-overflow' else 1 if label == 'sum-overflow' else 1000
            cases[label] = {'grant': grant, 'arguments': {'operator_namespace': 'stripe-platform-refunds',
                'operation_id': label, 'recipe_digest': review['recipe_digest'],
                'payment_intent': resources['payments'][index], 'amount': amount,
                'currency': 'eur' if label == 'wrong-currency' else 'usd'}}
        plan = {'schema': 'auths.stripe-gateway-demo/1', 'mode': mode,
                'trust': 'separate operator-issued development root and actor; no production trust claim',
                'expires_at': expires, 'recipe_digest': review['recipe_digest'],
                'platform': resources['platform'], 'limits': limits, 'grants': grants,
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
        PRIVATE.mkdir(mode=0o700)
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
            from double import PLATFORM, serve
            token = 'rk_test_simulation_' + secrets.token_hex(24)
            self.keys = {'runtime': token}
            ledger = HOME / 'provider.jsonl'
            self.double, _, self.refunds = serve(digest(token.encode()), ledger)
            self.port = self.double.server_address[1]
            resources = {'platform': PLATFORM, 'payments': [f'pi_demo_{index:02}' for index in range(16)]}
        else:
            # Only the operator sees stdin credentials; the app has an allowlist environment.
            self.keys = input_credentials()
            # These reviewed release-only helpers are copied into the operator kit,
            # not imported into the application or gateway runtime.
            sys.path.insert(0, str(HERE / 'reference'))
            from stripe_resources import Resources
            self.resources = Resources(self.keys)
            session = 'stripe-demo/' + str(int(time.time())) + '/1'
            journal = JOURNAL
            self.resources.prepare(session, 16, journal, POOL)
            pool = decode(read(POOL))
            resources = {'platform': pool['platform'], 'payments': [value['id'] for value in pool['payments']]}
        plan = asyncio.run(authority(self.binary, resources, HOME, self.mode))
        attempts = HOME / 'attempts'
        attempts.mkdir(mode=0o700)
        for host in range(3):
            state = HOME / ('gateway' + str(host))
            args = [self.binary, 'install', '--state-dir', state, '--recipe', HERE / 'recipe.json',
                    '--profile-lock', HERE / 'profile.lock.json', '--trusted-context',
                    HOME / 'private' / ('context-' + str(1 if host == 2 else 0) + '.cbor'), '--approve-digest', plan['recipe_digest'],
                    '--provider', 'stripe', '--alias', 'demo' + str(host), '--credential-stdin',
                    '--attempt-store', attempts, '--account-label', resources['platform']]
            # Each installation checks the account and restricted credential.
            # All three share the operation/budget store; no simulation join
            # may accidentally probe the live provider with a synthetic key.
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
        if self.resources and JOURNAL.exists():
            self.resources.cleanup(JOURNAL)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--live', action='store_true', help='Use the real provider with operator-only stdin credentials')
    parser.add_argument('--port', type=int, default=8080)
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
    try:
        main()
    except ValueError as error:
        code = str(error)
        if not re.fullmatch(r'(?:demo|qualification)\.[a-z0-9.-]+(?::[a-z0-9-]+)?', code):
            code = 'demo.operator-input-refused'
        print(code, file=sys.stderr)
        raise SystemExit(1) from None
