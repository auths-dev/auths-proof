#!/usr/bin/env python3
"""Source-free live-provider rehearsal with an isolated installed SDK consumer.

This is development evidence, not a protected production qualification.
The operator reads the PAT; the application receives only proof and action.
"""
import argparse
import asyncio
import concurrent.futures
import base64
from dataclasses import asdict
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid


class Refusal(Exception):
    pass


def require(value, code):
    if not value:
        raise Refusal(code)


def canonical(value):
    # The signature statement contains only ASCII strings and booleans.
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def author_packet(native, arguments, configuration):
    """Author disposable trust using native primitives and the reviewed gateway pin."""
    current = int(time.time())
    audience = 'mcp://airtable-gateway-demo'
    resource = audience + '/tools/set_demo_status_v1'
    key = native.DevelopmentEd25519Key.generate()
    actor = native.Principal(key.principal)
    request = native.GrantRequest(actor, 'auths.mcp', 2, [('tools/call', resource)],
        current - 60, current + 600, [audience], None, None, 0, None, 'raw-key-baseline', [])
    grant_unsigned = native.root_grant(actor, request)
    signing = native.prepare_signing(grant_unsigned, key.principal_method, key.verification_method, key.suite)
    grant = signing.complete(key.sign(signing.signing_preimage))
    challenge = native.generate_challenge_v1()
    call = native.mcp_call('airtable-gateway-demo', 'set_demo_status_v1', canonical(arguments))
    prepared = native.prepare_mcp_call_action(call, actor, grant, challenge, current, 30)
    signing = native.prepare_signing(prepared.unsigned, key.principal_method, key.verification_method, key.suite)
    action = signing.complete(key.sign(signing.signing_preimage))
    assurance = native.AssurancePolicy('raw-key-baseline', [
        ('root', 'every', 'self-certifying-identifier', None),
        ('actor', 'every', 'self-certifying-identifier', None),
        ('actor', 'every', 'offline-verifiable', None)])
    anchor = native.TrustAnchor(actor.value, actor, [key.principal_method], [('auths.mcp', 2)],
        [('tools/call', resource)], [audience], [audience], current - 60, current + 600,
        None, 1, 'raw-key-baseline', None)
    template = native.compile_trusted_context(configuration, None, 1, 1, 1, [anchor], assurance,
        None, None, 'none-v1', [key.evidence_type], [])
    context = template.bind_request(audience, challenge, current)
    evidence = (key.evidence_type, key.media_type, key.evidence)
    return native.assemble_mcp_proof(prepared, action, [grant], [[evidence]], [evidence], context)


def consumer(verb, work, socket):
    from auths import _native
    from auths.gateway import GatewayClient, GatewayEndpoint
    require('PERSONAL_ACCESS_TOKEN' not in os.environ and 'PYTHONPATH' not in os.environ,
            'live.consumer-environment')
    if verb == 'author':
        args = json.loads((work / 'arguments.json').read_text())
        packet = author_packet(_native, args, bytes.fromhex((work / 'configuration').read_text()))
        for name, data in zip(['proof.cbor', 'action.cbor', 'context.cbor'], packet):
            (work / name).write_bytes(data)
        print(json.dumps({'sdk_location': __import__('auths').__file__, 'sdk_version': importlib.metadata.version('auths')}))
    elif verb == 'isolation':
        for label, path in [('credential', '/run/provider-secret/provider.env'), ('first-state', '/run/operator/first'), ('second-state', '/run/operator/second')]:
            try:
                Path(path).read_bytes() if path.endswith('.env') else list(Path(path).iterdir())
            except PermissionError:
                continue
            raise Refusal('live.application-can-read-' + label)
        print('{"isolated":true}')
    elif verb == 'sign':
        report = (work / 'airtable-record-update-v1.json').read_bytes()
        key = _native.DevelopmentEd25519Key.generate()
        enc = lambda data: base64.b64encode(data).rstrip(b'=').decode()
        statement = {'schema': 'auths.provider-simulation-attestation/1', 'simulation': True,
                     'stable_launch_ready': False, 'signer_kind': 'disposable-self-signed-simulation-key',
                     'family': 'airtable-record-update-v1', 'report_sha256': hashlib.sha256(report).hexdigest(),
                     'public_key_b64': enc(bytes(key.public_key))}
        preimage = b'auths.provider-simulation-attestation/1\0' + canonical(statement)
        signature = bytes(key.sign(preimage))
        _native.verify_ed25519_preimage_v1(bytes(key.public_key), preimage, signature)
        path = work / 'airtable-record-update-v1.attestation.json'
        path.write_bytes(json.dumps({'statement': statement, 'signature_b64': enc(signature)}, indent=2).encode())
        # Re-read published bytes and verify the exact digest and signature.
        published = json.loads(path.read_bytes())
        require(published['statement']['report_sha256'] == hashlib.sha256((work / 'airtable-record-update-v1.json').read_bytes()).hexdigest(),
                'live.signature-report-mismatch')
        _native.verify_ed25519_preimage_v1(base64.b64decode(published['statement']['public_key_b64'] + '=='),
            b'auths.provider-simulation-attestation/1\0' + canonical(published['statement']),
            base64.b64decode(published['signature_b64'] + '=='))
        print('{"persisted_signature_verified":true}')
    else:
        action = (work / 'action.cbor').read_bytes()
        if verb == 'altered':
            action += b'\0'
        result = asyncio.run(GatewayClient(GatewayEndpoint(socket)).submit(
            proof=(work / 'proof.cbor').read_bytes(), action=action))
        print(json.dumps(asdict(result), sort_keys=True))


class Operator:
    uid, gid, app_uid = 62001, 62000, 62002

    def __init__(self, args):
        self.args, self.processes, self.steps = args, [], []
        self.binary = args.package / 'bin/auths-gateway'
        self.python = Path('/opt/consumer/bin/python')
        self.work, self.app = Path('/run/operator'), Path('/run/app')
        self.record = None
        self.token = None
        self.env = {'PATH': '/usr/bin:/bin', 'PYTHONNOUSERSITE': '1'}

    def scan(self, data):
        if self.token:
            token = self.token.encode()
            require(not any(v in data for v in [token, token.hex().encode(), base64.b64encode(token),
                base64.urlsafe_b64encode(token)]), 'live.secret-exposure')

    def run(self, label, argv, stdin=b'', uid=None, allowed=(0,)):
        start = time.monotonic()
        result = subprocess.run(list(map(str, argv)), input=stdin, capture_output=True, timeout=60,
            env=self.env, cwd='/run', user=self.uid if uid is None else uid, group=self.gid, extra_groups=[])
        self.scan(result.stdout + result.stderr)
        require(len(result.stdout) + len(result.stderr) < 1048576, 'live.output-bound')
        if result.returncode not in allowed:
            codes = re.findall(rb'live\.[a-z0-9-]+', result.stderr)
            raise Refusal('live.command-refused:' + label + (':' + codes[-1].decode() if codes else ''))
        self.steps.append({'case': label, 'seconds': round(time.monotonic() - start, 3),
                           'exit_code': result.returncode})
        return result.stdout

    def child(self, verb, socket=None):
        return [self.python, Path(__file__).resolve(), '--consumer', verb,
                '--consumer-work', self.app, '--consumer-socket', socket or '/run/sockets/first.sock']

    def api(self, method, suffix, body=None):
        require(suffix.startswith('/v0/'), 'live.invalid-api-path')
        data = None if body is None else canonical(body)
        request = urllib.request.Request('https://api.airtable.com' + suffix, data=data, method=method,
            headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=25) as response:
                payload = response.read(65537)
                require(len(payload) <= 65536, 'live.provider-response-bound')
                return json.loads(payload)
        except urllib.error.HTTPError as error:
            raise Refusal('live.airtable-http-' + str(error.code)) from None

    def install(self, state, digest, join=False):
        argv = [self.binary, 'install', '--state-dir', state, '--recipe', self.work / 'recipe.json',
                '--profile-lock', self.work / 'profile.lock.json', '--trusted-context', self.app / 'context.cbor',
                '--approve-digest', digest, '--provider', 'airtable', '--alias', 'live-rehearsal',
                '--attempt-store', self.work / 'store', '--credential-stdin']
        argv += ['--join'] if join else ['--account-label', self.args.base]
        self.run('join' if join else 'install', argv, stdin=(self.token + '\n').encode())

    def start(self, name):
        sock = Path('/run/sockets') / (name + '.sock')
        log = tempfile.TemporaryFile()
        process = subprocess.Popen([str(self.binary), 'serve', '--state-dir', str(self.work / name),
            '--app-socket', str(sock)], stdout=subprocess.PIPE, stderr=log, env=self.env, cwd='/run',
            user=self.uid, group=self.gid, extra_groups=[])
        self.processes.append((process, log))
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            require(bool(selector.select(15)), 'live.gateway-start-timeout')
            ready = process.stdout.readline(65537)
        self.scan(ready)
        require(ready.startswith(b'app socket ready'), 'live.gateway-start-refused')
        return sock

    def stop(self):
        for process, log in self.processes:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise Refusal('live.gateway-stop-timeout')
            log.seek(0)
            self.scan(log.read(1048577))
            require(process.returncode == 0, 'live.gateway-stop-refused')
            log.close()
            process.stdout.close()
        self.processes.clear()

    def exercise(self):
        require(os.getuid() == 0, 'live.requires-container-root')
        require(not self.args.out.exists(), 'live.output-must-be-new')
        self.args.out.mkdir(parents=True)
        manifest = json.loads((self.args.package / 'manifest.json').read_text())
        require(manifest['source_commit'] == self.args.commit, 'live.candidate-commit-mismatch')
        for entry in manifest['files']:
            path = self.args.package / entry['path']
            require(not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest() == entry['sha256'],
                    'live.package-hash-mismatch')
        require(re.fullmatch(r'app[A-Za-z0-9]{14}', self.args.base) and re.fullmatch(r'tbl[A-Za-z0-9]{14}', self.args.table),
                'live.invalid-resource')
        require(self.args.credential_stdin and not sys.stdin.isatty(), 'live.credential-stdin-required')
        credential = sys.stdin.buffer.read(8193)
        require(len(credential) <= 8192, 'live.credential-input-bound')
        private = Path('/run/provider-secret')
        private.mkdir(mode=0o700)
        descriptor = os.open(private / 'provider.env', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(credential)
        for line in credential.decode().splitlines():
            match = re.fullmatch(r'\s*PERSONAL_ACCESS_TOKEN\s*=\s*(.*?)\s*', line)
            if match:
                self.token = match[1].strip('"\'')
        require(self.token and self.token.startswith('pat'), 'live.missing-pat')
        for path, uid, mode in [(self.work, self.uid, 0o700), (self.app, self.app_uid, 0o750),
                                (Path('/run/sockets'), self.uid, 0o770)]:
            path.mkdir(mode=mode)
            os.chown(path, uid, self.gid)
        recipe = json.loads((self.args.inputs / 'recipe.json').read_bytes())
        for member in ['write', 'observation']:
            recipe[member]['path'][1]['value'] = self.args.base
            recipe[member]['path'][2]['value'] = self.args.table
        (self.work / 'recipe.json').write_bytes(canonical(recipe))
        (self.work / 'profile.lock.json').write_bytes((self.args.inputs / 'profile.lock.json').read_bytes())
        for path in self.work.iterdir():
            os.chown(path, self.uid, self.gid)
        review = json.loads(self.run('review', [self.binary, 'review', '--recipe', self.work / 'recipe.json',
            '--profile-lock', self.work / 'profile.lock.json']))
        record = self.api('POST', '/v0/' + self.args.base + '/' + self.args.table,
                         {'fields': {'Name': 'Auths disposable qualification ' + str(uuid.uuid4()), 'DemoStatus': 'Pending'}})
        self.record = record['id']
        require(re.fullmatch(r'rec[A-Za-z0-9]{14}', self.record), 'live.invalid-created-record')
        operation = str(uuid.uuid4())
        args = {'operator_namespace': 'airtable-demo', 'operation_id': operation,
                'recipe_digest': review['recipe_digest'], 'record_id': self.record, 'replacement': 'Approved'}
        (self.app / 'configuration').write_text(review['verifier_configuration'])
        (self.app / 'arguments.json').write_bytes(canonical(args))
        os.chown(self.app / 'arguments.json', self.app_uid, self.gid)
        authored = json.loads(self.run('installed-consumer-author', self.child('author'), uid=self.app_uid))
        require(authored['sdk_location'].startswith('/opt/consumer/lib/'), 'live.repository-import')
        self.install(self.work / 'first', review['recipe_digest'])
        self.install(self.work / 'second', review['recipe_digest'], join=True)
        first, second = self.start('first'), self.start('second')
        self.run('application-secret-isolation', self.child('isolation'), uid=self.app_uid)
        # Distinct processes share the actual durable store. Both receive the
        # same signed action; the gateway's durable claim chooses entry.
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.run, 'two-instance-submit-' + str(index), self.child('submit', sock),
                                  uid=self.app_uid) for index, sock in enumerate([first, second])]
            results = [json.loads(future.result()) for future in futures]
        require(any(value.get('outcome') == 'observed-by-provider' for value in results), 'live.write-not-observed')
        require(all(value.get('outcome') in ['observed-by-provider', 'not-entered'] for value in results),
                'live.race-unexpected-outcome')
        observed = next(value for value in results if value.get('outcome') == 'observed-by-provider')
        readback = self.api('GET', '/v0/' + self.args.base + '/' + self.args.table + '/' + self.record)
        require(readback['fields']['DemoStatus'] == 'Approved' and
                readback['fields']['auths_echo'] == observed['evidence']['echo'], 'live.fresh-read-back-mismatch')
        replay = json.loads(self.run('proof-replay', self.child('submit', first), uid=self.app_uid))
        require(replay.get('outcome') == 'not-entered' and replay.get('code') == 'gateway.attempt.replay', 'live.replay-not-refused')
        altered = json.loads(self.run('altered-action', self.child('altered', first), uid=self.app_uid))
        require(altered.get('outcome') in ['not-entered', 'denied', 'indeterminate'], 'live.altered-action-entered')
        support = self.run('support-bundle', [self.binary, 'support-bundle', '--state-dir', self.work / 'first'])
        require(json.loads(support)['deployment'] == 'development', 'live.production-claim')
        (self.args.out / 'support-bundle.json').write_bytes(support)
        self.stop()
        restarted = self.start('first')
        replay_after = json.loads(self.run('restart-replay', self.child('submit', restarted), uid=self.app_uid))
        require(replay_after.get('outcome') == 'not-entered' and replay_after.get('code') == 'gateway.attempt.replay',
                'live.restart-replay-entered')
        self.stop()
        report = {'schema': 'auths.recipe-qualification-simulation/1', 'simulation': True,
            'stable_launch_ready': False, 'family': 'airtable-record-update-v1',
            'provider': 'live Airtable Web API v0', 'verification_boundary': 'installed SDK and native application socket',
            'source_commit': self.args.commit, 'gateway_sha256': hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            'compiled_recipe_sha256': review['recipe_digest'], 'sdk_location': authored['sdk_location'],
            'sdk_version': authored['sdk_version'], 'wheel_sha256': hashlib.sha256(self.args.wheel.read_bytes()).hexdigest(),
            'store': 'shared-file-v1', 'custody': 'local-file-v1', 'clock': 'development-host-clock',
            'resources': {'base': self.args.base, 'table': self.args.table, 'record': self.record},
            'results': {'race': results, 'proof_replay': replay, 'altered_action': altered, 'restart_replay': replay_after,
                        'fresh_read_back': {'replacement_matches': True, 'echo_matches': True}},
            'cases': self.steps,
            'excluded_claims': ['protected production qualification', 'production PostgreSQL/AWS custody',
                'complete qualification corpus', 'independent provider-entry and lease counters', 'token restriction to one base']}
        return report

    def cleanup(self):
        try:
            self.stop()
        finally:
            if self.record:
                result = self.api('DELETE', '/v0/' + self.args.base + '/' + self.args.table + '/' + self.record)
                require(result.get('deleted') is True and result.get('id') == self.record, 'live.cleanup-refused')
                self.record = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--consumer', choices=['author', 'submit', 'altered', 'isolation', 'sign'])
    parser.add_argument('--consumer-work', type=Path)
    parser.add_argument('--consumer-socket', type=Path)
    parser.add_argument('--package', type=Path)
    parser.add_argument('--inputs', type=Path)
    parser.add_argument('--wheel', type=Path)
    parser.add_argument('--credential-stdin', action='store_true')
    parser.add_argument('--base')
    parser.add_argument('--table')
    parser.add_argument('--commit')
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    try:
        if args.consumer:
            consumer(args.consumer, args.consumer_work, args.consumer_socket)
            return
        operator = Operator(args)
        def interrupted(_signal, _frame):
            raise Refusal('live.interrupted')
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        try:
            report = operator.exercise()
        finally:
            operator.cleanup()
        report['cleanup'] = {'created_record_deleted': True, 'table_retained_for_future_rehearsals': True}
        data = json.dumps(report, indent=2).encode()
        operator.scan(data)
        (args.out / 'airtable-record-update-v1.json').write_bytes(data)
        # Sign with the installed SDK's existing Ed25519 primitive. No key is
        # serialized or given protected qualification authority.
        operator.run('sign-published-report', [operator.python, Path(__file__).resolve(), '--consumer', 'sign',
            '--consumer-work', args.out], uid=0)
        print('Live Airtable rehearsal passed; fresh read-back, replay refusals, isolation, cleanup and report signature verified.')
    except Refusal as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
