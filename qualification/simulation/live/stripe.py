#!/usr/bin/env python3
"""Live platform-account refund rehearsal; Connect is outside this tuple."""
import argparse
import asyncio
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
import urllib.parse
import urllib.request
import uuid


class Refusal(Exception):
    pass


def require(value, code):
    if not value:
        raise Refusal(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def consumer(args):
    from auths import _native as native
    from auths.gateway import GatewayClient, GatewayEndpoint
    require('STRIPE_TEST_API_KEY' not in os.environ and 'STRIPE_TEST_RESTRICTED_KEY' not in os.environ
            and 'PYTHONPATH' not in os.environ, 'live.consumer-environment')
    work = args.consumer_work
    if args.consumer == 'author':
        plan = json.loads((work / 'plan.json').read_bytes())
        current = int(time.time())
        audience = 'mcp://stripe-platform-refunds'
        resource = audience + '/tools/create_refund_v1'
        key = native.DevelopmentEd25519Key.generate()
        actor = native.Principal(key.principal)
        extension = plan['extension']
        ext = [(extension['extension_id'], bytes.fromhex(extension['extension_body_hex']))]
        request = native.GrantRequest(actor, 'auths.mcp', 2, [('tools/call', resource)], current - 60,
            current + 600, [audience], None, None, 0, None, 'raw-key-baseline', ext)
        unsigned = native.root_grant(actor, request)
        signing = native.prepare_signing(unsigned, key.principal_method, key.verification_method, key.suite)
        grant = signing.complete(key.sign(signing.signing_preimage))
        challenge = native.generate_challenge_v1()
        anchor = native.TrustAnchor(actor.value, actor, [key.principal_method], [('auths.mcp', 2)],
            [('tools/call', resource)], [audience], [audience], current - 60, current + 600,
            None, 1, 'raw-key-baseline', None)
        assurance = native.AssurancePolicy('raw-key-baseline', [
            ('root', 'every', 'self-certifying-identifier', None),
            ('actor', 'every', 'self-certifying-identifier', None), ('actor', 'every', 'offline-verifiable', None)])
        template = native.compile_trusted_context(bytes.fromhex(plan['configuration']), None, 1, 1, 1,
            [anchor], assurance, None, None, 'none-v1', [key.evidence_type], [extension['extension_id']])
        context = template.bind_request(audience, challenge, current)
        evidence = (key.evidence_type, key.media_type, key.evidence)
        for label, arguments in plan['arguments'].items():
            call = native.mcp_call('stripe-platform-refunds', 'create_refund_v1', canonical(arguments))
            prepared = native.prepare_mcp_call_action(call, actor, grant, challenge, current, 120)
            signing = native.prepare_signing(prepared.unsigned, key.principal_method, key.verification_method, key.suite)
            action = signing.complete(key.sign(signing.signing_preimage))
            proof, action, trust = native.assemble_mcp_proof(prepared, action, [grant], [[evidence]], [evidence], context)
            (work / (label + '.proof')).write_bytes(proof)
            (work / (label + '.action')).write_bytes(action)
            (work / 'context.cbor').write_bytes(trust)
        print(json.dumps({'sdk_version': importlib.metadata.version('auths'), 'sdk_location': __import__('auths').__file__}))
    elif args.consumer == 'isolation':
        for path in ['/run/provider-secret/provider.env', '/run/operator/state']:
            try:
                Path(path).read_bytes() if path.endswith('.env') else list(Path(path).iterdir())
            except PermissionError:
                continue
            raise Refusal('live.application-can-read-secret')
        print('{"isolated":true}')
    elif args.consumer == 'sign':
        key = native.DevelopmentEd25519Key.generate()
        report = (work / 'report.json').read_bytes()
        enc = lambda data: base64.b64encode(data).rstrip(b'=').decode()
        statement = {'schema': 'auths.provider-simulation-attestation/1', 'simulation': True,
            'stable_launch_ready': False, 'signer_kind': 'disposable-self-signed-simulation-key',
            'family': 'stripe-platform-refund-v1', 'report_sha256': hashlib.sha256(report).hexdigest(),
            'public_key_b64': enc(bytes(key.public_key))}
        preimage = b'auths.provider-simulation-attestation/1\0' + canonical(statement)
        signature = bytes(key.sign(preimage))
        path = work / 'attestation.json'
        path.write_bytes(json.dumps({'statement': statement, 'signature_b64': enc(signature)}, indent=2).encode())
        envelope = json.loads(path.read_bytes())
        require(envelope['statement']['report_sha256'] == hashlib.sha256((work / 'report.json').read_bytes()).hexdigest(),
                'live.signature-report-mismatch')
        native.verify_ed25519_preimage_v1(base64.b64decode(envelope['statement']['public_key_b64'] + '=='),
            b'auths.provider-simulation-attestation/1\0' + canonical(envelope['statement']),
            base64.b64decode(envelope['signature_b64'] + '=='))
        print('{"persisted_signature_verified":true}')
    else:
        label = args.case
        action = (work / (label + '.action')).read_bytes()
        if args.consumer == 'altered':
            action += b'\0'
        result = asyncio.run(GatewayClient(GatewayEndpoint(args.consumer_socket)).submit(
            proof=(work / (label + '.proof')).read_bytes(), action=action))
        print(json.dumps(asdict(result), sort_keys=True))


class Operator:
    uid, app_uid, gid = 62001, 62002, 62000

    def __init__(self, args):
        self.args, self.steps = args, []
        self.binary = args.package / 'bin/auths-gateway'
        self.python = Path('/opt/consumer/bin/python')
        self.env = {'PATH': '/usr/bin:/bin', 'PYTHONNOUSERSITE': '1'}
        self.work, self.app = Path('/run/operator'), Path('/run/app')
        self.process, self.log, self.payment, self.keys = None, None, None, {}

    def scan(self, data):
        for key in self.keys.values():
            raw = key.encode()
            require(not any(value in data for value in [raw, raw.hex().encode(), base64.b64encode(raw),
                base64.urlsafe_b64encode(raw)]), 'live.secret-exposure')

    def run(self, label, argv, stdin=b'', uid=None):
        start = time.monotonic()
        result = subprocess.run(list(map(str, argv)), input=stdin, capture_output=True, timeout=60,
            env=self.env, cwd='/run', user=self.uid if uid is None else uid, group=self.gid, extra_groups=[])
        self.scan(result.stdout + result.stderr)
        require(len(result.stdout) + len(result.stderr) <= 1048576, 'live.output-bound')
        if result.returncode != 0:
            codes = re.findall(rb'(?:live|gateway)\.[a-z0-9.-]+', result.stderr)
            raise Refusal('live.command-refused:' + label + (':' + codes[-1].decode() if codes else ''))
        self.steps.append({'case': label, 'seconds': round(time.monotonic() - start, 3)})
        return result.stdout

    def child(self, verb, label='normal', work=None):
        return [self.python, Path(__file__).resolve(), '--consumer', verb, '--case', label,
                '--consumer-work', work or self.app, '--consumer-socket', '/run/sockets/app.sock']

    def api(self, method, path, fields=None, restricted=False, expected=200):
        require(path.startswith('/v1/'), 'live.invalid-provider-path')
        key = self.keys['STRIPE_TEST_RESTRICTED_KEY' if restricted else 'STRIPE_TEST_API_KEY']
        data = None if fields is None else urllib.parse.urlencode(fields).encode()
        request = urllib.request.Request('https://api.stripe.com' + path, data=data, method=method,
            headers={'Authorization': 'Bearer ' + key, 'Stripe-Version': '2025-03-31.basil'})
        try:
            response = urllib.request.urlopen(request, timeout=25)
        except urllib.error.HTTPError as error:
            require(error.code == expected, 'live.stripe-http-' + str(error.code))
            error.close()
            return {'http_status': expected}
        with response:
            require(response.status == expected, 'live.unexpected-provider-status')
            body = response.read(65537)
            require(len(body) <= 65536, 'live.provider-response-bound')
            return json.loads(body)

    def start(self):
        self.log = tempfile.TemporaryFile()
        self.process = subprocess.Popen([str(self.binary), 'serve', '--state-dir', str(self.work / 'state'),
            '--app-socket', '/run/sockets/app.sock'], stdout=subprocess.PIPE, stderr=self.log,
            env=self.env, cwd='/run', user=self.uid, group=self.gid, extra_groups=[])
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            require(bool(selector.select(15)), 'live.gateway-start-timeout')
            require(self.process.stdout.readline(65537).startswith(b'app socket ready'), 'live.gateway-start-refused')

    def stop(self):
        if self.process:
            if self.process.poll() is None:
                self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait()
                raise Refusal('live.gateway-stop-timeout')
            self.log.seek(0); self.scan(self.log.read(1048577))
            require(self.process.returncode == 0, 'live.gateway-stop-refused')
            self.process.stdout.close(); self.log.close()
            self.process = None

    def exercise(self):
        require(os.getuid() == 0 and not self.args.out.exists(), 'live.private-container-required')
        self.args.out.mkdir(parents=True)
        require(self.args.credential_stdin and not sys.stdin.isatty(), 'live.credential-stdin-required')
        raw = sys.stdin.buffer.read(8193)
        require(len(raw) <= 8192, 'live.credential-input-bound')
        private = Path('/run/provider-secret'); private.mkdir(mode=0o700)
        with os.fdopen(os.open(private / 'provider.env', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as output:
            output.write(raw)
        for line in raw.decode().splitlines():
            match = re.fullmatch(r'\s*(STRIPE_TEST_API_KEY|STRIPE_TEST_RESTRICTED_KEY)\s*=\s*(.*?)\s*', line)
            if match: self.keys[match[1]] = match[2].strip('"\'')
        require(self.keys.get('STRIPE_TEST_API_KEY', '').startswith('sk_test_') and
                self.keys.get('STRIPE_TEST_RESTRICTED_KEY', '').startswith('rk_test_'), 'live.test-keys-required')
        manifest = json.loads((self.args.package / 'manifest.json').read_bytes())
        require(manifest['source_commit'] == self.args.commit, 'live.candidate-commit-mismatch')
        for entry in manifest['files']:
            path = self.args.package / entry['path']
            require(not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest() == entry['sha256'], 'live.package-hash-mismatch')
        platform = self.api('GET', '/v1/account', restricted=True)['id']
        require(self.api('GET', '/v1/balance', restricted=True)['livemode'] is False, 'live.not-test-mode')
        for path in ['/v1/customers', '/v1/payouts']:
            self.api('GET', path, restricted=True, expected=403)
        payment = self.api('POST', '/v1/payment_intents', {'amount': 2000, 'currency': 'usd',
            'payment_method': 'pm_card_visa', 'confirm': 'true', 'automatic_payment_methods[enabled]': 'true',
            'automatic_payment_methods[allow_redirects]': 'never', 'metadata[auths_simulation]': 'disposable-platform-refund'})
        self.payment = payment['id']
        require(payment['livemode'] is False and payment['status'] == 'succeeded', 'live.fixture-payment-not-ready')
        for path, uid, mode in [(self.work, self.uid, 0o700), (self.app, self.app_uid, 0o750),
                                (Path('/run/sockets'), self.uid, 0o770)]:
            path.mkdir(mode=mode); os.chown(path, uid, self.gid)
        for name in ['recipe.json', 'profile.lock.json']:
            (self.work / name).write_bytes((self.args.inputs / name).read_bytes())
            os.chown(self.work / name, self.uid, self.gid)
        recipe = json.loads((self.work / 'recipe.json').read_bytes())
        require('account_scope' not in recipe, 'live.connect-scope-outside-contract')
        review = json.loads(self.run('review', [self.binary, 'review', '--recipe', self.work / 'recipe.json', '--profile-lock', self.work / 'profile.lock.json']))
        extension = json.loads(self.run('bound-extension', [self.binary, 'bound-extension', '--argument', 'amount',
            '--ceiling', '10000', '--window-seconds', '86400', '--max-count', '10', '--sum-limit', '10000', '--partition', 'currency=usd']))
        operation = str(uuid.uuid4())
        normal = {'operator_namespace': 'stripe-platform-refunds', 'operation_id': operation,
            'recipe_digest': review['recipe_digest'], 'payment_intent': self.payment, 'amount': 500, 'currency': 'usd'}
        arguments = {'normal': normal, 'above-ratio': {**normal, 'operation_id': operation + '-ratio', 'amount': 1001},
                     'above-grant': {**normal, 'operation_id': operation + '-grant', 'amount': 10001},
                     'wrong-currency': {**normal, 'operation_id': operation + '-currency', 'currency': 'eur'}}
        (self.app / 'plan.json').write_bytes(canonical({'configuration': review['verifier_configuration'],
            'extension': extension, 'arguments': arguments}))
        os.chown(self.app / 'plan.json', self.app_uid, self.gid)
        sdk = json.loads(self.run('installed-consumer-author', self.child('author'), uid=self.app_uid))
        require(sdk['sdk_location'].startswith('/opt/consumer/lib/'), 'live.repository-import')
        self.run('install', [self.binary, 'install', '--state-dir', self.work / 'state', '--recipe', self.work / 'recipe.json',
            '--profile-lock', self.work / 'profile.lock.json', '--trusted-context', self.app / 'context.cbor',
            '--approve-digest', review['recipe_digest'], '--provider', 'stripe', '--alias', 'platform-rehearsal',
            '--account-label', platform, '--credential-stdin'], stdin=(self.keys['STRIPE_TEST_RESTRICTED_KEY'] + '\n').encode())
        self.start()
        self.run('application-secret-isolation', self.child('isolation'), uid=self.app_uid)
        results = {}
        for label in ['above-grant', 'above-ratio', 'wrong-currency', 'normal']:
            results[label] = json.loads(self.run(label, self.child('submit', label), uid=self.app_uid))
        require(results['above-grant'].get('code') == 'gateway.policy.above-ceiling', 'live.grant-ceiling-not-refused')
        require(results['above-ratio'].get('code') == 'gateway.relative-ceiling.above', 'live.ratio-not-refused')
        require(results['wrong-currency'].get('outcome') == 'not-entered', 'live.currency-not-refused')
        require(results['normal'].get('outcome') == 'observed-by-provider', 'live.refund-not-observed')
        echo = results['normal']['evidence']['echo']
        refunds = self.api('GET', '/v1/refunds?' + urllib.parse.urlencode({'payment_intent': self.payment, 'limit': 10}))['data']
        matched = [refund for refund in refunds if refund['amount'] == 500 and refund['metadata'].get('auths_echo') == echo]
        require(len(refunds) == 1 and len(matched) == 1 and matched[0]['payment_intent'] == self.payment,
                'live.fresh-refund-read-back-mismatch')
        results['proof-replay'] = json.loads(self.run('proof-replay', self.child('submit'), uid=self.app_uid))
        require(results['proof-replay'].get('code') == 'gateway.attempt.replay', 'live.replay-entered')
        results['altered-action'] = json.loads(self.run('altered-action', self.child('altered'), uid=self.app_uid))
        require(results['altered-action'].get('outcome') in ['denied', 'indeterminate', 'not-entered'], 'live.altered-action-entered')
        support = self.run('support-bundle', [self.binary, 'support-bundle', '--state-dir', self.work / 'state'])
        require(json.loads(support)['deployment'] == 'development', 'live.production-claim')
        (self.args.out / 'support-bundle.json').write_bytes(support)
        self.stop(); self.start()
        results['restart-replay'] = json.loads(self.run('restart-replay', self.child('submit'), uid=self.app_uid))
        require(results['restart-replay'].get('code') == 'gateway.attempt.replay', 'live.restart-replay-entered')
        self.stop()
        return {'schema': 'auths.recipe-qualification-simulation/1', 'simulation': True, 'stable_launch_ready': False,
            'family': 'stripe-platform-refund-v1', 'provider': 'live Stripe test mode; platform account',
            'source_commit': self.args.commit, 'compiled_recipe_sha256': review['recipe_digest'],
            'gateway_sha256': hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            'wheel_sha256': hashlib.sha256(self.args.wheel.read_bytes()).hexdigest(), **sdk,
            'resources': {'platform_account': platform, 'payment_intent': self.payment, 'refund': matched[0]['id']},
            'store': 'shared-file-v1', 'custody': 'local-file-v1', 'clock': 'development-host-clock',
            'verification_boundary': 'installed SDK and native application socket', 'cases': self.steps, 'results': results,
            'fresh_read_back': {'refund_count_before_cleanup': len(refunds), 'amount_matches': True, 'echo_matches': True},
            'excluded_claims': ['Connect/connected-account scope', 'protected production qualification',
                'production PostgreSQL/AWS custody', 'complete qualification corpus', 'independent lease/provider-entry counters']}

    def cleanup(self):
        try:
            self.stop()
        finally:
            if self.payment:
                # Test setup/teardown uses the operator test key, never the app.
                refunds = self.api('GET', '/v1/refunds?' + urllib.parse.urlencode({'payment_intent': self.payment, 'limit': 100}))['data']
                total = sum(refund['amount'] for refund in refunds)
                if total < 2000:
                    refund = self.api('POST', '/v1/refunds', {'payment_intent': self.payment, 'amount': 2000 - total,
                        'metadata[auths_simulation_cleanup]': 'true'})
                    require(refund['status'] == 'succeeded' and refund['payment_intent'] == self.payment, 'live.cleanup-refund-refused')
                payment = self.api('GET', '/v1/payment_intents/' + self.payment)
                charge = self.api('GET', '/v1/charges/' + payment['latest_charge'])
                require(payment['livemode'] is False and charge['livemode'] is False and
                        charge['refunded'] is True and charge['amount_refunded'] == 2000, 'live.cleanup-read-back-mismatch')
                self.payment = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--consumer', choices=['author', 'submit', 'altered', 'isolation', 'sign'])
    parser.add_argument('--case', default='normal')
    parser.add_argument('--consumer-work', type=Path)
    parser.add_argument('--consumer-socket', type=Path)
    for name in ['package', 'inputs', 'wheel', 'out']:
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--commit')
    parser.add_argument('--credential-stdin', action='store_true')
    args = parser.parse_args()
    try:
        if args.consumer:
            consumer(args); return
        operator = Operator(args)
        def interrupted(_signal, _frame):
            raise Refusal('live.interrupted')
        signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
        try:
            report = operator.exercise()
        finally:
            operator.cleanup()
        report['cleanup'] = {'test_payment_fully_refunded': True, 'stripe_retains_test_payment_and_refund_records': True}
        data = json.dumps(report, indent=2).encode(); operator.scan(data)
        (args.out / 'report.json').write_bytes(data)
        operator.run('sign-published-report', operator.child('sign', work=args.out), uid=0)
        print('Live platform Stripe refund rehearsal passed; limits, read-back, replay, isolation, cleanup and signature verified.')
    except Refusal as error:
        print(str(error), file=sys.stderr); sys.exit(1)


if __name__ == '__main__':
    main()
