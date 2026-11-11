#!/usr/bin/env python3
"""AP075 independent transport/deployment probes of the installed Stripe package.

Run in an assessment-owned Linux container, never on the operator's host. The
existing operator authors real signed inputs; this driver does not replace any
native verifier, fence, custody check, or journal transition.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import struct
import subprocess
import sys
import time

TARGET = os.environ.get('AUTHS_ASSESSMENT_TARGET_SHA', 'ac5fcabe9c6300e46789b4e847bb1991f9f9d66f')
APP_UID, APP_GID = 62004, 62005
ENV = {'PATH': '/opt/consumer/bin:/usr/local/bin:/usr/bin:/bin', 'PYTHONNOUSERSITE': '1'}


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def decode64(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def untrusted(request):
    """Transport and access probes only; deliberately no authorization policy."""
    if request['kind'] == 'access':
        observations = []
        for name in request['paths']:
            try:
                with open(name, 'rb') as stream:
                    stream.read(1)
                readable = True
            except OSError:
                readable = False
            observations.append({'path': name, 'readable': readable})
        return {'uid': os.getuid(), 'gid': os.getgid(), 'paths': observations,
                'cap_eff': next(line.split(':', 1)[1].strip()
                                for line in Path('/proc/self/status').read_text().splitlines()
                                if line.startswith('CapEff:')),
                'no_new_privs': next(line.split(':', 1)[1].strip()
                                     for line in Path('/proc/self/status').read_text().splitlines()
                                     if line.startswith('NoNewPrivs:')),
                'environment_names': sorted(os.environ)}
    if request['kind'] == 'connect':
        try:
            with socket.create_connection(('127.0.0.1', request['port']), timeout=2):
                return {'connected': True}
        except OSError as error:
            return {'connected': False, 'errno': error.errno}
    if request['kind'] == 'admin':
        try:
            with socket.socket(socket.AF_UNIX) as channel:
                channel.settimeout(2)
                channel.connect(request['socket'])
            return {'connected': True}
        except OSError as error:
            return {'connected': False, 'errno': error.errno}
    payload = decode64(request['payload'])
    started = time.monotonic()
    try:
        with socket.socket(socket.AF_UNIX) as channel:
            channel.settimeout(7)
            channel.connect(request['socket'])
            channel.sendall(struct.pack('>I', request.get('length', len(payload))) + payload)
            channel.shutdown(socket.SHUT_WR)

            def receive(size):
                result = b''
                while len(result) < size:
                    part = channel.recv(size - len(result))
                    if not part:
                        raise EOFError('closed')
                    result += part
                return result

            length = struct.unpack('>I', receive(4))[0]
            if not 0 < length <= 8 * 1024 * 1024:
                raise ValueError('response bound')
            value = json.loads(receive(length))
        return {'response': value, 'elapsed_seconds': time.monotonic() - started}
    except (OSError, EOFError, ValueError) as error:
        return {'closed': type(error).__name__, 'elapsed_seconds': time.monotonic() - started}


class Campaign:
    def __init__(self, operator):
        self.operator = operator
        self.rows = []

    def invoke(self, request):
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--untrusted'],
                                input=canonical(request), capture_output=True, env=ENV,
                                user=APP_UID, group=APP_GID, extra_groups=[], timeout=12)
        if result.returncode != 0:
            raise AssertionError('restricted probe process failed')
        return json.loads(result.stdout)

    def traffic(self):
        return [json.loads(line) for line in Path('/run/demo/provider.jsonl').read_bytes().splitlines()]

    def run(self, name, families, action):
        before = len(self.traffic())
        started = time.monotonic()
        try:
            observed = action()
            state, error = 'pass', None
        except Exception as failure:
            observed, state = {}, 'finding'
            # Never publish raw native/private stderr or secret-bearing inputs.
            error = {'class': type(failure).__name__, 'assertion': str(failure)[:160]
                     if isinstance(failure, AssertionError) else 'probe execution failed'}
        traffic = self.traffic()[before:]
        row = {'schema': 'auths.security-assessment-case/1', 'id': name,
               'families': families, 'status': state, 'target_revision': TARGET,
               'backend': 'file', 'interface': 'installed Python/raw Unix IPC',
               'elapsed_seconds': time.monotonic() - started,
               'provider_reads': sum(x['kind'] == 'read' for x in traffic),
               'provider_write_requests': sum(x['kind'] == 'write' for x in traffic),
               'distinct_effects_in_interval': len({x['refund'] for x in traffic if x.get('refund')}),
               'observed': observed, 'error': error}
        self.rows.append(row)
        return row

    def frame(self, value, host=0, length=None):
        raw = value if isinstance(value, bytes) else canonical(value)
        request = {'kind': 'frame', 'payload': b64(raw),
                   'socket': str(self.operator.app_sockets[host])}
        if length is not None:
            request['length'] = length
        return self.invoke(request)

    def refused(self, value, length=None):
        witness = self.operator.witnesses()
        traffic = len(self.traffic())
        result = self.frame(value, length=length)
        assert self.operator.witnesses() == witness, 'refused input changed native execution counters'
        assert len(self.traffic()) == traffic, 'refused input reached provider'
        response = result.get('response', {})
        assert response.get('outcome') not in ['response-recorded', 'observed-by-provider'], 'invalid input entered'
        assert result['elapsed_seconds'] < 8, 'malformed frame exceeded bounded refusal time'
        return result

    def submit(self, label):
        result = self.operator.application('submit', '--experiment', label)
        assert result.returncode == 0, 'installed application request failed'
        value = json.loads(result.stdout)
        return [row['result'] for row in value['records']]


def boundary_campaign(operator):
    campaign = Campaign(operator)
    plan = json.loads(Path('/run/demo/app/application.json').read_text())
    packet = json.loads(Path('/run/demo/app/packet-exact.json').read_text())
    frame = {'schema': 'auths.gateway-submit/2', 'proof_b64': packet['proof'],
             'action_b64': packet['action'], 'approval_b64': plan['effect_approvals']['exact']}
    mutations = {}
    for name in ['trusted_context', 'verifier_configuration', 'effect_policy', 'evaluation_time',
                 'provider_url', 'credential', 'namespace', 'operation_id']:
        value = dict(frame)
        value[name] = 0 if name == 'evaluation_time' else 'attacker-controlled'
        mutations['extra-' + name] = value
    for name in ['proof_b64', 'action_b64', 'approval_b64']:
        value = dict(frame)
        original = decode64(value[name])
        value[name] = b64(original[:-1] + bytes([original[-1] ^ 1]))
        mutations['changed-' + name] = value
        value = dict(frame)
        value[name] = ''
        mutations['empty-' + name] = value
    value = dict(frame)
    value['approval_b64'] = plan['effect_approvals']['boundary']
    mutations['other-exact-approval'] = value
    value = dict(frame)
    value['approval_b64'] = b64(b'x' * 4097)
    mutations['approval-over-bound'] = value
    mutations['duplicate-proof'] = canonical(frame)[:-1] + b',"proof_b64":"invalid"}'
    mutations['duplicate-schema'] = canonical(frame)[:-1] + b',"schema":"auths.gateway-submit/1"}'
    mutations['truncated-json'] = canonical(frame)[:-1]
    mutations['non-object'] = b'[]'
    mutations['invalid-utf8'] = b'\xff'
    mutations['admin-schema-on-app'] = {'schema': 'auths.gateway-admin/1', 'operation': 'enable'}
    for name, value in mutations.items():
        campaign.run('IPC-' + name, ['SB04', 'SB05', 'SB16', 'SB28'],
                     lambda value=value: campaign.refused(value))
    for name, length, payload in [('empty', 0, b''), ('over-bound', 8 * 1024 * 1024 + 1, b''),
                                  ('incomplete', 100, b'{}')]:
        campaign.run('FRAME-' + name, ['SB28', 'SB32'],
                     lambda length=length, payload=payload: campaign.refused(payload, length))

    def isolation():
        process = next(p for p, _, host in operator.processes if host == 0)
        paths = ['/run/demo/private/root.seed', '/run/demo/private/manager-a.seed',
                 '/run/demo/private/manager-b.seed', '/run/demo/gateway0/credentials.cbor',
                 '/run/demo/gateway0/installation.json', '/proc/' + str(process.pid) + '/environ',
                 '/proc/' + str(process.pid) + '/mem']
        result = campaign.invoke({'kind': 'access', 'paths': paths})
        assert result['uid'] == APP_UID and int(result['cap_eff'], 16) == 0, 'attacker unexpectedly privileged'
        assert not any(x['readable'] for x in result['paths']), 'attacker read protected lab state'
        assert set(result['environment_names']) <= set(ENV) | {'LC_CTYPE'}, 'unexpected inherited environment'
        assert result['no_new_privs'] == '1', 'attacker can acquire new process privileges'
        admin = campaign.invoke({'kind': 'admin', 'socket': '/run/demo/gateway0/admin.sock'})
        assert admin['connected'] is False, 'attacker reached private admin socket'
        return {'access': result, 'admin': admin}

    campaign.run('ISOLATION-files-memory-admin', ['SB09', 'SB10'], isolation)

    def egress():
        subprocess.run(['iptables', '-A', 'OUTPUT', '-m', 'owner', '--uid-owner', str(APP_UID),
                        '-j', 'REJECT'], check=True, capture_output=True)
        result = campaign.invoke({'kind': 'connect', 'port': operator.port})
        assert result['connected'] is False, 'attacker bypassed per-UID provider egress restriction'
        return {'actual_probe': result, 'rule': 'deny INET egress from application UID; Unix IPC remains available'}

    campaign.run('ISOLATION-provider-egress', ['SB10'], egress)

    def positive():
        before = len(campaign.traffic())
        result = campaign.submit('exact')
        requests = [x for x in campaign.traffic()[before:] if x['kind'] == 'write']
        assert result[0]['outcome'] == 'response-recorded', 'valid control did not reach native provider entry'
        assert len(requests) == 1 and requests[0]['status'] == 200, 'valid control missing one applied effect'
        from urllib.parse import parse_qs
        fields = parse_qs(requests[0]['body'], strict_parsing=True)
        action = plan['cases']['exact']['arguments']
        assert fields['amount'] == [str(action['amount'])], 'wrong independently observed amount'
        assert fields['payment_intent'] == [action['payment_intent']], 'wrong independently observed resource'
        return {'outcome': result[0]['outcome'], 'request_method': requests[0]['method'],
                'request_path': requests[0]['path'], 'exact_amount_and_payment_checked': True}

    campaign.run('POSITIVE-exact-after-hostile-inputs', ['SB01', 'SB05'], positive)

    def race():
        other = json.loads(Path('/run/demo/app/packet-race.json').read_text())
        race_frame = dict(frame, proof_b64=other['proof'], action_b64=other['action'],
                          approval_b64=plan['effect_approvals']['race'])
        before = len(campaign.traffic())
        with ThreadPoolExecutor(max_workers=12) as pool:
            replies = list(pool.map(lambda n: campaign.frame(race_frame, n % 2), range(24)))
        writes = [x for x in campaign.traffic()[before:] if x['kind'] == 'write']
        assert len(writes) == 1, 'concurrent duplicates produced multiple provider write entries'
        assert len({x['refund'] for x in writes}) == 1, 'duplicate or missing provider effect'
        final = campaign.frame(race_frame)['response']
        assert final['outcome'] == 'response-recorded', 'history failed to converge'
        return {'contenders': len(replies), 'provider_write_entries': len(writes), 'final': final['outcome']}

    campaign.run('RACE-24-independent-connections-two-gateways', ['SB13', 'SB16'], race)

    def final_capacity():
        frames = []
        for label in ['sum-positive', 'sum-overflow']:
            value = json.loads(Path('/run/demo/app/packet-' + label + '.json').read_text())
            frames.append(dict(frame, proof_b64=value['proof'], action_b64=value['action'],
                               approval_b64=plan['effect_approvals'][label]))
        before = len(campaign.traffic())
        with ThreadPoolExecutor(max_workers=8) as pool:
            replies = list(pool.map(lambda n: campaign.frame(frames[n % 2], n % 2), range(16)))
        writes = [x for x in campaign.traffic()[before:] if x['kind'] == 'write']
        from urllib.parse import parse_qs
        total = sum(int(parse_qs(x['body'])['amount'][0]) for x in writes)
        assert len(writes) == 1 and total <= 1000, 'final shared sum capacity overspent'
        return {'contenders': len(replies), 'provider_write_entries': len(writes),
                'independently_observed_amount': total, 'limit': 1000}

    campaign.run('RACE-distinct-operations-final-sum-capacity', ['SB13'], final_capacity)

    def recovery():
        records = []

        def step(label, command):
            started = time.monotonic()
            value = command()
            records.append({'step': label, 'elapsed_seconds': time.monotonic() - started,
                            'outcome': value[0].get('outcome') if isinstance(value, list) else 'completed'})
            return value

        original = step('submit-lost-response', lambda: campaign.submit('lost-response'))
        assert original[0]['outcome'] == 'unknown', 'lost response was not Unknown'
        before = len(campaign.traffic())
        step('restart-gateway', lambda: operator.restart(0))
        replay = step('inspect-original-operation', lambda: campaign.submit('lost-response'))
        assert replay[0]['outcome'] == 'unknown', 'restart strengthened unknown without evidence'
        assert len(campaign.traffic()) == before, 'restart inspection retried provider I/O'
        pre = len(campaign.traffic())
        observed = step('independently-authorized-observation-of-known-source',
                        lambda: campaign.submit('recover-exact'))
        assert observed[0]['outcome'] == 'recovery-report', 'authorized observation unavailable'
        assert not any(x['kind'] == 'write' for x in campaign.traffic()[pre:]), 'recovery mutated provider'
        return {'role': 'scripted trusted operator and authorized application', 'steps': records,
                'safe_next_action': 'retain uncertain charge; use separately authorized evidence or escalate',
                'prohibited_action': 'new refund or automatic retry to resolve uncertainty',
                'unresolved_case': 'lost response; no response-provided locator in retained source',
                'human_effort_measured': False, 'production_incident_frequency_measured': False}

    campaign.run('RECOVERY-unknown-restart-and-independent-read', ['SB18', 'SB19', 'SB20', 'SB21'], recovery)

    def audit():
        pins = json.loads(Path('/run/demo/private/pins.json').read_text())
        destination = Path('/run/demo/private/ap075-audit.json')
        operator.export_audit(destination)
        original = json.loads(destination.read_text())
        results = []
        for key in ['proof_b64', 'action_b64', 'outcome_b64']:
            value = copy.deepcopy(original)
            entry = next(x for x in value['entries'] if x.get(key))
            data = decode64(entry[key])
            entry[key] = b64(data[:-1] + bytes([data[-1] ^ 1]))
            changed = destination.with_name('ap075-audit-' + key + '.json')
            changed.write_bytes(canonical(value))
            result = subprocess.run([str(operator.binary), 'audit', '--bundle', str(changed),
                                     '--trusted-context-sha256', pins['trusted_context_sha256'],
                                     '--observer', pins['observer']['observer_anchor']['principal']],
                                    capture_output=True, env=ENV, timeout=30)
            verdict = json.loads(result.stdout) if result.stdout else {}
            assert result.returncode != 0 or any(verdict.get(k, 0) for k in
                                               ['inconsistent', 'unverified', 'refused']), 'tampered evidence accepted'
            results.append({'field': key, 'exit_code': result.returncode, 'tamper_detected': True})
        return {'mutations': results, 'trust_inputs': 'independent private operator pins'}

    campaign.run('AUDIT-byte-substitution-under-independent-trust', ['SB25', 'SB26'], audit)

    def withdrawn():
        process = subprocess.run([str(operator.binary), 'disable', '--state-dir', '/run/demo/gateway0'],
                                 capture_output=True, env=ENV, timeout=30)
        assert process.returncode == 0, 'trusted disable command failed'
        packet = json.loads(Path('/run/demo/app/packet-boundary.json').read_text())
        value = dict(frame, proof_b64=packet['proof'], action_b64=packet['action'],
                     approval_b64=plan['effect_approvals']['boundary'])
        return campaign.refused(value)

    campaign.run('REVOCATION-connection-disable-before-new-entry', ['SB15', 'SB31'], withdrawn)
    return campaign.rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--untrusted', action='store_true')
    parser.add_argument('--suite', choices=['boundary', 'reference'], default='boundary')
    args = parser.parse_args()
    if args.untrusted:
        print(json.dumps(untrusted(json.loads(sys.stdin.buffer.read(12 * 1024 * 1024)))))
        return
    if platform.system() != 'Linux' or os.getuid() != 0:
        raise SystemExit('assessment-owned Linux container/controller required')
    sys.path.insert(0, '/opt/demo')
    from operate import Operator
    metadata = json.loads(Path('/opt/demo/manifest.json').read_text())
    if metadata['source_commit'] != TARGET:
        raise SystemExit('wrong installed assessment target')
    operator = Operator('simulation')
    try:
        operator.prepare()
        if args.suite == 'reference':
            from selftest import run
            run(operator)
            return
        rows = boundary_campaign(operator)
        report = {'schema': 'auths.security-assessment-stripe/1', 'target_revision': TARGET,
                  'kernel': platform.release(), 'controller_uid': os.getuid(), 'attacker_uid': APP_UID,
                  'binary_sha256': hashlib.sha256(operator.binary.read_bytes()).hexdigest(),
                  'build_kind': 'loopback simulation; original native enforcement',
                  'deployment': {'network_namespace': os.readlink('/proc/self/ns/net'),
                                 'provider_dns_stub': [line for line in Path('/etc/hosts').read_text().splitlines()
                                                       if 'api.stripe.com' in line],
                                 'uid_map': Path('/proc/self/uid_map').read_text().strip(),
                                 'cpu_max': Path('/sys/fs/cgroup/cpu.max').read_text().strip(),
                                 'memory_max': Path('/sys/fs/cgroup/memory.max').read_text().strip(),
                                 'egress_rules': subprocess.run(['iptables', '-S', 'OUTPUT'],
                                     check=True, capture_output=True, text=True).stdout.splitlines(),
                                 'durability_scope': 'process restart on disposable Linux filesystem; not power loss'},
                  'native_policy_replaced': False, 'production_qualification': False,
                  'human_trial': False, 'cases': rows}
        output = Path('/evidence/independent-stripe.json')
        output.write_bytes(canonical(report) + b'\n')
        print(json.dumps({'cases': len(rows), 'findings': sum(x['status'] == 'finding' for x in rows),
                          'target_revision': TARGET}))
        if any(x['status'] == 'finding' for x in rows):
            raise SystemExit(1)
    except Exception as failure:
        if args.suite == 'reference':
            doctor = subprocess.run([str(operator.binary), 'doctor', '--state-dir', '/run/demo/gateway0',
                                     '--app-socket', str(operator.app_sockets[0]),
                                     '--app-uid', str(APP_UID), '--app-gid', str(APP_GID)],
                                    capture_output=True, env=ENV, timeout=30)
            readiness = json.loads(doctor.stdout) if doctor.stdout else {}
            Path('/evidence/reference-failure.json').write_bytes(canonical({
                'schema': 'auths.security-assessment-reference-failure/1', 'target_revision': TARGET,
                'failure_class': type(failure).__name__, 'readiness': readiness,
                'no_passing_reference_result': True}) + b'\n')
        raise
    finally:
        operator.stop()


if __name__ == '__main__':
    main()
