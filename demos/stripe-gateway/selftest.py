"""Installed-client/native-process evidence; expected facts do not come from the UI."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request
from urllib.parse import urlencode

from demo_common import canonical, decode, digest, read, require, write


def test_native_refusals_replay_race_and_loss(operator):
    """No double replaces gateway verification, admission, persistence or observation."""
    from operate import HOME
    require(operator.mode == 'simulation', 'demo.selftest-simulation-only')
    ledger = HOME / 'provider.jsonl'
    cases = []

    def entries():
        return [decode(line) for line in ledger.read_bytes().splitlines()]

    def execute(label):
        before = len(entries())
        native_before = operator.witnesses()
        completed = operator.application('submit', '--experiment', label)
        require(completed.returncode == 0, 'demo.selftest-client-refused:' + label)
        result = decode(completed.stdout)
        traffic = entries()[before:]
        native_after = operator.witnesses()
        counters = {name: 0 for name in ['credential_lease_calls', 'write_transport_entries', 'read_transport_entries']}
        for first, last in zip(native_before, native_after):
            require(first['scope'] == last['scope'], 'demo.selftest-counter-scope')
            for name in counters:
                require(first[name] <= last[name] < 2**64 - 1, 'demo.selftest-counter-overflow')
                counters[name] += last[name] - first[name]
        records = [item['result'] for item in result['records']]
        cases.append({'case': label, 'results': records,
                      'native_counters': counters,
                      'provider_reads': sum(item['kind'] == 'read' for item in traffic),
                      'provider_writes': sum(item['kind'] == 'write' for item in traffic)})
        return result, records, traffic

    for label in ['above-grant', 'altered-action', 'forged-proof', 'expired-action']:
        _, records, traffic = execute(label)
        require(all(item['outcome'] in ['not-entered', 'denied', 'indeterminate'] for item in records)
                and not traffic and cases[-1]['native_counters']['credential_lease_calls'] == 0,
                'demo.selftest-pre-custody-refusal:' + label)
    for label in ['above-boundary', 'wrong-currency']:
        _, records, traffic = execute(label)
        require(records[0]['outcome'] == 'not-entered' and traffic
                and not any(item['kind'] == 'write' for item in traffic)
                and cases[-1]['native_counters']['credential_lease_calls'] == 1
                and cases[-1]['native_counters']['write_transport_entries'] == 0,
                'demo.selftest-read-guard:' + label)
    for label in ['exact', 'boundary']:
        result, records, traffic = execute(label)
        require(records[0]['outcome'] == 'observed-by-provider', 'demo.selftest-observation:' + label)
        writes = [item for item in traffic if item['kind'] == 'write']
        require(len(writes) == 1 and cases[-1]['native_counters']['write_transport_entries'] == 1,
                'demo.selftest-write-count:' + label)
        packet = decode(read(HOME / 'app' / ('packet-' + label + '.json')))
        action = result['action']
        echo = 'auths-e1-' + digest(b'auths.gateway-echo/1\0' + action['operator_namespace'].encode()
               + b'\0' + action['operation_id'].encode() + b'\0' + bytes.fromhex(packet['action_commitment']))
        key = 'auths-i1-' + digest(b'auths.gateway-idempotency-key/1\0'
              + action['operator_namespace'].encode() + b'\0' + action['operation_id'].encode())
        expected = urlencode([('amount', str(action['amount'])), ('metadata[auths_echo]', echo),
                              ('payment_intent', action['payment_intent'])])
        require(writes[0]['body'] == expected and writes[0]['idempotency_key'] == key
                and writes[0]['stripe_account'] is None and writes[0]['stripe_version'] == '2025-03-31.basil',
                'demo.selftest-independent-request-mapping')
        locator = writes[0]['refund']
        require(type(locator) is str and locator.startswith('re_demo_'), 'demo.selftest-refund-locator')
        request = urllib.request.Request(f'http://127.0.0.1:{operator.port}/v1/refunds/{locator}',
            headers={'Authorization': 'Bearer ' + operator.keys['runtime'], 'Stripe-Version': '2025-03-31.basil'})
        # Independent fresh HTTP read, outside native execution counters.
        with urllib.request.urlopen(request, timeout=5) as response:
            refund_bytes = response.read(16385)
        require(len(refund_bytes) <= 16384, 'demo.selftest-refund-response-bound')
        refund = decode(refund_bytes)
        require(refund['amount'] == action['amount'] and refund['payment_intent'] == action['payment_intent']
                and refund['metadata']['auths_echo'] == echo, 'demo.selftest-independent-read-back')
        cases[-1]['independent_read_back'] = {'fixture_api_entries': 1, 'response_sha256': digest(refund_bytes)}
    for label in ['replay', 'fresh-replay', 'typescript']:
        _, records, traffic = execute(label)
        require(records[0]['outcome'] == 'not-entered' and records[0]['code'] == 'gateway.attempt.replay'
                and not traffic and cases[-1]['native_counters']['credential_lease_calls'] == 0,
                'demo.selftest-replay:' + label)
    _, records, traffic = execute('race')
    require(sorted(item['outcome'] for item in records) == ['not-entered', 'observed-by-provider']
            and sum(item['kind'] == 'write' for item in traffic) == 1
            and cases[-1]['native_counters']['write_transport_entries'] == 1, 'demo.selftest-two-process-race')
    operator.restart(0)
    _, records, traffic = execute('replay')
    require(records[0]['code'] == 'gateway.attempt.replay' and not traffic, 'demo.selftest-restart-replay')
    cases[-1]['case'] = 'restart-replay'
    for name in ['count', 'sum']:
        _, records, traffic = execute(name + '-positive')
        require(records[0]['outcome'] == 'observed-by-provider'
                and sum(item['kind'] == 'write' for item in traffic) == 1, 'demo.selftest-budget-positive')
        _, records, traffic = execute(name + '-overflow')
        require(records[0]['outcome'] == 'not-entered' and not traffic
                and cases[-1]['native_counters']['credential_lease_calls'] == 0, 'demo.selftest-budget-overflow')
    _, records, traffic = execute('lost-response')
    require(records[0]['outcome'] == 'unknown'
            and sum(item['kind'] == 'write' for item in traffic) == 1
            and cases[-1]['native_counters']['write_transport_entries'] == 1
            and any(item['response_dropped_after_effect'] for item in traffic), 'demo.selftest-loss-after-effect')
    _, records, traffic = execute('lost-response')
    require(records[0]['outcome'] in ['not-entered', 'unknown']
            and not any(item['kind'] == 'write' for item in traffic), 'demo.selftest-unknown-never-retries')
    return cases


def test_application_isolation_and_native_audit(operator):
    from operate import APP_UID, APP_GID, ENVIRONMENT, HOME, child
    private = [HOME / 'private' / 'root.seed', HOME / 'gateway0' / 'credentials.cbor',
               HOME / 'gateway0' / 'observer.seed', HOME / 'gateway0' / 'installation.json',
               HOME / 'attempts']
    for path in private:
        probe = subprocess.run(['/opt/consumer/bin/python', '-c',
            'import os,sys; p=sys.argv[1]; sys.exit(1 if os.access(p,os.R_OK) else 0)', str(path)],
            user=APP_UID, group=APP_GID, extra_groups=[], env=ENVIRONMENT)
        require(probe.returncode == 0, 'demo.selftest-application-secret-isolation')
    doctor = child([operator.binary, 'doctor', '--state-dir', HOME / 'gateway0',
                    '--app-socket', HOME / 'sockets/app0.sock', '--app-uid', APP_UID, '--app-gid', APP_GID], check=False)
    doctor_value = decode(doctor.stdout)
    require(doctor_value.get('ready') is True, 'demo.selftest-doctor-not-ready')
    pins = decode(read(HOME / 'private/pins.json'))
    audit = child([operator.binary, 'audit', '--bundle', HOME / 'app/audit.json',
                   '--trusted-context-sha256', pins['trusted_context_sha256'],
                   '--observer', pins['observer']['observer_anchor']['principal']])
    result = decode(audit.stdout)
    require(result['inconsistent'] == 0 and result['unverified'] == 0, 'demo.selftest-audit-open')
    return {'doctor': doctor_value, 'audit': result}


def run(operator):
    from operate import HOME
    cases = test_native_refusals_replay_race_and_loss(operator)
    verified = test_application_isolation_and_native_audit(operator)
    report = {'schema': 'auths.stripe-gateway-demo-evidence/1',
              'mode': 'simulation', 'production_qualification': False,
              'independent_human_trial': False, 'source_commit': decode(read(Path(__file__).parent / 'manifest.json'))['source_commit'],
              'cases': cases, **verified,
              'excluded': ['live Stripe writes', 'production AWS custody and PostgreSQL',
                           'protected full-corpus qualification', 'provider key rotation',
                           'independent security review', 'GitHub release installation']}
    data = canonical(report)
    audit = read(HOME / 'app/audit.json')
    support = subprocess.run([str(operator.binary), 'support-bundle', '--state-dir', str(HOME / 'gateway0')],
                             capture_output=True, timeout=30)
    require(support.returncode == 0, 'demo.selftest-support-refused')
    published = data + audit + support.stdout
    for secret in list(operator.keys.values()) + [read(HOME / 'private/root.seed'), read(HOME / 'app/actor.seed')]:
        raw = secret.encode() if isinstance(secret, str) else secret
        for encoded in [raw, raw.hex().encode(), base64.b64encode(raw), base64.urlsafe_b64encode(raw)]:
            require(encoded not in published, 'demo.selftest-report-secret-exposure')
    destination = Path('/evidence')
    destination.mkdir(exist_ok=True)
    write(destination / 'simulation.json', data, new=True, mode=0o644)
    write(destination / 'audit-bundle.json', audit, new=True, mode=0o644)
    write(destination / 'support-bundle.json', support.stdout, new=True, mode=0o644)
    print(canonical({'status': 'passed', 'cases': len(cases), 'production_qualification': False}).decode())
