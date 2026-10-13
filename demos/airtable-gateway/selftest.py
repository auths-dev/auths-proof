"""Actual installed SDK/native journey with independent HTTP and execution counters."""
import base64
import json
import os
from pathlib import Path
import subprocess
import urllib.request
from urllib.parse import quote

from demo_common import canonical, decode, digest, read, require, write


def test_native_refusals_replay_race_and_loss(operator):
    from operate import HOME
    from double import PREFIX, record_ids
    require(operator.mode == 'simulation', 'demo.selftest-simulation-only')
    ledger, cases = HOME / 'provider.jsonl', []

    def entries():
        return [decode(line) for line in ledger.read_bytes().splitlines()] if ledger.exists() else []

    def execute(label):
        before, native_before = len(entries()), operator.witnesses()
        completed = operator.application('submit', '--experiment', label)
        require(completed.returncode == 0, 'demo.selftest-client-refused:' + label)
        result, traffic = decode(completed.stdout), entries()[before:]
        native_after = operator.witnesses()
        counters = {name: 0 for name in ['credential_lease_calls', 'write_transport_entries', 'read_transport_entries']}
        for first, last in zip(native_before, native_after):
            require(first['scope'] == last['scope'], 'demo.selftest-counter-scope')
            for name in counters:
                require(first[name] <= last[name] < 2**64 - 1, 'demo.selftest-counter-overflow')
                counters[name] += last[name] - first[name]
        records = [item['result'] for item in result['records']]
        cases.append({'case': label, 'results': records, 'native_counters': counters,
            'provider_reads': sum(item['kind'] == 'read' for item in traffic),
            'provider_writes': sum(item['kind'] == 'write' for item in traffic),
            'other_actor_writes': sum(item['kind'] == 'fixture-write' for item in traffic)})
        return result, records, traffic

    for label in ['unsupported-value', 'record-substitution', 'path-injection', 'wrong-recipe', 'altered-action', 'forged-proof', 'expired-action']:
        _, records, traffic = execute(label)
        require(all(item['outcome'] in ['not-entered', 'denied', 'indeterminate'] for item in records)
                and not traffic and cases[-1]['native_counters']['credential_lease_calls'] == 0,
                'demo.selftest-pre-custody-refusal:' + label)
    _, records, traffic = execute('encoded-segment')
    # Percent-encoded text may name a nonexistent record, but cannot add a
    # path segment or escape the operator's fixed base/table.
    require(not traffic or all(item['path'] == PREFIX + quote('rec../other-record', safe='') for item in traffic),
            'demo.selftest-path-escaped-fixed-resource')
    require(records[0]['outcome'] in ['not-entered', 'response-recorded', 'denied'],
            'demo.selftest-path-injection-effect-claim')
    for label in ['exact', 'pending', 'typescript-positive']:
        result, records, traffic = execute(label)
        require(records[0]['outcome'] == 'observed-by-provider', 'demo.selftest-observation:' + label)
        writes = [item for item in traffic if item['kind'] == 'write']
        require(len(writes) == 1 and cases[-1]['native_counters']['write_transport_entries'] == 1,
                'demo.selftest-write-count:' + label)
        packet = decode(read(HOME / 'app' / ('packet-' + label + '.json')))
        action = result['action']
        echo = 'auths-e1-' + digest(b'auths.gateway-echo/1\0' + action['operator_namespace'].encode()
               + b'\0' + action['operation_id'].encode() + b'\0' + bytes.fromhex(packet['action_commitment']))
        expected = canonical({'fields': {'DemoStatus': action['replacement'], 'auths_echo': echo}}).decode()
        require(writes[0]['body'] == expected and writes[0]['idempotency_key'] is None
                and writes[0]['path'] == PREFIX + action['record_id'], 'demo.selftest-independent-request-mapping')
        request = urllib.request.Request(f'http://127.0.0.1:{operator.port}' + PREFIX + action['record_id'],
            headers={'Authorization': 'Bearer ' + operator.keys['runtime']})
        with urllib.request.urlopen(request, timeout=5) as response:
            raw = response.read(16385)
        require(len(raw) <= 16384, 'demo.selftest-read-bound')
        value = decode(raw)
        require(value['id'] == action['record_id'] and value['fields'] == {
            'DemoStatus': action['replacement'], 'auths_echo': echo}, 'demo.selftest-independent-read-back')
        cases[-1]['independent_read_back'] = {'fixture_api_entries': 1, 'response_sha256': digest(raw)}
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
    _, records, traffic = execute('lost-response')
    require(records[0]['outcome'] == 'unknown' and cases[-1]['native_counters']['write_transport_entries'] == 1
            and any(item['response_dropped_after_effect'] for item in traffic), 'demo.selftest-loss-after-effect')
    with operator.fixture.lock:
        operator.fixture.hidden_until[record_ids()[10]] = float('inf')
    _, records, traffic = execute('recover-loss')
    require(records[0]['outcome'] != 'observed-by-provider' and not any(item['kind'] == 'write' for item in traffic),
            'demo.selftest-delayed-visibility-not-confirmed')
    operator.fixture.release_visibility(record_ids()[10])
    _, records, traffic = execute('recover-loss')
    require(records[0]['outcome'] == 'observed-by-provider' and traffic
            and cases[-1]['native_counters']['write_transport_entries'] == 0, 'demo.selftest-read-only-recovery')
    _, records, traffic = execute('competing-writer')
    require(records[0]['outcome'] == 'unknown' and cases[-1]['other_actor_writes'] == 1,
            'demo.selftest-competing-writer-fixture')
    _, records, traffic = execute('recover-competing')
    require(records[0]['outcome'] != 'observed-by-provider' and traffic
            and cases[-1]['native_counters']['write_transport_entries'] == 0
            and operator.fixture.records[record_ids()[11]]['auths_echo'] == 'external-writer-echo',
            'demo.selftest-matching-value-wrong-echo-not-confirmed')
    for label in ['rate-limit', 'provider-error', 'malformed-response', 'oversized-response']:
        _, records, traffic = execute(label)
        require(records[0]['outcome'] in ['response-recorded', 'unknown']
                and cases[-1]['native_counters']['write_transport_entries'] == 1,
                'demo.selftest-provider-error-not-confirmed:' + label)
        _, records, traffic = execute(label)
        require(records[0]['outcome'] != 'observed-by-provider'
                and cases[-1]['native_counters']['write_transport_entries'] == 0
                and not any(item['kind'] == 'write' for item in traffic), 'demo.selftest-provider-error-never-rewrites')
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
    require(doctor_value.get('schema') == 'auths.gateway-readiness/1'
            and doctor_value.get('ready') is False and doctor.returncode != 0,
            'demo.selftest-development-must-not-claim-production-readiness')
    checks = {item['check']: item for item in doctor_value['checks']}
    for name in ['store', 'recipe', 'connection-generation', 'transport-policy', 'operator-plane-isolation']:
        require(checks[name]['ready'] is True, 'demo.selftest-doctor-failed:' + name)
    for name in ['trust', 'qualification', 'provider-secret-custody', 'clock']:
        require(checks[name]['ready'] is False, 'demo.selftest-development-production-gate:' + name)
    require(checks['observer-custody']['state'] == 'not-ready',
            'demo.selftest-software-observer-not-production-ready')
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
    report = {'schema': 'auths.airtable-gateway-demo-evidence/1',
              'mode': 'simulation', 'production_qualification': False,
              'independent_human_trial': False, 'source_commit': decode(read(Path(__file__).parent / 'manifest.json'))['source_commit'],
              'cases': cases, **verified,
              'excluded': ['live Airtable writes', 'production AWS custody and PostgreSQL',
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
