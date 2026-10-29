"""Actual installed SDK/native journey with independent HTTP and execution counters."""
import base64
import os
import tempfile
import time
from pathlib import Path
import subprocess
import urllib.request
from concurrent.futures import ThreadPoolExecutor
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

    for label in ['unsupported-value', 'record-substitution', 'path-injection', 'wrong-recipe',
                  'altered-action', 'forged-proof', 'expired-action',
                  'approval-insufficient']:
        _, records, traffic = execute(label)
        require(all(item['outcome'] in ['not-entered', 'denied', 'indeterminate'] for item in records)
                and not traffic and cases[-1]['native_counters']['credential_lease_calls'] == 0,
                'demo.selftest-pre-custody-refusal:' + label)
    _, records, traffic = execute('approval-duplicate')
    require(records[0]['outcome'] == 'not-submitted'
            and records[0]['approved'] == 0 and records[0]['required'] == 2
            and records[0]['code'] == 'approval.duplicate-response'
            and not traffic and not any(cases[-1]['native_counters'].values()),
            'demo.selftest-duplicate-approval-entered-gateway')
    _, records, traffic = execute('encoded-segment')
    # Percent-encoded text may name a nonexistent record, but cannot add a
    # path segment or escape the operator's fixed base/table.
    require(not traffic or all(item['path'] == PREFIX + quote('rec../other-record', safe='') for item in traffic),
            'demo.selftest-path-escaped-fixed-resource')
    require(records[0]['outcome'] in ['not-entered', 'response-recorded', 'denied'],
            'demo.selftest-path-injection-effect-claim')
    for label in ['exact', 'pending', 'typescript-positive']:
        result, records, traffic = execute(label)
        require(records[0]['outcome'] == 'response-recorded' and records[0]['status'] == 200,
                'demo.selftest-response-is-not-observation:' + label)
        _, recovery, recovery_traffic = execute('recover-' + label)
        report = recovery[0]['report']
        require(recovery[0]['outcome'] == 'recovery-report'
                and report['source']['stage'] == 'observed-by-provider'
                and report['source']['provider_linked'] is True
                and report['acquisition']['stage'] == 'response-recorded'
                and report['disposition'] == 'recorded'
                and not any(item['kind'] == 'write' for item in recovery_traffic)
                and cases[-1]['native_counters']['write_transport_entries'] == 0,
                'demo.selftest-independent-native-observation:' + label)
        inspect_before, inspect_traffic = operator.witnesses(), len(entries())
        inspected = operator.application('submit', '--experiment', label)
        require(inspect_before == operator.witnesses() and inspect_traffic == len(entries()),
                'demo.selftest-source-inspection-must-not-enter-provider')
        require(inspected.returncode == 0, 'demo.selftest-source-inspection-refused')
        records = [item['result'] for item in decode(inspected.stdout)['records']]
        require(records[0]['outcome'] == 'observed-by-provider', 'demo.selftest-source-observation')
        writes = [item for item in traffic if item['kind'] == 'write']
        require(len(writes) == 1 and cases[-2]['native_counters']['write_transport_entries'] == 1,
                'demo.selftest-write-count:' + label)
        action = result['action']
        echo = records[0]['evidence']['echo']
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
    for label in ['replay', 'typescript']:
        _, records, traffic = execute(label)
        require(records[0]['outcome'] == 'observed-by-provider'
                and not traffic and not any(cases[-1]['native_counters'].values()),
                'demo.selftest-replay-retains-observation-without-new-entry:' + label)
    _, records, traffic = execute('fresh-replay')
    require(records[0]['outcome'] == 'denied' and records[0]['code'] == 'challenge-mismatch'
            and not traffic and not any(cases[-1]['native_counters'].values()),
            'demo.selftest-substituted-challenge-under-installed-trust')
    _, records, traffic = execute('race')
    require(any(item['outcome'] == 'response-recorded' for item in records)
            and all(item['outcome'] in ('reserved', 'unknown', 'response-recorded') for item in records)
            and sum(item['kind'] == 'write' for item in traffic) == 1
            and cases[-1]['native_counters']['write_transport_entries'] == 1, 'demo.selftest-two-process-race')
    # A contender can inspect the winner after durable entry but before its
    # response is recorded, so Unknown is a truthful interim projection. Once
    # both calls finish, exact replay must converge without any external I/O.
    race_before, race_entries = operator.witnesses(), len(entries())
    replayed = operator.application('submit', '--experiment', 'race')
    require(replayed.returncode == 0
            and decode(replayed.stdout)['records'][0]['result']['outcome'] == 'response-recorded'
            and race_before == operator.witnesses() and race_entries == len(entries()),
            'demo.selftest-race-final-history-without-new-entry')
    operator.restart(0)
    _, records, traffic = execute('replay')
    require(records[0]['outcome'] == 'observed-by-provider' and not traffic
            and not any(cases[-1]['native_counters'].values()), 'demo.selftest-restart-replay')
    cases[-1]['case'] = 'restart-replay'
    _, records, traffic = execute('lost-response')
    require(records[0]['outcome'] == 'unknown' and cases[-1]['native_counters']['write_transport_entries'] == 1
            and any(item['response_dropped_after_effect'] for item in traffic), 'demo.selftest-loss-after-effect')
    with operator.fixture.lock:
        operator.fixture.hidden_until[record_ids()[10]] = float('inf')
    _, records, traffic = execute('recover-loss')
    require(records[0]['outcome'] == 'recovery-report'
            and records[0]['report']['source']['stage'] == 'unknown'
            and records[0]['report']['source']['provider_linked'] is False
            and not any(item['kind'] == 'write' for item in traffic),
            'demo.selftest-delayed-visibility-not-confirmed')
    operator.fixture.release_visibility(record_ids()[10])
    _, records, traffic = execute('recover-loss')
    require(records[0]['outcome'] == 'recovery-report'
            and records[0]['report']['source']['stage'] == 'observed-by-provider'
            and records[0]['report']['source']['provider_linked'] is True and traffic
            and cases[-1]['native_counters']['write_transport_entries'] == 0, 'demo.selftest-read-only-recovery')
    _, records, traffic = execute('competing-writer')
    require(records[0]['outcome'] == 'unknown' and cases[-1]['other_actor_writes'] == 1,
            'demo.selftest-competing-writer-fixture')
    _, records, traffic = execute('recover-competing')
    require(records[0]['outcome'] == 'recovery-report'
            and records[0]['report']['source']['provider_linked'] is False and traffic
            and cases[-1]['native_counters']['write_transport_entries'] == 0
            and operator.fixture.records[record_ids()[11]]['auths_echo'] == 'external-writer-echo',
            'demo.selftest-matching-value-wrong-echo-not-confirmed')
    for label in ['rate-limit', 'provider-error', 'malformed-response', 'oversized-response']:
        _, records, traffic = execute(label)
        require((records[0]['outcome'] in ['response-recorded', 'unknown']
                 or records[0]['outcome'] == 'observed' and records[0].get('matched') is False)
                and cases[-1]['native_counters']['write_transport_entries'] == 1,
                'demo.selftest-provider-error-not-confirmed:' + label)
        _, records, traffic = execute(label)
        require(records[0]['outcome'] != 'observed-by-provider'
                and not traffic and not any(cases[-1]['native_counters'].values()),
                'demo.selftest-provider-error-never-refetches-or-rewrites')
    return cases


def test_native_process_crashes(operator):
    from operate import HOME
    ledger = HOME / 'provider.jsonl'

    def writes():
        return sum(decode(line)['kind'] == 'write' for line in ledger.read_bytes().splitlines())

    def kill_gateway():
        process = next(process for process, _, host in operator.processes if host == 0)
        process.kill()
        require(process.wait(timeout=10) == -9, 'demo.selftest-gateway-not-killed')

    before = writes()
    kill_gateway()
    completed = operator.application('submit', '--experiment', 'crash-before')
    require(completed.returncode == 0 and decode(completed.stdout)['records'][0]['result']['outcome'] == 'transport-unconfirmed'
            and writes() == before, 'demo.selftest-crash-before-entry')
    operator.restart(0)
    completed = operator.application('submit', '--experiment', 'crash-before')
    require(completed.returncode == 0 and decode(completed.stdout)['records'][0]['result']['outcome'] == 'response-recorded'
            and writes() == before + 1, 'demo.selftest-confirmed-pre-entry-restart')
    before, witness = writes(), operator.witnesses()[0]
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(operator.application, 'submit', '--experiment', 'crash-after')
        require(operator.fixture.delivered.wait(20), 'demo.selftest-delivery-timeout')
        entered = operator.witnesses()[0]
        require(entered['scope'] == witness['scope']
                and entered['write_transport_entries'] == witness['write_transport_entries'] + 1
                and writes() == before + 1, 'demo.selftest-crash-after-real-entry')
        kill_gateway()
        operator.fixture.release_response.set()
        completed = pending.result(timeout=30)
    require(completed.returncode == 0 and decode(completed.stdout)['records'][0]['result']['outcome'] == 'transport-unconfirmed',
            'demo.selftest-crash-after-ipc-unconfirmed')
    operator.restart(0)
    fresh = operator.witnesses()[0]
    require(fresh['scope'] != entered['scope'], 'demo.selftest-crash-counter-scope-not-renewed')
    completed = operator.application('submit', '--experiment', 'crash-after')
    replay = operator.witnesses()[0]
    require(completed.returncode == 0 and decode(completed.stdout)['records'][0]['result']['outcome'] == 'unknown'
            and writes() == before + 1
            and replay['write_transport_entries'] == fresh['write_transport_entries']
            and replay['read_transport_entries'] == fresh['read_transport_entries'],
            'demo.selftest-crash-replay-cannot-read-or-write')
    completed = operator.application('submit', '--experiment', 'recover-crash-after')
    after = operator.witnesses()[0]
    native = decode(completed.stdout)['records'][0]['result']
    require(completed.returncode == 0 and native['outcome'] == 'recovery-report'
            and native['report']['source']['stage'] == 'observed-by-provider'
            and native['report']['source']['provider_linked'] is True
            and writes() == before + 1 and after['write_transport_entries'] == fresh['write_transport_entries']
            and after['read_transport_entries'] == fresh['read_transport_entries'] + 1,
            'demo.selftest-crash-recovery-must-only-read')
    return [{'case': 'crash-before-entry', 'gateway_exit_signal': 'SIGKILL', 'provider_writes_before_restart': 0,
             'provider_writes_after_operator_confirmed_restart': 1},
            {'case': 'crash-after-effect-before-response', 'gateway_exit_signal': 'SIGKILL',
             'before_kill': entered, 'after_restart': after, 'provider_writes': 1,
             'recovery_write_entries': 0, 'recovery_read_entries': 1}]


def test_application_isolation_and_native_audit(operator):
    from operate import APP_UID, APP_GID, ENVIRONMENT, HOME, child
    private = [HOME / 'private' / 'root.seed', HOME / 'private' / 'reader.seed',
               HOME / 'private' / 'read-grant.json',
               *(HOME / 'private' / (name + '.seed') for name in
                 ['manager-a', 'manager-b', 'manager-c']),
               HOME / 'gateway0' / 'credentials.cbor',
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
    require(result['inconsistent'] == 0 and result['unverified'] == 0
            and len(result['approval_responses']) >= 2,
            'demo.selftest-audit-open')
    return {'doctor': doctor_value, 'audit': result}


def test_exact_operator_consent_binding(operator):
    """Exercise private consent transport; scripted input is not a human trial."""
    from operate import HOME, operator_consent
    from demo_common import Refusal
    before = operator.witnesses()
    for accepted in [False, True]:
        with tempfile.TemporaryDirectory(prefix='consent-test-', dir=HOME / 'private') as temporary:
            directory = Path(temporary)
            write(directory / 'literal-review.json',
                  read(HOME / 'private/effect-exact/literal-review.json'), new=True)
            write(directory / 'literal-review.txt',
                  read(HOME / 'private/effect-exact/literal-review.txt'), new=True)
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(operator_consent, directory, 'exact-consent-test')
                fifo, deadline = directory / 'consent', time.monotonic() + 5
                while not fifo.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                require(fifo.exists() and fifo.stat().st_mode & 0o777 == 0o600,
                        'demo.selftest-consent-not-private')
                # The trusted operator channel supplies the exact operation
                # token; changing it cannot approve the saved native request.
                with fifo.open('wb', buffering=0) as stream:
                    stream.write(b'approve exact-consent-test\n' if accepted else b'approve another-operation\n')
                if accepted:
                    require(pending.result(timeout=5) is None, 'demo.selftest-consent-not-accepted')
                else:
                    try:
                        pending.result(timeout=5)
                        raise AssertionError('substituted operator consent accepted')
                    except Refusal as error:
                        require(str(error) == 'demo.operator-review-declined',
                                'demo.selftest-consent-wrong-refusal')
            require(not fifo.exists() and not (directory / 'approval').exists(),
                    'demo.selftest-consent-created-authority')
    require(before == operator.witnesses(), 'demo.selftest-consent-entered-provider')
    return {'cases': 2, 'changed_operation_refused': True, 'owner_only_fifo': True,
            'provider_entries': 0, 'human_trial': False}


def test_private_reviewer_refuses_unlisted_inputs(operator):
    """Unlisted or malformed app requests receive no read proof or exact approval."""
    from operate import APP_UID, APP_GID, ENVIRONMENT, HOME
    script = r"""
import json, socket, struct, sys
results = []
for value in [{'source': 'unlisted'}, {'source': []}, {'source': 'exact', 'url': 'https://other.example'}]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(5)
        channel.connect(sys.argv[1])
        raw = json.dumps(value).encode()
        channel.sendall(struct.pack('>I', len(raw)) + raw)
        def receive(length):
            output = b''
            while len(output) < length:
                part = channel.recv(length - len(output))
                if not part:
                    raise RuntimeError('incomplete reviewer response')
                output += part
            return output
        length = struct.unpack('>I', receive(4))[0]
        if not 0 < length <= 1024:
            raise RuntimeError('reviewer response bound')
        results.append(json.loads(receive(length)))
print(json.dumps(results))
"""
    before = operator.witnesses()
    result = subprocess.run(['/opt/consumer/bin/python', '-c', script,
        str(HOME / 'sockets/review.sock')], user=APP_UID, group=APP_GID, extra_groups=[],
        env=ENVIRONMENT, capture_output=True, timeout=20)
    require(result.returncode == 0, 'demo.selftest-review-channel-unavailable')
    refusals = decode(result.stdout)
    require(refusals == [{'code': 'demo.operator-recovery-review-refused'}] * 3
            and before == operator.witnesses(), 'demo.selftest-review-channel-minted-authority')
    return {'cases': 3, 'app_uid': APP_UID, 'native_counters_unchanged': True,
            'returned_proof_or_approval': False}


def run(operator):
    from operate import HOME
    consent = test_exact_operator_consent_binding(operator)
    reviewer = test_private_reviewer_refuses_unlisted_inputs(operator)
    cases = test_native_refusals_replay_race_and_loss(operator)
    cases.extend(test_native_process_crashes(operator))
    verified = test_application_isolation_and_native_audit(operator)
    report = {'schema': 'auths.airtable-gateway-demo-evidence/1',
              'mode': 'simulation', 'production_qualification': False,
              'independent_human_trial': False, 'source_commit': decode(read(Path(__file__).parent / 'manifest.json'))['source_commit'],
              'operator_consent': consent, 'operator_review_channel': reviewer, 'cases': cases, **verified,
              'excluded': ['live Airtable writes', 'production AWS custody and PostgreSQL',
                           'protected full-corpus qualification', 'provider key rotation',
                           'independent security review', 'GitHub release installation']}
    data = canonical(report)
    audit = read(HOME / 'app/audit.json')
    support = subprocess.run([str(operator.binary), 'support-bundle', '--state-dir', str(HOME / 'gateway0')],
                             capture_output=True, timeout=30)
    require(support.returncode == 0, 'demo.selftest-support-refused')
    published = data + audit + support.stdout
    private_seeds = [read(HOME / 'private' / (name + '.seed'))
                     for name in ['root', 'reader', 'manager-a', 'manager-b', 'manager-c']]
    for secret in list(operator.keys.values()) + private_seeds + [read(HOME / 'app/actor.seed')]:
        raw = secret.encode() if isinstance(secret, str) else secret
        for encoded in [raw, raw.hex().encode(), base64.b64encode(raw), base64.urlsafe_b64encode(raw)]:
            require(encoded not in published, 'demo.selftest-report-secret-exposure')
    destination = Path('/evidence')
    destination.mkdir(exist_ok=True)
    write(destination / 'simulation.json', data, new=True, mode=0o644)
    write(destination / 'audit-bundle.json', audit, new=True, mode=0o644)
    write(destination / 'support-bundle.json', support.stdout, new=True, mode=0o644)
    print(canonical({'status': 'passed', 'cases': len(cases), 'production_qualification': False}).decode())
