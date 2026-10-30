"""Installed-client/native-process evidence; expected facts do not come from the UI."""
import base64
import os
import tempfile
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import subprocess
import urllib.request
from urllib.parse import urlencode

from demo_common import canonical, decode, digest, read, require, write


def private_action_echo(label, action):
    """Test-only expected link from the operator's exact native approval input."""
    from operate import PRIVATE
    binding = decode(read(PRIVATE / ('effect-' + label) / 'binding'))
    commitment = binding['action']
    require(binding['schema'] == 'auths.bound-effect/3'
            and binding['namespace'] == action['operator_namespace']
            and binding['operation'] == action['operation_id']
            and type(commitment) is list and len(commitment) == 32
            and all(type(value) is int and 0 <= value <= 255 for value in commitment),
            'demo.selftest-private-action-binding')
    return 'auths-e1-' + digest(b'auths.gateway-echo/1\0'
        + action['operator_namespace'].encode() + b'\0'
        + action['operation_id'].encode() + b'\0' + bytes(commitment))


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

    for label in ['above-grant', 'altered-action', 'forged-proof', 'expired-action',
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
    for label in ['above-boundary', 'wrong-currency']:
        _, records, traffic = execute(label)
        require(records[0]['outcome'] == 'not-entered' and traffic
                and not any(item['kind'] == 'write' for item in traffic)
                and cases[-1]['native_counters']['credential_lease_calls'] == 1
                and cases[-1]['native_counters']['write_transport_entries'] == 0,
                'demo.selftest-read-guard:' + label)
    for label in ['exact', 'boundary']:
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
        evidence = records[0]['evidence']
        language = decode(inspected.stdout)['records'][0]['language']
        require(language in ('python', 'typescript'), 'demo.selftest-client-language')
        commitment_field, time_field = (('evidenceCommitment', 'observedAt')
                                        if language == 'typescript' else ('evidence_commitment', 'observed_at'))
        require(set(evidence) == {'schema', 'channel', commitment_field, time_field}
                and evidence['schema'] == 'auths.gateway-public-evidence/1'
                and evidence['channel'] == 'read-back'
                and type(evidence[commitment_field]) is str
                and len(evidence[commitment_field]) == 64
                and all(value in '0123456789abcdef' for value in evidence[commitment_field])
                and type(evidence[time_field]) is int and 0 <= evidence[time_field] <= 2**53 - 1,
                'demo.selftest-public-hiding-evidence')
        # Private test expectation never returns through the application result.
        echo = private_action_echo(label, action)
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
        require(evidence[commitment_field] != digest(refund_bytes),
                'demo.selftest-public-raw-evidence-digest')
        cases[-1]['independent_read_back'] = {'fixture_api_entries': 1, 'response_sha256': digest(refund_bytes)}
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
    for name in ['count', 'sum']:
        _, records, traffic = execute(name + '-positive')
        require(records[0]['outcome'] == 'response-recorded'
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
    require(records[0]['outcome'] == 'unknown' and not traffic
            and not any(cases[-1]['native_counters'].values()), 'demo.selftest-unknown-never-refetches-or-retries')
    return cases


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
    verified = test_application_isolation_and_native_audit(operator)
    report = {'schema': 'auths.stripe-gateway-demo-evidence/1',
              'mode': 'simulation', 'production_qualification': False,
              'independent_human_trial': False, 'source_commit': decode(read(Path(__file__).parent / 'manifest.json'))['source_commit'],
              'operator_consent': consent, 'operator_review_channel': reviewer, 'cases': cases, **verified,
              'excluded': ['live Stripe writes', 'production AWS custody and PostgreSQL',
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
