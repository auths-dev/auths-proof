"""Post-authorization state comparisons with unchanged AP070 application code.

Run after the exact native file/PostgreSQL selectors in the same hosted job,
with that checkout's Python SDK installed. No Google or managed credential is
used. Synthetic VerifiedRead inputs delimit the claim: this does not compare
authorization proofs or turn AP070 release commitment into recipient ACK.
"""

import argparse
import json
import multiprocessing
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile

from common import require, sha256

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'demos/google-employee-delegation/broker/src'))

from employee_read_demo.admission import AdmissionDenied, AdmissionStore
from employee_read_demo.authority import VerifiedRead, native_body_digest
from employee_read_demo.contracts import MAX_METADATA_BYTES, TaskDescriptor

NOW = 1_790_000_000
MAXIMUM = 1024
BODY = b'private-test-content!'
CHARGES = ['calls', 'provider_attempt_slots', 'charged_content_bytes', 'reserved_provider_bytes']
SUITES = {
    'capacity': ('native_budget_tests', 'window_capacity', 'native-window-capacity', 'auths.native-window-capacity/1'),
    'replay': ('native_information_replay_tests', 'information_retained_replay', 'native-information-retained-replay', 'auths.native-information-retained-replay/1'),
    'acquisition-crash': ('native_crash_tests', 'process_crash', 'native-process-crash', 'auths.native-process-crash/1'),
    'disclosure-crash': ('native_disclosure_crash_tests', 'disclosure_process_crash', 'native-disclosure-process-crash', 'auths.native-disclosure-process-crash/1'),
}


def descriptor(limit='count-and-byte-sum'):
    calls = 4 if limit == 'byte-sum' else 2
    total = 4096 if limit == 'count' else 2048
    return TaskDescriptor(
        'auths.google-read-task/v1', 'atlas-studio', 'customer-demo-01', 'a' * 64,
        'employee-principal', 'binding-1', 'agent-principal', 'atlas-drive',
        'connection-1', 1, ('file-A', 'file-B'), 'text', MAXIMUM, calls, total,
        NOW - 1, NOW + 600, 'differential-task', 'Independent reference state comparison',
    )


def setup(path, task):
    store = AdmissionStore(path)
    store.register_connection(connection_id=task.connection_id, company=task.company_id,
        employee=task.employee_principal, binding_ref=task.identity_binding_ref, generation=1)
    store.enroll(task)
    return store


def verified(task):
    # Exactly the existing reference unit-test boundary: its caller has already
    # verified authorization. This fixture supplies no managed authority/permit.
    return VerifiedRead(task.calls()[0], b'x' * 32, 'authorized')


def challenge(store, task):
    return store.issue_challenge(task, native_body_digest(task.calls()[0], task.service), now=NOW)


def snapshot(store, task, token=None):
    with store._connect() as db:
        row = db.execute('SELECT calls,attempts,charged_bytes,reserved_provider_bytes,in_flight '
                         'FROM tasks WHERE id=?', (task.task_id,)).fetchone()
        state = None if token is None else db.execute(
            'SELECT status FROM challenges WHERE value=?', (token,)).fetchone()[0]
    return {**dict(zip(CHARGES, row[:4])), 'in_flight': row[4], 'challenge_state': state}


def charges(snapshot_value):
    return {key: snapshot_value[key] for key in CHARGES}


def denied(action):
    try:
        action()
    except AdmissionDenied:
        return True
    return False


def claim_worker(path, task, token, start, output):
    require(start.wait(10), 'ap074.reference.worker-start')
    store = AdmissionStore(Path(path))
    try:
        reservation = store.claim(task, verified(task), token, now=NOW)
    except AdmissionDenied:
        output.put(False)
    else:
        # Close only the in-flight slot; calls/bytes/attempt charges stay spent.
        store.fail(reservation)
        output.put(True)


def stop(processes):
    for process in processes:
        if process.is_alive():
            process.kill()
        if process.pid is not None:
            process.join(timeout=5)


def capacity_reference(limit):
    task = descriptor(limit)
    with tempfile.TemporaryDirectory(prefix='ap074-reference-capacity-') as directory:
        path = Path(directory) / 'admission.sqlite3'
        store = setup(path, task)
        prefix = store.claim(task, verified(task), challenge(store, task), now=NOW)
        store.fail(prefix)
        tokens = [challenge(store, task) for _ in range(2)]
        context = multiprocessing.get_context('spawn')
        start, output = context.Event(), context.Queue()
        workers = [context.Process(target=claim_worker,
            args=(str(path), task, token, start, output)) for token in tokens]
        try:
            for worker in workers:
                worker.start()
            start.set()
            for worker in workers:
                worker.join(timeout=15)
                require(worker.exitcode == 0, 'ap074.reference.capacity-worker')
            winners = sum(output.get(timeout=3) for _ in workers)
        finally:
            stop(workers)
            output.close()
        require(winners == 1, 'ap074.reference.capacity-single-winner')
        final = snapshot(AdmissionStore(path), task)
        require(charges(final) == {'calls': 2, 'provider_attempt_slots': 4,
            'charged_content_bytes': 2048,
            'reserved_provider_bytes': 2 * (MAX_METADATA_BYTES + MAXIMUM + 2)},
            'ap074.reference.capacity-charges')
        require(final['in_flight'] == 0, 'ap074.reference.capacity-in-flight')
        return {'limit': limit, 'prefix': 1, 'contenders': 2, 'final_winners': winners,
                'snapshot': final, 'provider_io_executed': False}


def release_reference(gate, *, disconnect_after_release=False):
    task = descriptor()
    with tempfile.TemporaryDirectory(prefix='ap074-reference-release-') as directory:
        path = Path(directory) / 'admission.sqlite3'
        store = setup(path, task)
        token = challenge(store, task)
        reservation = store.claim(task, verified(task), token, now=NOW)
        before = snapshot(store, task, token)
        at = NOW
        if gate == 'task-revoked':
            store.revoke(task.task_id)
        elif gate == 'connection-revoked':
            store.disconnect(task.connection_id)
        elif gate == 'task-expired':
            at = NOW + 601
        released = []
        try:
            released.append(store.release(reservation, BODY, now=at))
        except AdmissionDenied:
            pass
        require(bool(released) is (gate == 'current'), 'ap074.reference.release-current-gate')
        if disconnect_after_release:
            require(gate == 'current', 'ap074.reference.replay-positive-control')
            store.disconnect(task.connection_id)
        reopened = AdmissionStore(path)
        require(denied(lambda: reopened.release(reservation, BODY, now=at))
                and denied(lambda: reopened.claim(task, verified(task), token, now=at)),
                'ap074.reference.no-repeat-release-or-claim')
        after = snapshot(reopened, task, token)
        require(charges(before) == charges(after), 'ap074.reference.release-conservation')
        return {'gate': gate, 'connection_revoked_after_release': disconnect_after_release,
                'returned_content_bytes': sum(map(len, released)),
                'before': before, 'after': after,
                'repeat_release_and_claim_refused': True,
                'recipient_ack_protocol': False, 'provider_io_executed': False}


def crash_worker(path, task, token, ready, hold):
    store = AdmissionStore(Path(path))
    runtime = store.open_runtime()
    reservation = store.claim(task, verified(task), token, now=NOW)
    store.attempt_observer(reservation).begin(1, 'metadata')
    ready.send(reservation)
    require(hold.wait(30), 'ap074.reference.crash-worker-not-killed')
    runtime.close()


def crash_reference():
    task = descriptor()
    with tempfile.TemporaryDirectory(prefix='ap074-reference-crash-') as directory:
        path = Path(directory) / 'admission.sqlite3'
        store = setup(path, task)
        token = challenge(store, task)
        context = multiprocessing.get_context('spawn')
        received, ready = context.Pipe(duplex=False)
        worker = context.Process(target=crash_worker,
            args=(str(path), task, token, ready, context.Event()))
        worker.start()
        ready.close()
        try:
            require(received.poll(15), 'ap074.reference.crash-ready')
            reservation = received.recv()
            before = snapshot(store, task, token)
            worker.kill()
            worker.join(timeout=5)
            require(worker.exitcode == -signal.SIGKILL, 'ap074.reference.actual-sigkill')
        finally:
            stop([worker])
            received.close()
        reopened = AdmissionStore(path)
        runtime = reopened.open_runtime()
        try:
            require(runtime.abandoned_claims == 1, 'ap074.reference.abandoned-claim')
            require(denied(lambda: reopened.claim(task, verified(task), token, now=NOW))
                    and denied(lambda: reopened.release(reservation, BODY, now=NOW)),
                    'ap074.reference.crash-no-reentry-or-release')
            after = snapshot(reopened, task, token)
            require(charges(before) == charges(after)
                    and after['in_flight'] == 0 and after['challenge_state'] == 'abandoned',
                    'ap074.reference.crash-conservation')
            with reopened._connect() as db:
                attempt = db.execute('SELECT status FROM provider_attempts WHERE challenge=? '
                    'AND ordinal=1', (token,)).fetchone()
            require(attempt == ('started',), 'ap074.reference.unknown-provider-attempt')
        finally:
            runtime.close()
        return {'sigkill': True, 'before': before, 'after': after,
                'provider_attempt': 'started', 'old_claim_and_release_refused': True,
                'provider_io_executed': False}


def native_evidence(log):
    require('AUTHS_UPDATE_FIXTURES' not in os.environ, 'ap074.differential.fixture-updates-forbidden')
    require(0 < log.stat().st_size <= 8 * 1024 * 1024, 'ap074.differential.native-log-bound')
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', log.read_text())
    result = {}
    for adapter in ['file', 'postgres']:
        result[adapter] = {}
        for label, (module, suffix, stem, schema) in SUITES.items():
            function = ('native_file_' if adapter == 'file' else 'postgres_native_') + suffix + '_fixture_is_current'
            selector = module + '::' + function
            occurrences = list(re.finditer(r'^test ' + re.escape(selector) + r' \.\.\. ok$', text, re.M))
            require(len(occurrences) == 1, 'ap074.differential.native-selector-execution')
            following = text[occurrences[0].end():]
            outcome = re.search(r'test result: (.*)', following)
            require(outcome is not None and outcome.group(1).startswith('ok. 1 passed; 0 failed; 0 ignored;'),
                    'ap074.differential.native-selector-result')
            path = ROOT / f'bindings/fixtures/gateway/{stem}-{adapter}.json'
            raw = path.read_bytes()
            value = json.loads(raw)
            require(value['schema'] == schema and value['adapter'] == adapter,
                    'ap074.differential.native-artifact-binding')
            result[adapter][label] = {'selector': selector, 'sha256': sha256(raw), 'value': value}
    return result


def one(rows, **fields):
    matches = [row for row in rows if all(row.get(key) == value for key, value in fields.items())]
    require(len(matches) == 1, 'ap074.differential.native-case-unique')
    return matches[0]


def compare(native, reference):
    pairs = []
    for adapter, artifacts in native.items():
        for ref in reference['capacity']:
            case = one(artifacts['capacity']['value']['cases'], limit=ref['limit'])
            require(case['prefix'] == ref['prefix'] and case['contenders'] == ref['contenders']
                    and case['final_winners'] == ref['final_winners']
                    and case['reserved_calls'] == ref['snapshot']['calls'] == 2
                    and case['reserved_bytes'] == ref['snapshot']['charged_content_bytes'] == 2048
                    and case['actual_http_reads'] == 2
                    and case['reopened_replay_preserves_attempt_and_counter_bytes'] is True
                    and case['reopened_replay_leases_and_sends_nothing'] is True,
                    'ap074.differential.capacity-conservation')
            pairs.append({'adapter': adapter, 'contract': 'one final admission; charges conserved',
                'reference': ref, 'native': case,
                'units': 'same chosen numeric ceiling; native response bytes and reference content/provider bytes retain distinct meanings'})
        for ref in reference['release']:
            gate = {'current': 'current', 'task-revoked': 'revoked',
                    'connection-revoked': 'revoked', 'task-expired': 'authority-expired'}[ref['gate']]
            case = one(artifacts['disclosure-crash']['value']['cases'],
                       pause='after-reservation-commit', current_gate=gate)
            accepted = ref['gate'] == 'current'
            require((case['final_history']['stage'] == 'acknowledged') is accepted
                    and case['continued_only_after_fresh_authorization'] is accepted
                    and case['replays_do_not_authenticate_or_redeliver'] is True
                    and case['source_allocation_calls'] == 1
                    and case['source_allocation_bytes'] == ref['before']['charged_content_bytes'] == MAXIMUM,
                    'ap074.differential.release-current-gate')
            if not accepted:
                require(case['original_recipient']['received_full'] is False
                        and case['final_history']['stage'] == 'reserved',
                        'ap074.differential.release-no-delivery')
            pairs.append({'adapter': adapter, 'contract': 'current state gate before release; no repeated release',
                'reference': ref, 'native': case,
                'difference': 'reference task expiry/revision versus native current authority/connection; reference release commitment is not native recipient ACK'})
        case = one(artifacts['acquisition-crash']['value']['cases'], pause='after-entry-commit')
        require(case['after']['stage'] == 'unknown'
                and case['provider_calls_at_kill'] == case['provider_calls_after_replays'] == 0
                and case['terminal_replays_leave_journal_and_boundary_counters_unchanged'] is True
                and case['after']['reserved_calls'] == reference['crash']['after']['calls'] == 1
                and case['after']['reserved_bytes'] == reference['crash']['after']['charged_content_bytes'] == MAXIMUM,
                'ap074.differential.crash-no-reentry')
        pairs.append({'adapter': adapter, 'contract': 'durable entry uncertainty retains charges and forbids old operation reentry',
                      'reference': reference['crash'], 'native': case})
        for protocol in ['acquisition-response', 'disclosure-acknowledged', 'disclosure-unknown']:
            case = one(artifacts['replay']['value']['cases'], protocol=protocol, change='connection-revoked')
            require(case['journal_and_execution_witness_unchanged'] is True
                    and case['no_replay_authentication_or_delivery'] is True
                    and case['changed_caller_target_refused'] is True,
                    'ap074.differential.historical-replay-no-new-release')
            pairs.append({'adapter': adapter, 'contract': 'historical replay does not deliver or charge again',
                'native': case, 'reference': reference['retained_replay'],
                'difference': 'native returns retained protocol facts; AP070 refuses a repeated challenge/release'})
    return pairs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-log', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    native = native_evidence(args.native_log)
    reference = {'capacity': [capacity_reference(limit) for limit in ['count', 'byte-sum', 'count-and-byte-sum']],
        'release': [release_reference(gate) for gate in ['current', 'task-revoked', 'connection-revoked', 'task-expired']],
        'retained_replay': release_reference('current', disconnect_after_release=True),
        'crash': crash_reference()}
    sources = ['demos/google-employee-delegation/broker/src/employee_read_demo/' + name
               for name in ['admission.py', 'authority.py', 'contracts.py']]
    sources.append('qualification/reference/ap074_information_differential.py')
    sources.append('qualification/reference/common.py')
    report = {'schema': 'auths.ap074-independent-information-differential/1',
        'scope': 'post-authorization reference state only; actual SQLite workers/SIGKILL paired with freshly executed native file/TLS PostgreSQL histories; no AP070 managed, recipient ACK, full authorization equivalence or live Google claim',
        'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'run_id': os.environ.get('GITHUB_RUN_ID'), 'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
        'native_log_sha256': sha256(args.native_log.read_bytes()),
        'sources_sha256': {name: sha256((ROOT / name).read_bytes()) for name in sources},
        'native_execution': {adapter: {label: {key: artifact[key] for key in ['selector', 'sha256']}
            for label, artifact in artifacts.items()} for adapter, artifacts in native.items()},
        'pairs': compare(native, reference)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'schema': report['schema'], 'adapters': len(native), 'pairs': len(report['pairs'])}))


if __name__ == '__main__':
    main()
