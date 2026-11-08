#!/usr/bin/env python3
"""Replay an explicit compiled native registry with real TLS PostgreSQL.

Existing source tests are supplemental evidence, not an independent security
assessment. Dedicated worker entrypoints are excluded from scenario counts.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time


def select(names, support):
    entries = support['entries']
    support_names = [row['id'] for row in entries]
    if (support['schema'] != 'auths.security-assessment-native-support/1'
            or len(support_names) != len(set(support_names))
            or not set(support_names) <= set(names)
            or any(row['kind'] not in ['child-worker', 'external-fixture-consumer'] for row in entries)):
        raise ValueError('support inventory differs from actual compiled registry')
    workers = [row['id'] for row in entries if row['kind'] == 'child-worker']
    consumers = [row['id'] for row in entries if row['kind'] == 'external-fixture-consumer']
    selected = [name for name in names if name not in support_names]
    if not selected or len(names) != len(set(names)):
        raise ValueError('invalid compiled registry')
    return selected, workers, consumers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--registry', type=Path, required=True)
    parser.add_argument('--postgres-fixture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    registry = json.loads(args.registry.read_text())
    fixture = json.loads(args.postgres_fixture.read_text())
    binary = Path(registry['binary'])
    names = registry['registered_tests']
    support = json.loads(Path(__file__).with_name('support-entrypoints.json').read_text())
    selected, workers, consumers = select(names, support)
    # Do not inherit fixture-update flags, child-peer commands or host credentials.
    environment = {name: os.environ[name] for name in ['PATH', 'HOME', 'TMPDIR'] if name in os.environ}
    environment.update({'AUTHS_POSTGRES_URL': 'host=localhost port=' + str(fixture['port'])
                        + ' dbname=auths_lifecycle user=auths password=local-fixture-password sslmode=require',
                        'AUTHS_POSTGRES_CA_PEM': str(Path(fixture['private_directory']) / 'generated/ca.crt'),
                        'AUTHS_POSTGRES_SERVER_NAME': 'localhost'})
    args.output.mkdir(parents=True, exist_ok=True)
    plan = {'schema': 'auths.security-assessment-native-selection/1', 'selected': selected,
            'excluded_worker_entrypoints': workers, 'unconfigured_fixture_consumers': consumers,
            'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            'source': registry['target_source'], 'harness_revision': registry['harness_revision'],
            'assurance_scope': 'fresh execution of existing native tests; not independent attack discovery'}
    (args.output / 'selection.json').write_text(json.dumps(plan, indent=2) + '\n')
    results = []
    for index, name in enumerate(selected):
        started = time.monotonic()
        command = [str(binary), '--include-ignored', '--exact', name, '--test-threads=2', '--nocapture']
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       env=environment, start_new_session=True)
            stdout, stderr = process.communicate(timeout=180)
            log = stdout + stderr
            verdicts = re.findall(rb'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', log)
            # Parent process tests also retain child harness output. Require the
            # final selected result and a successful named execution, never zero.
            named = b'test ' + name.encode() + b' ... ok' in log
            passed = process.returncode == 0 and named and verdicts and verdicts[-1] == (b'1', b'0', b'0')
            status, code = ('pass' if passed else 'finding'), process.returncode
        except subprocess.TimeoutExpired as error:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate()
            log = stdout + stderr
            status, code = 'inconclusive', None
        path = args.output / (str(index).zfill(3) + '.log')
        path.write_bytes(log)
        path.chmod(0o600)
        results.append({'id': name, 'status': status, 'returncode': code,
                        'backend': 'tls-postgresql' if 'postgres' in name else 'file-or-pure-native',
                        'elapsed_seconds': time.monotonic() - started,
                        'log': path.name, 'log_sha256': hashlib.sha256(log).hexdigest()})
        (args.output / 'results.json').write_text(json.dumps({'schema': 'auths.security-assessment-native-results/1',
                                                           'selection': plan, 'results': results}, indent=2) + '\n')
        if status != 'pass':
            print(json.dumps({'case': name, 'status': status}), flush=True)
    print(json.dumps({'selected': len(selected), 'passed': sum(x['status'] == 'pass' for x in results),
                      'tls_postgresql': sum(x['backend'] == 'tls-postgresql' for x in results),
                      'excluded_workers': len(workers)}))
    if any(x['status'] != 'pass' for x in results):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
