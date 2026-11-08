#!/usr/bin/env python3
"""Assemble retained AP075 observations; never promote coverage into security closure.

The hand-authored claim/gap report owns conclusions. This utility freezes actual
results and selectors, and refuses missing or duplicate expected executions.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

from validate import validate


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def verify_bundle(output):
    manifest = json.loads((output / 'evidence-manifest.json').read_text())
    target = manifest['target_revision']
    names = [x['path'] for x in manifest['experiments']]
    if not names or len(names) != len(set(names)):
        raise ValueError('missing or duplicate evidence inventory')
    for item in manifest['experiments']:
        path = Path(item['path'])
        if path.is_absolute() or '..' in path.parts or digest(output / path) != item['sha256']:
            raise ValueError('retained evidence digest/path mismatch')
    rows = [json.loads(line) for line in (output / 'case-results.jsonl').read_text().splitlines()]
    ids = [x['id'] for x in rows]
    if not ids or len(ids) != len(set(ids)):
        raise ValueError('missing or duplicate case results')
    for row in rows:
        if (row['schema'] != 'auths.security-assessment-case-result/1'
                or row['target_revision'] != target or row['status'] not in
                ['pass', 'finding', 'inconclusive', 'not-run', 'not-applicable']):
            raise ValueError('invalid case attribution/status')
    retained = output / 'evidence'
    boundary = json.loads((retained / 'installed-stripe-boundary.json').read_text())
    baseline = json.loads((retained / 'baseline-comparison.json').read_text())
    validate(boundary, baseline, json.loads(Path(__file__).with_name('inventory.json').read_text()), target)
    native = json.loads((retained / 'native-census.json').read_text())
    expected = {x['id'] for x in boundary['cases']}
    expected.update('NATIVE:' + x['id'] for x in native['results'])
    expected.update('NATIVE:' + x['id'] for x in native.get('unconfigured_observations', []))
    expected.update('AP073:' + x['case'] for x in json.loads((retained / 'installed-delegation.json').read_text())['cases'])
    expected.update('REFERENCE:' + str(i).zfill(2) + ':' + x['case'] for i, x in
                    enumerate(json.loads((retained / 'installed-stripe-reference.json').read_text())['cases']))
    expected.update('ARTIFACT:' + x['id'] for x in json.loads((retained / 'artifact-controls.json').read_text())['cases'])
    expected.update('BASELINE:' + x['case'] for x in baseline['baseline_cases'])
    expected.update(['PORTABLE:go', 'PORTABLE:typescript'])
    if set(ids) != expected:
        raise ValueError('case census differs from retained source observations')
    plan = json.loads((output / 'test-plan.json').read_text())
    if {x['id'] for x in plan['cases']} != {f'SB{i:02d}' for i in range(1, 33)}:
        raise ValueError('missing required family disposition')
    for family in plan['cases']:
        if not family['variants'] or any(x['case_id'] not in ids for x in family['variants']):
            raise ValueError('missing family execution reference')
    ledger = json.loads((output / 'claim-ledger.json').read_text())
    if (ledger['target_revision'] != target
            or {x['id'] for x in ledger['claims']} != {f'SC{i:02d}' for i in range(1, 13)}):
        raise ValueError('missing claim disposition')
    if any(not x['evidence'] or not x.get('enforcement_paths') or not x.get('assumptions')
           for x in ledger['claims']):
        raise ValueError('missing claim basis')
    return {'schema': 'auths.security-assessment-report-validation/1', 'case_records': len(rows),
            'target_revision': target, 'coverage_is_security_closure': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    if args.verify:
        print(json.dumps(verify_bundle(args.output)))
        return
    if args.input is None:
        parser.error('--input required for assembly')
    root, output = args.input, args.output
    coverage = json.loads(Path(__file__).with_name('coverage.json').read_text())
    plan = json.loads((output / 'test-plan.json').read_text())
    claims = {row['id']: row['claims'] for row in plan['cases']}
    if set(coverage['native_patterns']) != set(claims):
        raise ValueError('coverage map must account for every required family')
    target = plan['target_revision']
    retained = output / 'evidence'
    retained.mkdir(exist_ok=True)
    manifest = json.loads((output / 'evidence-manifest.json').read_text())
    copies = {
        'installed-stripe-boundary.json': 'boundary/independent-stripe.json',
        'baseline-comparison.json': 'comparison/baseline-comparison.json',
        'installed-stripe-reference.json': 'reference/simulation.json',
        'installed-delegation.json': 'ap073/installed-delegation.json',
        'native-census.json': 'native/results.json',
        'native-before-support-audit.json': 'native/results-before-support-audit.json',
        'artifact-controls.json': 'artifact-controls.json',
        'go-semantic.jsonl': 'go-semantic.jsonl',
        'typescript-semantic.jsonl': 'typescript-semantic.jsonl',
    }
    experiments = []
    for name, relative in copies.items():
        source = root / relative
        destination = retained / name
        shutil.copyfile(source, destination)
        experiments.append({'name': name, 'path': 'evidence/' + name,
                            'sha256': digest(destination), 'target_revision': target,
                            'provenance': 'see reproduce.md and record-specific harness identity'})
        if name in ['installed-stripe-boundary.json', 'baseline-comparison.json']:
            experiments[-1]['executed_harness_revision'] = '9ba04192e332966ea7f7f173d6ad21c11a1ed779'
        elif name == 'installed-stripe-reference.json':
            experiments[-1]['executed_harness_revision'] = 'working tree derived from 9ba04192; corrected DNS launch'
            experiments[-1]['harness_byte_snapshot_at_execution'] = 'not captured; narrower provenance than committed boundary campaign'
        elif name == 'native-census.json':
            experiments[-1]['executed_harness_sha256'] = '3e7013756d6b67d193ab86c297c11680751de8fe2c55dd62256e16e4c880a70a'
    manifest['experiments'] = experiments
    manifest['assessment_tool_sha256'] = {
        path.name: digest(path) for path in sorted(Path(__file__).parent.glob('*')) if path.is_file()
    }
    manifest['native_runner_executed_sha256'] = '3e7013756d6b67d193ab86c297c11680751de8fe2c55dd62256e16e4c880a70a'
    write(output / 'evidence-manifest.json', manifest)

    records = []

    def add(identifier, families, kind, result, reference, command, backend, limitations):
        records.append({'schema': 'auths.security-assessment-case-result/1', 'id': identifier,
                        'families': families, 'claims': sorted({c for f in families for c in claims[f]}),
                        'target_revision': target, 'remediation_revision': None,
                        'artifact_digests': 'evidence-manifest.json', 'evidence_kind': kind,
                        'backend': backend, 'topology': 'scope-and-threat-model.md',
                        'command': command, 'schedule_and_input': reference,
                        'positive_control': 'see family mapping; not independently reauthored for existing tests',
                        'expected': 'assertions in cited case under the bounded contract',
                        'actual': result, 'credential_leases': None, 'deliveries': None,
                        'durable_accounting': 'case assertions; no inferred count from status strings',
                        'evidence': reference, 'limitations': limitations,
                        'status': result.get('status', 'pass')})

    boundary = json.loads((retained / 'installed-stripe-boundary.json').read_text())
    for row in boundary['cases']:
        add(row['id'], row['families'], 'new independent transport/effect observation', row,
            'evidence/installed-stripe-boundary.json#' + row['id'],
            'stripe_probe.py --suite boundary; exact row selected within full inventory', 'file',
            ['Synthetic loopback provider; trusted lab controller; finite schedules.',
             'A changed signed byte is not a valid widened delegation.',
             'Positive control fully checks amount/payment; double enforces fixed contract headers/path.'])
    native = json.loads((retained / 'native-census.json').read_text())
    selected = native['selection']['selected']
    if len(selected) != len(set(selected)) or {x['id'] for x in native['results']} != set(selected):
        raise ValueError('native registry/result mismatch')
    if native['selection']['source'] != target:
        raise ValueError('wrong native source')
    for row in native['results']:
        families = [f for f, patterns in coverage['native_patterns'].items()
                    if any(p in row['id'] for p in patterns)]
        add('NATIVE:' + row['id'], families, 'existing native regression freshly executed', row,
            'evidence/native-census.json#' + row['id'],
            '<pinned-native-test-binary> --include-ignored --exact ' + row['id']
            + ' --test-threads=2 --nocapture', row['backend'],
            ['Existing implementation assertions are supplemental, not independent attack discovery.',
             'Backend label identifies selected PostgreSQL tests; remaining tests include pure and file tests.',
             'Raw per-case logs are private local artifacts identified by retained hashes.'])
    for row in native.get('unconfigured_observations', []):
        add('NATIVE:' + row['id'], [], 'unconfigured support execution; not security evidence', row,
            'evidence/native-census.json#unconfigured_observations/' + row['id'],
            '<pinned-native-test-binary> --include-ignored --exact ' + row['id']
            + ' --test-threads=2 --nocapture', 'unconfigured support',
            ['Initial wrapper misclassified an early successful return. Corrected to not-run; not counted as a scenario.'])
    delegation = json.loads((retained / 'installed-delegation.json').read_text())
    if len(delegation['cases']) != 8 or len({x['case'] for x in delegation['cases']}) != 8:
        raise ValueError('installed delegation census mismatch')
    for row in delegation['cases']:
        if (row['distinct_uids'] is not True or row['private_keys_exported_to_orchestrator'] != 0
                or row['restart_replay_new_writes'] != 0 or row['disclosure_replay_deliveries'] != 0
                or row['recovery_replay_provider_calls'] != 0):
            raise ValueError('installed delegation observation violates contract')
        families = [f for f, patterns in coverage['ap073_patterns'].items()
                    if any(p in row['case'] for p in patterns)]
        add('AP073:' + row['case'], families, 'existing installed multi-process journey', row,
            'evidence/installed-delegation.json#' + row['case'],
            'auths-ap073-journey --ignored --exact '
            'delegation_process::native_installed_delegation_process_fixture_is_current --nocapture',
            'file', row['not_established'])
    reference = json.loads((retained / 'installed-stripe-reference.json').read_text())
    if len(reference['cases']) != 23 or reference['source_commit'] != target:
        raise ValueError('reference census/source mismatch')
    for index, row in enumerate(reference['cases']):
        # Repeated labels can describe distinct before/after-restart steps.
        # Retain their ordinal rather than silently deduplicating observations.
        add('REFERENCE:' + str(index).zfill(2) + ':' + row['case'], [], 'existing installed Stripe reference', row,
            'evidence/installed-stripe-reference.json#/cases/' + str(index), 'stripe_probe.py --suite reference',
            'file', ['Existing scripted approvals; no human presence or live provider qualification.'])
    for row in json.loads((retained / 'artifact-controls.json').read_text())['cases']:
        add('ARTIFACT:' + row['id'], ['SB30'], 'assessment acquisition mutation control', row,
            'evidence/artifact-controls.json#' + row['id'],
            'artifact_probes.py --manifest <pinned-manifest> --cache <archives> --output <report>',
            'package acquisition', ['Mutants not executed; test repins outer digest to reach nested checks.'])
    for row in json.loads((retained / 'baseline-comparison.json').read_text())['baseline_cases']:
        add('BASELINE:' + row['case'], [], 'conventional research adapter comparison', row,
            'evidence/baseline-comparison.json#' + row['case'], 'compare.py',
            'SQLite/local HTTP', ['No production OAuth deployment, delegation or transferable public-key audit.'])
    for language in ['go', 'typescript']:
        lines = (retained / (language + '-semantic.jsonl')).read_text().splitlines()
        vectors = [json.loads(line) for line in lines]
        if (len(lines) != 323 or len({x['name'] for x in vectors}) != 323
                or any(x['mismatched_fields'] for x in vectors)):
            raise ValueError('independent semantic corpus census mismatch')
        add('PORTABLE:' + language, ['SB28', 'SB29'], 'specification-derived portable semantic verifier',
            {'status': 'pass', 'vectors': len(lines)}, 'evidence/' + language + '-semantic.jsonl',
            'see reproduce.md for exact independent semantic corpus command', 'offline portable core',
            ['Portable contract only; not a gateway, binding ABI or stateful execution proof.'])
    for family in plan['cases']:
        related = [x for x in records if family['id'] in x['families']]
        if not related:
            raise ValueError('missing family disposition: ' + family['id'])
        family['variants'] = [{'case_id': x['id'], 'kind': x['evidence_kind']} for x in related]
        family['execution_status'] = 'tested-with-limitations'
        family['coverage_claim'] = 'Related concrete executions; not exhaustive establishment of every stated variant.'
        family['positive_control'] = 'POSITIVE-exact-after-hostile-inputs plus existing paired native/journey controls'
        family['remaining_gaps'] = 'findings.md; do not infer a passed release gate from this mapping'
    plan['phase'] = 'executed-and-dispositioned-with-explicit-gaps'
    for batch in plan['batches']:
        batch['status'] = 'executed; see retained census and limitations'
    plan['native_census'] = {'registered': len(selected) + len(native['selection']['excluded_worker_entrypoints'])
                            + len(native['selection'].get('unconfigured_fixture_consumers', [])),
                            'selected': len(selected), 'excluded_worker_entrypoints': len(native['selection']['excluded_worker_entrypoints']),
                            'unconfigured_fixture_consumers': len(native['selection'].get('unconfigured_fixture_consumers', [])),
                            'tls_postgresql': sum(x['backend'] == 'tls-postgresql' for x in native['results'])}
    write(output / 'test-plan.json', plan)
    identifiers = [x['id'] for x in records]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError('duplicate case IDs')
    (output / 'case-results.jsonl').write_text(''.join(json.dumps(x, separators=(',', ':')) + '\n' for x in records))
    print(json.dumps({'case_records': len(records), 'families_dispositioned': len(plan['cases']),
                      'security_closure_inferred': False}))


if __name__ == '__main__':
    main()
