#!/usr/bin/env python3
"""Sign only proposals independently reconstructed from this protected source.

The commissioning inputs, candidate and SDK artifacts are public data. This
job executes only its own reviewer and issuer; its key is read after the whole
pool, corpus, policy statements and native evidence closure have been checked.
"""

import argparse
import os
from pathlib import Path
import shutil
import tempfile
import time
from types import SimpleNamespace
import tomllib

import artifact_wait
import commission

from common import canonical, closed, require, sha256
import expand
from family_corpus import authenticate, compile_plan
from resource_io import finish, write_bytes
from resource_summary import summary

ROOT = commission.ROOT
FIRST_EXCLUSION = ('First-run commissioning: ordinary installed clients were refused; their qualified '
                   'effect and production readiness require the subsequent live phase.')
DRAFT_FIELDS = ['qualification_id', 'provider_kind', 'tuple', 'not_before', 'not_after', 'provenance',
    'source_closure_sha256', 'generated_artifacts_sha256', 'installed_packages',
    'recipe_decision_record_sha256', 'corpus_manifest_sha256', 'provider_resources',
    'custody_descriptor', 'store_descriptor', 'residual_assumptions', 'excluded_claims']


def json(path, maximum=2 * 1024 * 1024):
    return expand.decode(expand.read(path, maximum))


def packages(candidate, wheel, typescript, commit, tuple_value):
    metadata = json(typescript / 'package.json')
    closed(metadata, ['schema', 'source_commit', 'name', 'version', 'file', 'sha256', 'qualification_issued'])
    source = json(ROOT / 'bindings/typescript/package.json')
    require(metadata['schema'] == 'auths.qualification-installed-package/1'
            and metadata['source_commit'] == commit and metadata['name'] == source['name']
            and metadata['version'] == source['version'] and metadata['qualification_issued'] is False
            and type(metadata['file']) is str and Path(metadata['file']).name == metadata['file']
            and metadata['file'].endswith('.tgz')
            and metadata['sha256'] == sha256(expand.read(typescript / metadata['file'], 64 * 1024 * 1024)),
            'qualification.sign.package-binding')
    python_version = tomllib.loads(expand.read(ROOT / 'bindings/python/pyproject.toml', 65536).decode())['project']['version']
    require(wheel.name.startswith('auths-' + python_version + '-') and wheel.suffix == '.whl',
            'qualification.sign.package-binding')
    return sorted([
        {'name': 'auths', 'version': python_version, 'sha256': sha256(expand.read(wheel, 64 * 1024 * 1024))},
        {'name': 'auths-gateway', 'version': tuple_value['target']['gateway_version'],
         'sha256': sha256(expand.read(candidate / 'bin/auths-gateway', 256 * 1024 * 1024))},
        {'name': source['name'], 'version': source['version'], 'sha256': metadata['sha256']},
    ], key=lambda value: value['name'])


def coverage(proposal, corpus, stage):
    expected = {case['id']: case for case in corpus['cases'] if case['phase'] in ['offline', stage]}
    actual = {}
    for path in sorted((proposal / 'evidence').iterdir()):
        require(path.name.endswith('.json'), 'qualification.sign.evidence-binding')
        for case in json(path)['cases']:
            name = case['id']
            if name in expected:
                require(name not in actual and case['scenario'] == expected[name]['scenario']
                        and type(case['capabilities']) is list
                        and len(case['capabilities']) == len(set(case['capabilities']))
                        and set(case['capabilities']) == set(expected[name]['capabilities'])
                        and case['unauthorized_provider_entries'] == 0,
                        'qualification.sign.corpus-coverage')
                actual[name] = case
            else:
                # Additional reports come only from native trust and publication
                # stages. They cannot substitute for a source-owned run case.
                require(not name.startswith(('offline-', 'commissioning-', 'live-')),
                        'qualification.sign.corpus-coverage')
    require(set(actual) == set(expected), 'qualification.sign.corpus-coverage')


def verify_proposal(family, stage, inputs, candidate, wheel, typescript, proposal, private, run, attempt, commit):
    issuer, reviewer = [ROOT / 'target/release' / name for name in ['auths-qualification', 'auths-gateway']]
    tuple_value = commission.source_contract(family, inputs, issuer)
    expansion = private / 'expansion'
    expand.expand(SimpleNamespace(source_commit=commit, protected_run='recipe-qualification/' + run + '/' + attempt,
        tuple=inputs / 'tuple.json', candidate=candidate / 'bin/auths-gateway', reviewer=reviewer,
        recipe=inputs / 'recipe.json', profile_lock=inputs / 'profile.lock.json', resources=inputs / 'resources.json',
        packets=inputs / 'packets/public-packets.json', conformance=inputs / 'offline/conformance.json',
        differential=inputs / 'offline/differential.json', out_dir=expansion))
    work = private / 'pool'
    work.mkdir(mode=0o700)
    for path in (inputs / 'packets').iterdir():
        write_bytes(work / path.name, expand.read(path, 2 * 1024 * 1024), new=True)
    for name in ['recipe.json', 'profile.lock.json', 'resources.json']:
        write_bytes(work / name, expand.read(inputs / name, 65536), new=True)
    resources, reviewed = authenticate(family, work, reviewer, tuple_value)
    corpus = compile_plan(family, resources, reviewed, tuple_value['compiled_recipe_sha256'])
    coverage(proposal, corpus, stage)
    record_bytes = expand.read(proposal / 'record.json', 2 * 1024 * 1024)
    record = expand.decode(record_bytes)
    now = int(time.time())
    start, end = record['not_before'], record['not_after']
    policy = json(ROOT / 'qualification/families' / family / 'record.json')
    require(type(start) is int and type(end) is int and now - 7200 < start <= now
            and now < end and end == start + (7200 if stage == 'commissioning' else policy['validity_days'] * 86400),
            'qualification.sign.validity-binding')
    expected = {
        'qualification_id': 'qlf_' + sha256(('\n'.join([family, commit, run + '-' + attempt, stage])).encode())[:32],
        'provider_kind': policy['provider_kind'], 'tuple': tuple_value,
        'not_before': start, 'not_after': end,
        'provenance': {'repository': 'github.com/auths-dev/auths-proof', 'commit': commit,
                       'workflow': '.github/workflows/recipe-qualification.yml', 'environment': 'gateway-custody-live'},
        'source_closure_sha256': sha256(commission.call(['/usr/bin/git', 'ls-tree', '-r', 'HEAD'])),
        'generated_artifacts_sha256': sha256(expand.read(candidate / 'bin/auths-gateway', 256 * 1024 * 1024)
                                            + expand.read(candidate / 'bin/auths-qualification', 256 * 1024 * 1024)),
        'installed_packages': packages(candidate, wheel, typescript, commit, tuple_value),
        'recipe_decision_record_sha256': sha256(expand.read(ROOT / 'qualification/families' / family / 'decision-record.md', 65536)),
        'corpus_manifest_sha256': sha256(canonical(corpus)), 'provider_resources': summary(family, resources),
        'custody_descriptor': policy['custody_descriptor'], 'store_descriptor': policy['store_descriptor'],
        'residual_assumptions': sorted(policy['residual_assumptions']),
        'excluded_claims': sorted(set(policy['excluded_claims'] + ([FIRST_EXCLUSION] if stage == 'commissioning' else []))),
    }
    require({name: record.get(name) for name in DRAFT_FIELDS} == expected
            and json(proposal / 'tuple.json') == tuple_value, 'qualification.sign.record-source-binding')
    draft = private / 'draft.json'
    write_bytes(draft, canonical({**expected, 'not_applicable': policy['not_applicable']}), new=True)
    reconstructed = private / 'reconstructed'
    commission.call([issuer, 'assemble', '--draft', draft, '--evidence-dir', proposal / 'evidence',
                     '--out-dir', reconstructed])
    require(expand.read(reconstructed / 'record.json', 2 * 1024 * 1024) == record_bytes,
            'qualification.sign.native-closure')
    return issuer, tuple_value


def sign(args):
    run, attempt, commit = artifact_wait.identity(os.environ)
    require(commission.call(['/usr/bin/git', 'rev-parse', 'HEAD']).decode().strip() == commit
            and not commission.call(['/usr/bin/git', 'status', '--porcelain']).strip(),
            'qualification.sign.source-binding')
    require(not args.out.exists() and not args.out.is_symlink(), 'qualification.sign.output-exists')
    require(args.family == sorted(set(args.family)) and 1 <= len(args.family) <= len(expand.REFERENCES),
            'qualification.sign.family-set')
    complete = False
    try:
        with tempfile.TemporaryDirectory(prefix='auths-source-release-') as temporary:
            private = Path(temporary)
            for family in args.family:
                local = private / family
                local.mkdir(mode=0o700)
                issuer, _tuple = verify_proposal(family, args.stage, args.inputs / family, args.candidate,
                    args.wheel, args.typescript, args.proposal / family, local, run, attempt, commit)
            seed = commission.signing_seed(os.environ.get('QUALIFICATION_RELEASE_SIGNER_KEY'))
            key, canaries = private / 'release-signer.key', private / 'canaries'
            write_bytes(key, seed, new=True)
            write_bytes(canaries, seed + b'\n', new=True)
            args.out.mkdir(mode=0o700)
            arguments = [issuer, 'sign']
            for family in args.family:
                arguments += ['--proposal-dir', args.proposal / family]
            commission.call([*arguments, '--signer-key', key,
                '--certificate', ROOT / 'qualification/trust/signer-certificate.json', '--out-dir', args.out])
            write_bytes(args.out / 'revocation-list.json', expand.read(ROOT / 'qualification/trust/revocation-list.json', 65536), new=True)
            for family in args.family:
                commission.call([issuer, 'verify', '--root', ROOT / 'qualification/trust/qualification-trust-root.json',
                    '--release-dir', args.out, '--deployment', args.inputs / family / 'tuple.json'])
            sources = sorted(path for path in args.out.rglob('*') if path.is_file())
            require(0 < len(sources) <= 256 and all(not path.is_symlink() for path in sources),
                    'qualification.sign.publication-bound')
            arguments = [issuer, 'stage-redaction', '--canaries', canaries]
            for path in sources:
                arguments += ['--source', 'evidence=' + str(path)]
            commission.call([*arguments, '--out', private / 'publication-scan.json'])
            complete = True
    finally:
        if not complete and args.out.exists():
            shutil.rmtree(args.out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family', choices=sorted(expand.REFERENCES), action='append', required=True)
    parser.add_argument('--stage', choices=['commissioning', 'live'], required=True)
    for name in ['inputs', 'candidate', 'wheel', 'typescript', 'proposal', 'out']:
        parser.add_argument('--' + name, type=lambda value: Path(value).absolute(), required=True)
    finish(lambda: sign(parser.parse_args()))


if __name__ == '__main__':
    main()
