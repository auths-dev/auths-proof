"""Reviewed family harness. Offline steps perform actual native checks.

Protected operations require the source-owned production journey. No missing
operation produces an observation or a passing report.
"""

import copy
import os
from pathlib import Path
import subprocess
import sys

import airtable_record
import stripe_platform
from common import canonical, closed, require, sha256
from expand import child, decode, read, SOURCES
from family_corpus import authenticate, compile_plan, RESOURCES
from packet_plan import prepare as packet_prepare
from resource_io import finish, run_id, write, write_bytes

ROOT = Path(__file__).resolve().parents[2]
REFERENCES = {r.FAMILY: r for r in [stripe_platform, airtable_record]}


def command(arguments, cwd=ROOT):
    result = subprocess.run(list(map(str, arguments)), capture_output=True, timeout=90,
        cwd=cwd, env={'PATH': '/usr/bin:/bin', 'PYTHONNOUSERSITE': '1'})
    require(len(result.stdout) <= 65536 and len(result.stderr) <= 65536,
            'qualification.harness.output-bound')
    return result


def gateway():
    return Path(os.environ['AUTHS_GATEWAY']).resolve(strict=True)


def consumer_python():
    # Resolving a venv launcher symlink selects the base interpreter and loses
    # its installed wheel. Keep the absolute launcher path when executing it.
    python = Path(os.environ['AUTHS_QUALIFICATION_CONSUMER_PYTHON']).absolute()
    require(python.is_file() and os.access(python, os.X_OK),
            'qualification.harness.consumer-python')
    return python


def source_commit():
    # A protected root controller reads the runner-owned checkout. Trust only
    # this exact source directory for these read-only Git invocations.
    git = ['/usr/bin/git', '-c', 'safe.directory=' + str(ROOT)]
    revision = command([*git, 'rev-parse', 'HEAD'])
    status = command([*git, 'status', '--porcelain'])
    require(revision.returncode == status.returncode == 0 and not status.stdout.strip(),
            'qualification.harness.source-not-clean')
    commit = revision.stdout.decode('ascii').strip()
    require('GITHUB_SHA' not in os.environ or os.environ['GITHUB_SHA'] == commit,
            'qualification.harness.source-binding')
    return commit


def synthetic_resources(family, protected_run):
    if family == stripe_platform.FAMILY:
        return {'schema': 'auths.stripe-platform-qualification-resources/1',
            'protected_run': protected_run, 'platform': 'acct_SYNTHETIC', 'payments': [
                {'id': 'pi_SYNTHETIC' + str(index).zfill(2), 'amount_received': 2000,
                 'currency': 'usd', 'livemode': False, 'run_metadata': protected_run}
                for index in range(RESOURCES)]}
    return {'schema': 'auths.airtable-record-qualification-resources/1',
        'protected_run': protected_run, 'base': airtable_record.BASE, 'table': airtable_record.TABLE,
        'records': [{'id': 'recTEST' + str(index).zfill(10), 'run_metadata': protected_run}
                    for index in range(RESOURCES)]}


def candidate(family, work):
    issuer = Path(os.environ['AUTHS_QUALIFICATION']).resolve(strict=True)
    contract = command([issuer, 'contract-id', '--contract',
                        ROOT / 'qualification/families' / family / 'contract.json'])
    require(contract.returncode == 0, 'qualification.harness.contract')
    return child(gateway(), ['qualification-candidate', '--recipe', work / 'recipe.json',
        '--profile-lock', work / 'profile.lock.json', '--recipe-family', family,
        '--provider-contract-id', contract.stdout.decode('ascii').strip()])


def prepare(family, work):
    from generate_families import generate
    generate(check=True)
    source_commit()
    require(work.is_dir() and not work.is_symlink(), 'qualification.harness.work-directory')
    os.chmod(work, 0o700)
    protected_run = run_id('recipe-qualification/' + os.environ['GITHUB_RUN_ID'] + '/' + os.environ['GITHUB_RUN_ATTEMPT'])
    write(work / 'resources.json', synthetic_resources(family, protected_run), new=True)
    packet_prepare(type('Inputs', (), {'family': family, 'resources': work / 'resources.json',
                                     'gateway': gateway(), 'work': work})())
    # The wheel and public author kit are installed/copied by the credential-
    # free workflow. The SDK process never receives this checkout or its env.
    python = consumer_python()
    kit = Path(os.environ['AUTHS_QUALIFICATION_AUTHOR_KIT']).resolve(strict=True)
    result = command([python, '-B', kit / 'author_packets.py', '--plan', work / 'packet-plan.json',
                      '--work', work], cwd=work)
    require(result.returncode == 0, 'qualification.harness.installed-author')
    tuple_value = candidate(family, work)
    write(work / 'tuple.json', tuple_value, new=True)
    operator = command([python, '-B', kit / 'author_operator.py',
                        '--gateway', gateway(), '--work', work], cwd=work)
    require(operator.returncode == 0, 'qualification.harness.installed-operator')
    resources, reviewed = authenticate(family, work, gateway(), tuple_value)
    operator_report = decode(read(work / 'operator-report.json', 65536))
    require(all(operator_report['operator_principal'] not in value['actors']
                for value in reviewed.values()), 'qualification.harness.operator-separation')
    corpus = compile_plan(family, resources, reviewed, tuple_value['compiled_recipe_sha256'])
    write_bytes(work / 'corpus.json', canonical(corpus), new=True)
    author = decode(read(work / 'author-report.json', 65536))
    wheel = Path(os.environ['AUTHS_QUALIFICATION_WHEEL']).resolve(strict=True)
    write(work / 'packages.json', sorted([
        {'name': 'auths', 'version': author['sdk_version'], 'sha256': sha256(read(wheel, 64 * 1024 * 1024))},
        {'name': 'auths-gateway', 'version': tuple_value['target']['gateway_version'],
         'sha256': tuple_value['target']['gateway_build_sha256']},
    ], key=lambda package: package['name']), new=True)


def review(work, packet, evaluated_at):
    return child(gateway(), ['review-submission', '--recipe', work / 'recipe.json',
        '--profile-lock', work / 'profile.lock.json', '--trusted-context', work / packet['trusted_context'],
        '--proof', work / packet['proof'], '--action', work / packet['action'],
        '--evaluated-at', str(evaluated_at)])


def hostile(work):
    original = decode(read(work / 'recipe.json', 65536))
    changes = [lambda value: value.update(unreviewed=True),
        lambda value: value.update(schema='auths.gateway-recipe-source/0'),
        lambda value: value.update(origin='http://api.example.invalid'),
        lambda value: value['credential'].update(kind='unreviewed-adapter'),
        lambda value: value['write'].update(method='CONNECT'),
        lambda value: value['write'].update(unreviewed=True),
        lambda value: value['write']['path'][0].update(kind='caller-url'),
        lambda value: value['observation'].update(unreviewed=True),
        lambda value: value['echo']['write'].update(kind='caller-header')]
    directory = work / 'hostile-recipes'
    directory.mkdir(mode=0o700, exist_ok=True)
    for index, change in enumerate(changes):
        value = copy.deepcopy(original)
        change(value)
        path = directory / (str(index) + '.json')
        write(path, value, new=not path.exists())
        refusal = command([gateway(), 'review', '--recipe', path,
                           '--profile-lock', work / 'profile.lock.json'])
        require(refusal.returncode != 0 and b'gateway.' in refusal.stderr,
                'qualification.harness.hostile-recipe-admitted')


def offline(family, identifier, index, operation, work):
    tuple_value = decode(read(work / 'tuple.json', 65536))
    resources = decode(read(work / 'resources.json', 65536))
    reference = REFERENCES[family]
    reference.resources(resources, resources['protected_run'])
    carrier = decode(read(work / 'public-packets.json', 65536))
    packet = carrier['packets'][0]
    verdict = {'outcome': 'complete', 'code': None, 'request_sha256': None, 'evidence_sha256': None}
    if identifier in ['source', 'digest', 'vectors', 'closed']:
        require(index == 0 and operation == 'probe', 'qualification.harness.step')
        if identifier == 'source':
            source_commit()
            require(candidate(family, work) == tuple_value, 'qualification.harness.candidate-changed')
            verdict['code'] = 'source-clean'
        elif identifier == 'digest':
            value = child(gateway(), ['review', '--recipe', work / 'recipe.json',
                                     '--profile-lock', work / 'profile.lock.json'])
            require(value['recipe_digest'] == tuple_value['compiled_recipe_sha256'],
                    'qualification.harness.recipe-digest')
            require(read(work / 'profile.lock.json', 65536) == read(SOURCES[family] / 'profile.lock.json', 65536),
                    'qualification.harness.lock-drift')
            verdict['code'] = 'recipe-digest-rederived'
        elif identifier == 'vectors':
            authenticate(family, work, gateway(), tuple_value)
            verdict['code'] = 'recipe-vectors-passed'
        else:
            hostile(work)
            verdict['code'] = 'closed-enumeration-refused'
    else:
        require(identifier in ['oracle-accept', 'oracle-reject'] and index in [0, 1]
                and operation == ['oracle', 'review'][index], 'qualification.harness.step')
        if identifier == 'oracle-reject':
            if operation == 'review':
                actual = review(work, packet, carrier['evaluated_at'] - 1)
                closed(actual, ['outcome', 'code'])
                require(actual['outcome'] == 'denied' and actual['code'] == 'action-outside-validity',
                        'qualification.harness.native-time-refusal')
            # The source author starts every action at this recorded time.
            # One second earlier is outside that closed action interval;
            # this is offline evaluation, never a production-clock override.
            verdict.update(outcome='refused', code='action-outside-validity')
        else:
            actual = review(work, packet, carrier['evaluated_at'])
            expected = reference.request(packet['arguments'], resources, actual['action_commitment'],
                                         tuple_value['compiled_recipe_sha256'])
            if operation == 'review':
                require(actual['arguments'] == packet['arguments'], 'qualification.harness.arguments')
                outbound = actual['request']
            else:
                # Only the authenticated action commitment is taken from
                # native review. The oracle constructs every request byte.
                outbound = expected
            verdict.update(code='request-mapped', request_sha256=sha256(canonical(outbound)))
    return {'tuple_sha256': sha256(b'auths.qualification-tuple/1\0' + canonical(tuple_value)),
        'observed': {'verdict': verdict, 'credential_leases': 0, 'provider_entries': 0,
                     'confirmed_by_read_back': 0}, 'fresh_evidence': None,
        'unauthorized_provider_entries': 0, 'secret_exposed': False,
        'repository_imported': False, 'provider_token_received': False}


def main(family, arguments):
    def dispatch():
        require(family in REFERENCES and type(arguments) is list, 'qualification.harness.family')
        if len(arguments) == 2 and arguments[0] == 'prepare':
            return prepare(family, Path(arguments[1]).absolute())
        if len(arguments) == 2 and arguments[0] == 'cleanup':
            # No protected setup has been configured yet. Cleanup can complete
            # only for the exact synthetic ledger this offline source prepared;
            # it cannot claim retirement of any real resource.
            work = Path(arguments[1]).absolute()
            resources = decode(read(work / 'resources.json', 65536))
            require(resources == synthetic_resources(family, resources['protected_run']),
                    'qualification.harness.real-resources-not-retired')
            return
        if len(arguments) == 6 and arguments[0] == 'step':
            _, case, index, operation, directory, output = arguments
            if case.startswith('offline-'):
                value = offline(family, case.removeprefix('offline-'), int(index), operation, Path(directory).absolute())
            else:
                controller = os.environ.get('AUTHS_QUALIFICATION_CONTROLLER')
                require(controller is not None, 'qualification.harness.protected-journey-not-configured')
                from controller_socket import call
                value = call(controller, family, case, int(index), operation)
            return write(Path(output).absolute(), value, new=True)
        # No helper can silently complete an unimplemented protected step,
        # provision development custody, or manufacture a live observation.
        require(False, 'qualification.harness.protected-journey-not-configured')
    finish(dispatch)
