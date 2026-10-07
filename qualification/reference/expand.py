#!/usr/bin/env python3
"""Recompute finite commissioning bindings from reviewed source and public input.

Run only the reviewer binary built by the signing job from its own checkout.
The downloaded candidate is hashed, never executed in the signing environment.
No program, expected request, actor or action commitment from an artifact is
trusted. The resulting binding is still unsigned and proves no live behavior.
"""

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

import airtable_record
import stripe_platform
from common import Refusal, canonical, closed, digest, identifier, require, sha256, text

REFERENCES = {reference.FAMILY: reference for reference in [stripe_platform, airtable_record]}
MAXIMUM_LEASES = 64
REPOSITORY = Path(__file__).resolve().parents[2]
SOURCES = {
    stripe_platform.FAMILY: REPOSITORY / 'qualification/simulation/live/stripe-platform',
    airtable_record.FAMILY: REPOSITORY / 'bindings/fixtures/gateway/airtable',
}


def read(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and 0 < metadata.st_size <= maximum,
                'qualification.reference.input-bound')
        value = stream.read(maximum + 1)
    require(0 < len(value) <= maximum, 'qualification.reference.input-bound')
    return value


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'qualification.reference.duplicate-field')
        value[key] = item
    return value


def decode(value):
    return json.loads(value, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refusal('qualification.reference.number')))


def child(binary, arguments):
    # Never inherit signer keys or provider credentials. A reviewed executable
    # has no custody input, store, installation or network operation here.
    result = subprocess.run([str(binary), *map(str, arguments)], capture_output=True,
                            timeout=15, env={'PATH': '/usr/bin:/bin'}, cwd='/')
    require(result.returncode == 0 and 0 < len(result.stdout) <= 65536
            and len(result.stderr) <= 65536, 'qualification.reference.native-review')
    return decode(result.stdout)


def member(path, name, commit, tuple_digest):
    raw = read(path, 2 * 1024 * 1024)
    body = decode(raw)
    require(raw == canonical(body) and body['schema'] == 'auths.qualification-evidence/1'
            and body['member'] == name and body['commit'] == commit
            and body['tuple_sha256'] == tuple_digest,
            'qualification.reference.offline-binding')
    # The native issuer subsequently validates the closed evidence type and
    # every mandatory scenario. This hash is independently rederived here.
    return sha256(body['schema'].encode() + b'\0' + raw)


def relative(work, value):
    identifier(value, r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}')
    return work / value


def expand(args):
    commit = identifier(args.source_commit, r'[0-9a-f]{40}')
    protected_run = text(args.protected_run, maximum=256)
    require('GITHUB_SHA' not in os.environ or os.environ['GITHUB_SHA'] == commit,
            'qualification.reference.source-binding')
    if 'GITHUB_RUN_ID' in os.environ:
        expected = 'recipe-qualification/' + os.environ['GITHUB_RUN_ID'] + '/' + os.environ['GITHUB_RUN_ATTEMPT']
        require(protected_run == expected, 'qualification.reference.run-binding')
    tuple_value = decode(read(args.tuple, 65536))
    reference = REFERENCES.get(tuple_value['recipe_family'])
    require(reference is not None, 'qualification.reference.family')
    target = tuple_value['target']
    require(target['os'] == 'linux' and target['arch'] == 'x86_64'
            and target['store_kind'] == 'postgresql-v1'
            and target['store_schema'] == 'auths.lifecycle.postgresql/6'
            and target['credential_store_kind'] == 'aws-secrets-manager-v1',
            'qualification.reference.production-target')
    require(sha256(read(args.candidate, 256 * 1024 * 1024)) == target['gateway_build_sha256'],
            'qualification.reference.candidate-bytes')
    actual = child(args.reviewer, ['qualification-candidate', '--recipe', args.recipe,
                                  '--profile-lock', args.profile_lock, '--recipe-family', reference.FAMILY,
                                  '--provider-contract-id', tuple_value['provider_contract_id']])
    # Separate builds can differ in executable bytes. Their source-owned
    # semantic closure, compiled recipe, lock and all other target fields must
    # agree. Only the original candidate digest enters signed authority.
    actual['target']['gateway_build_sha256'] = target['gateway_build_sha256']
    require(actual == tuple_value, 'qualification.reference.candidate-binding')
    resources_raw = read(args.resources, 65536)
    bound_resources = reference.resources(decode(resources_raw), protected_run)
    require(resources_raw == canonical(bound_resources), 'qualification.reference.resource-canonical')
    source = SOURCES[reference.FAMILY]
    expected_recipe = reference.recipe(decode(read(source / 'recipe.json', 65536)), bound_resources)
    require(decode(read(args.recipe, 65536)) == expected_recipe
            and read(args.profile_lock, 65536) == read(source / 'profile.lock.json', 65536),
            'qualification.reference.reviewed-source')
    plan = decode(read(args.packets, 65536))
    closed(plan, ['schema', 'protected_run', 'evaluated_at', 'not_after', 'trusted_context', 'packets'])
    require(plan['schema'] == 'auths.qualification-public-packets/2'
            and plan['protected_run'] == protected_run
            and type(plan['evaluated_at']) is int and 60 <= plan['evaluated_at'] <= 253402300499
            and type(plan['not_after']) is int
            and plan['evaluated_at'] < plan['not_after'] <= plan['evaluated_at'] + 300
            and int(time.time()) - 7200 <= plan['evaluated_at'] <= int(time.time()) + 60
            and type(plan['packets']) is list and 1 <= len(plan['packets']) <= 64,
            'qualification.reference.packet-bound')
    work = args.packets.parent
    context = relative(work, plan['trusted_context'])
    context_bytes = read(context, 4 * 1024 * 1024)
    actors, commitments, labels, oracle = set(), set(), set(), []
    for packet in plan['packets']:
        closed(packet, ['label', 'proof', 'action', 'arguments'])
        label = identifier(packet['label'], r'[a-z][a-z0-9-]{0,63}')
        require(label not in labels, 'qualification.reference.packet-bound')
        labels.add(label)
        proof, action = relative(work, packet['proof']), relative(work, packet['action'])
        read(proof, 4 * 1024 * 1024)
        read(action, 65536)
        reviewed = child(args.reviewer, ['review-submission', '--recipe', args.recipe,
                                         '--profile-lock', args.profile_lock, '--trusted-context', context,
                                         '--proof', proof, '--action', action,
                                         '--evaluated-at', str(plan['evaluated_at'])])
        require(reviewed.get('schema') == 'auths.gateway-submission-review/1'
                and len(reviewed['actors']) == 1 and reviewed['arguments'] == packet['arguments'],
                'qualification.reference.proof-binding')
        commitment = digest(reviewed['action_commitment'])
        expected = reference.request(packet['arguments'], bound_resources, commitment,
                                     tuple_value['compiled_recipe_sha256'])
        require(reviewed['request'] == expected, 'qualification.reference.oracle-mismatch')
        actors.add(reviewed['actors'][0])
        commitments.add(commitment)
        oracle.append({'label': label, 'request_sha256': sha256(canonical(expected)),
                       'action_commitment': commitment})
    require(len(actors) == 1, 'qualification.reference.principal-binding')
    tuple_digest = sha256(b'auths.qualification-tuple/1\0' + canonical(tuple_value))
    binding = {
        'protected_run': protected_run, 'source_commit': commit, 'tuple': tuple_value,
        'principal_sha256': sha256(next(iter(actors)).encode()),
        'trusted_contexts_sha256': [sha256(context_bytes)], 'resources_sha256': sha256(resources_raw),
        'provider_environment_class': reference.ENVIRONMENT,
        'offline_evidence': {
            'conformance_sha256': member(args.conformance, 'conformance', commit, tuple_digest),
            'differential_sha256': member(args.differential, 'differential', commit, tuple_digest),
        },
        'allowed_actions': sorted(commitments), 'maximum_credential_leases': MAXIMUM_LEASES,
    }
    require(not args.out_dir.exists(), 'qualification.reference.output-exists')
    args.out_dir.mkdir(mode=0o700)
    (args.out_dir / 'binding.json').write_bytes(canonical(binding))
    (args.out_dir / 'oracle-commitments.json').write_bytes(canonical({
        'schema': 'auths.qualification-reference-expansion/1',
        'protected_run': protected_run, 'source_commit': commit,
        'binding_sha256': sha256(canonical(binding)), 'oracle': oracle,
        'qualification_issued': False,
    }))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ['tuple', 'candidate', 'reviewer', 'recipe', 'profile-lock', 'resources',
                     'packets', 'conformance', 'differential', 'out-dir']:
        parser.add_argument('--' + argument, type=lambda value: Path(value).absolute(), required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--protected-run', required=True)
    args = parser.parse_args()
    try:
        expand(args)
    except Refusal as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, KeyError, ValueError, TypeError, RecursionError, OverflowError,
            subprocess.SubprocessError):
        print('qualification.reference.invalid-input', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
