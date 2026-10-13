#!/usr/bin/env python3
"""Sign installation statements with a separate installed-SDK operator key.

The credential-free process keeps its key in memory, signs only the source
installation's two contexts, and exports no key or qualification authority.
This establishes technical separation by key, never a human release review.
"""

import argparse
import base64
from pathlib import Path
import time

from author_packets import installed_native
from common import canonical, closed, require, sha256
from expand import child, decode, read
from resource_io import finish, write

SCHEMA = 'auths.gateway-operator-attestation/1'
ALIAS = 'recipe-qualification'


def checked_statement(request, key, installation):
    closed(request, ['statement', 'preimage_b64'])
    statement = request['statement']
    closed(statement, ['schema', 'operator_principal', 'principal_method',
        'verification_method', 'signature_suite', 'installation', 'issued_at'])
    now = int(time.time())
    require(statement['schema'] == SCHEMA
            and statement['operator_principal'] == key.principal
            and statement['principal_method'] == key.principal_method
            and statement['verification_method'] == key.verification_method
            and statement['signature_suite'] == key.suite
            and statement['installation'] == installation
            and type(statement['issued_at']) is int
            and now - 60 <= statement['issued_at'] <= now,
            'qualification.operator.statement-binding')
    preimage = SCHEMA.encode() + b'\0' + canonical(statement)
    require(request['preimage_b64'] == base64.urlsafe_b64encode(preimage).rstrip(b'=').decode(),
            'qualification.operator.preimage-binding')
    return statement, preimage


def author(gateway, work):
    native, version = installed_native()
    key = native.DevelopmentEd25519Key.generate()
    tuple_value = decode(read(work / 'tuple.json', 65536))
    carrier = decode(read(work / 'public-packets.json', 65536))
    require(carrier['trusted_contexts'] == ['context-0.cbor', 'context-1.cbor'],
            'qualification.operator.context-binding')
    family = tuple_value['recipe_family']
    require(family in ['stripe-platform-refund-v1', 'airtable-record-update-v1'],
            'qualification.operator.family')
    provider = 'stripe' if family == 'stripe-platform-refund-v1' else 'airtable'
    review = child(gateway, ['review', '--recipe', work / 'recipe.json',
                            '--profile-lock', work / 'profile.lock.json'])
    require(review['recipe_digest'] == tuple_value['compiled_recipe_sha256'],
            'qualification.operator.recipe-binding')
    for context in carrier['trusted_contexts']:
        installation = {'recipe_digest': tuple_value['compiled_recipe_sha256'],
            'profile_lock_sha256': sha256(read(work / 'profile.lock.json', 65536)),
            'trusted_context_sha256': sha256(read(work / context, 4 * 1024 * 1024)),
            'provider': provider, 'alias': ALIAS, 'deployment': 'production'}
        require(installation['profile_lock_sha256'] == tuple_value['profile_lock_sha256'],
                'qualification.operator.lock-binding')
        request = child(gateway, ['operator-request', '--recipe', work / 'recipe.json',
            '--profile-lock', work / 'profile.lock.json', '--trusted-context', work / context,
            '--provider', provider, '--alias', ALIAS, '--deployment', 'production',
            '--operator-principal', key.principal, '--principal-method', key.principal_method,
            '--verification-method', key.verification_method, '--signature-suite', key.suite])
        statement, preimage = checked_statement(request, key, installation)
        signature = bytes(key.sign(preimage))
        native.verify_ed25519_preimage_v1(bytes(key.public_key), preimage, signature)
        write(work / (context + '.operator.json'), {'statement': statement,
            'signature_b64': base64.urlsafe_b64encode(signature).rstrip(b'=').decode(),
            'evidence': [{'evidence_type': key.evidence_type, 'media_type': key.media_type,
                'bytes_b64': base64.urlsafe_b64encode(bytes(key.evidence)).rstrip(b'=').decode()}]}, new=True)
    write(work / 'operator-report.json', {'schema': 'auths.qualification-operator-author/1',
        'sdk_version': version, 'operator_principal': key.principal,
        'contexts': carrier['trusted_contexts'], 'private_key_exported': False,
        'provider_token_received': False, 'repository_imported': False,
        'human_review_claimed': False, 'production_install_verified': False,
        'qualification_issued': False}, new=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gateway', type=lambda value: Path(value).absolute(), required=True)
    parser.add_argument('--work', type=lambda value: Path(value).absolute(), required=True)
    args = parser.parse_args()
    finish(lambda: author(args.gateway, args.work))


if __name__ == '__main__':
    main()
