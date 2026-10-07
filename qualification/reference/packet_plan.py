#!/usr/bin/env python3
"""Prepare public packet inputs from the two reviewed resource carriers.

No credential is accepted. The installed author receives only the recipe pin,
closed bounded arguments and a public grant extension from the native gateway.
"""

import argparse
from pathlib import Path
import time

import airtable_record
import stripe_platform
from common import canonical, closed, digest, require, sha256
from expand import child, decode, read, SOURCES
from resource_io import finish, run_id, write, write_bytes

REFERENCES = {reference.FAMILY: reference for reference in [stripe_platform, airtable_record]}
PACKET_VALIDITY = 7200


def arguments(family, resources, recipe_digest):
    """One separate operation per resource and phase; reuse never adds a write."""
    reference = REFERENCES.get(family)
    require(reference is not None, 'qualification.packets.family')
    reference.resources(resources, run_id(resources['protected_run']))
    recipe_digest = digest(recipe_digest)
    namespace = reference.SERVICE if reference is stripe_platform else 'airtable-demo'
    values = resources['payments'] if reference is stripe_platform else resources['records']
    packets = []
    for phase in ['commissioning', 'live']:
        for index, resource in enumerate(values):
            label = phase + '-' + str(index).zfill(2)
            # The run marker makes logical operation identities distinct across
            # reruns, while an exact replay retains the original operation ID.
            operation = 'qlf-' + sha256(canonical([family, resources['protected_run'], label]))[:48]
            value = {'operator_namespace': namespace, 'operation_id': operation,
                     'recipe_digest': recipe_digest}
            if reference is stripe_platform:
                require(resource['amount_received'] == 2000, 'qualification.packets.payment-bound')
                value.update(payment_intent=resource['id'], amount=500, currency='usd')
            else:
                value.update(record_id=resource['id'], replacement='Approved' if phase == 'commissioning' else 'Pending')
            # This checks the full resource/action request contract before the
            # author can turn these inputs into signed action bytes.
            reference.request(value, resources, '0' * 64, recipe_digest)
            packets.append({'label': label, 'context': 'initial', 'arguments': value})
            if index == 0:
                # Same logical operation and exact arguments, under the other
                # predeclared challenge. It is replay evidence, never a second
                # planned write or caller-selected authoring authority.
                packets.append({'label': label + '-fresh', 'context': 'fresh', 'arguments': dict(value)})
        if reference is stripe_platform:
            for kind, changed in [('ceiling', {'amount': 1001}), ('currency', {'currency': 'eur'})]:
                label = phase + '-guard-' + kind
                probe = dict(value, **changed)
                probe['operation_id'] = 'qlf-' + sha256(canonical([family, resources['protected_run'], label]))[:48]
                # These valid native actions are deliberately outside the
                # provider's relative guard, so the corpus can measure its
                # real post-lease refusal rather than a permit refusal.
                reference.request(probe, resources, '0' * 64, recipe_digest)
                require(reference.entry_policy(probe, resources) is not None,
                        'qualification.packets.probe-binding')
                packets.append({'label': label, 'context': 'initial', 'arguments': probe})
    return packets


def public_pool(family, resources, recipe_digest, carrier):
    """Reconstruct the entire source-owned pool before signing any authority.

    This checks the original carrier, not a one-packet refresh. Native review
    still authenticates each proof and both distinct context byte strings.
    """
    closed(carrier, ['schema', 'protected_run', 'evaluated_at', 'not_after',
                     'trusted_contexts', 'packets'])
    require(carrier['schema'] == 'auths.qualification-public-packets/3'
            and carrier['protected_run'] == resources['protected_run']
            and carrier['trusted_contexts'] == ['context-0.cbor', 'context-1.cbor'],
            'qualification.packets.pool-binding')
    planned = arguments(family, resources, recipe_digest)
    expected = [{'label': packet['label'], 'proof': packet['label'] + '.proof',
                 'action': packet['label'] + '.action',
                 'trusted_context': 'context-' + str(['initial', 'fresh'].index(packet['context'])) + '.cbor',
                 'arguments': packet['arguments']} for packet in planned]
    require(4 <= len(expected) <= 64 and carrier['packets'] == expected,
            'qualification.packets.pool-binding')
    return expected


def validate(plan):
    closed(plan, ['schema', 'family', 'protected_run', 'evaluated_at', 'not_after',
                  'configuration', 'extension', 'resources', 'packets'])
    require(plan['schema'] == 'auths.qualification-packet-plan/3'
            and type(plan['family']) is str and plan['family'] in REFERENCES,
            'qualification.packets.schema')
    run_id(plan['protected_run'])
    require(type(plan['evaluated_at']) is int and 60 <= plan['evaluated_at'] <= 253402293599
            and type(plan['not_after']) is int
            and plan['not_after'] == plan['evaluated_at'] + PACKET_VALIDITY,
            'qualification.packets.time-bound')
    digest(plan['configuration'])
    packets = plan['packets']
    require(type(packets) is list and 4 <= len(packets) <= 64,
            'qualification.packets.packet-bound')
    labels, operations = set(), set()
    for packet in packets:
        closed(packet, ['label', 'context', 'arguments'])
        require(type(packet['label']) is str and packet['label'] not in labels
                and packet['label'] in ({phase + '-' + str(index).zfill(2) + suffix
                                       for phase in ['commissioning', 'live'] for index in range(32)
                                       for suffix in (['', '-fresh'] if index == 0 else [''])}
                    | ({phase + '-guard-' + kind for phase in ['commissioning', 'live']
                        for kind in ['ceiling', 'currency']} if plan['family'] == stripe_platform.FAMILY else set()))
                and packet['context'] == ('fresh' if packet['label'].endswith('-fresh') else 'initial'),
                'qualification.packets.packet-bound')
        labels.add(packet['label'])
        value = packet['arguments']
        fields = ['operator_namespace', 'operation_id', 'recipe_digest']
        fields += ['payment_intent', 'amount', 'currency'] if plan['family'] == stripe_platform.FAMILY else ['record_id', 'replacement']
        closed(value, fields)
        operation = 'qlf-' + sha256(canonical([plan['family'], plan['protected_run'],
                                             packet['label'].removesuffix('-fresh')]))[:48]
        require(value['operation_id'] == operation
                and (operation, packet['context']) not in operations,
                'qualification.packets.operation-binding')
        digest(value['recipe_digest'])
        operations.add((operation, packet['context']))
    require(len({packet['arguments']['recipe_digest'] for packet in packets}) == 1,
            'qualification.packets.recipe-binding')
    require(packets == arguments(plan['family'], plan['resources'], packets[0]['arguments']['recipe_digest'])
            and plan['resources']['protected_run'] == plan['protected_run'],
            'qualification.packets.resource-binding')
    extension = plan['extension']
    if plan['family'] == stripe_platform.FAMILY:
        closed(extension, ['extension_id', 'extension_body_hex'])
        require(extension['extension_id'] == 'bounded-policy-commitment-v1'
                and type(extension['extension_body_hex']) is str
                and 0 < len(extension['extension_body_hex']) <= 8192
                and len(extension['extension_body_hex']) % 2 == 0
                and all(character in '0123456789abcdef' for character in extension['extension_body_hex']),
                'qualification.packets.extension-bound')
    else:
        require(extension is None, 'qualification.packets.extension-bound')
    return plan


def prepare(args):
    reference = REFERENCES.get(args.family)
    require(reference is not None, 'qualification.packets.family')
    resources = decode(read(args.resources, 65536))
    reference.resources(resources, run_id(resources['protected_run']))
    source = SOURCES[args.family]
    recipe = reference.recipe(decode(read(source / 'recipe.json', 65536)), resources)
    # The private output directory must already exist. No private author key
    # or credential is ever created here, and existing outputs are refused.
    write(args.work / 'recipe.json', recipe, new=True)
    lock = read(source / 'profile.lock.json', 65536)
    write_bytes(args.work / 'profile.lock.json', lock, new=True)
    review = child(args.gateway, ['review', '--recipe', args.work / 'recipe.json',
                                 '--profile-lock', args.work / 'profile.lock.json'])
    require(review.get('schema') == 'auths.gateway-recipe-review/2', 'qualification.packets.native-review')
    extension = None
    if reference is stripe_platform:
        derived = child(args.gateway, ['bound-extension', '--argument', 'amount', '--ceiling', '10000',
            '--window-seconds', '86400', '--max-count', '64', '--sum-limit', '32000', '--partition', 'currency=usd,eur',
            '--scope', 'payment_intent=' + ','.join(payment['id'] for payment in resources['payments'])])
        extension = {name: derived[name] for name in ['extension_id', 'extension_body_hex']}
    evaluated_at = int(time.time())
    plan = validate({'schema': 'auths.qualification-packet-plan/3', 'family': args.family,
        'protected_run': resources['protected_run'], 'evaluated_at': evaluated_at,
        'not_after': evaluated_at + PACKET_VALIDITY, 'configuration': review['verifier_configuration'],
        'extension': extension, 'resources': resources,
        'packets': arguments(args.family, resources, review['recipe_digest'])})
    write(args.work / 'packet-plan.json', plan, new=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family', choices=sorted(REFERENCES), required=True)
    for name in ['resources', 'gateway', 'work']:
        parser.add_argument('--' + name, type=lambda value: Path(value).absolute(), required=True)
    args = parser.parse_args()
    finish(lambda: prepare(args))


if __name__ == '__main__':
    main()
