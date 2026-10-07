"""Independent bounded response checks for the two reviewed provider families.

This module performs no I/O and accepts no candidate result/digest/locator.
The protected reference harness supplies bytes from its own fresh read of a
resource selected from the reviewed run ledger and action, then the runner
compares the witness with the candidate separately.
"""

import json
from common import canonical, digest, echo, identifier, require, sha256
import airtable_record as airtable
import stripe_platform as stripe


def decode(response):
    require(type(response) is bytes and 0 < len(response) <= 65536,
            'qualification.fresh.response-bound')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'qualification.fresh.duplicate-member')
            result[key] = value
        return result
    def invalid(_value):
        require(False, 'qualification.fresh.invalid-json')
    try:
        value = json.loads(response, object_pairs_hook=unique, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError):
        require(False, 'qualification.fresh.invalid-json')
    require(type(value) is dict, 'qualification.fresh.invalid-json')
    return value


def subject(family, arguments, resources, action_commitment, recipe_digest):
    reference = {'stripe-platform-refund-v1': stripe,
                 'airtable-record-update-v1': airtable}.get(family)
    require(reference is not None, 'qualification.fresh.family')
    # Re-run the complete independent request oracle; invalid actions cannot
    # acquire a subject merely by hashing arbitrary input.
    require(type(resources) is dict, 'qualification.fresh.resources')
    reference.resources(resources, resources.get('protected_run'))
    request = reference.request(arguments, resources, action_commitment, recipe_digest)
    return sha256(b'auths.qualification-read-back-subject/1\0' + canonical({
        'family': family, 'arguments': arguments, 'request': request,
        'resources_sha256': sha256(canonical(resources)),
        'action_commitment': digest(action_commitment),
        'recipe_digest': digest(recipe_digest),
    }))


def witness(family, arguments, resources, action_commitment, recipe_digest, response):
    expected_subject = subject(family, arguments, resources, action_commitment, recipe_digest)
    value = decode(response)
    token = echo(arguments['operator_namespace'], arguments['operation_id'], action_commitment)
    if family == stripe.FAMILY:
        identifier(value.get('id'), r're_[A-Za-z0-9]{1,128}')
        require(value.get('object') == 'refund' and value.get('livemode', False) is False
                and value.get('payment_intent') == arguments['payment_intent']
                and type(value.get('amount')) is int and value['amount'] == arguments['amount']
                and value.get('currency') == arguments['currency']
                and value.get('status') == 'succeeded'
                and type(value.get('metadata')) is dict
                and value['metadata'].get('auths_echo') == token,
                'qualification.fresh.state-mismatch')
    else:
        require(value.get('id') == arguments['record_id']
                and type(value.get('fields')) is dict
                and value['fields'].get('DemoStatus') == arguments['replacement']
                and value['fields'].get('auths_echo') == token,
                'qualification.fresh.state-mismatch')
    return {'kind': 'independent-read-back', 'subject_sha256': expected_subject,
            'response_sha256': sha256(response)}
