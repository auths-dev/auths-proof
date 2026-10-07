"""Fresh provider reads selected by authenticated actions and the owned pool.

No candidate response locator, digest or claimed outcome chooses a read. Only
this source-owned reference holds the operator's read credential. Returned raw
bytes remain private; the independent witness publishes their digest only.
"""

import urllib.parse

import airtable_record
import stripe_platform
from common import closed, echo, identifier, require
from fresh_evidence import decode, witness
import resource_io


class ReadBack:
    def __init__(self, family, resources, key, *, exchange=None):
        self.family, self.resources, self.key = family, resources, key
        self.exchange = exchange or resource_io.exchange
        reference = {stripe_platform.FAMILY: stripe_platform, airtable_record.FAMILY: airtable_record}.get(family)
        require(reference is not None, 'qualification.readback.family')
        reference.resources(resources, resources['protected_run'])
        self.reference = reference

    def get(self, path):
        stripe = self.reference is stripe_platform
        status, raw = self.exchange('https://api.stripe.com' if stripe else 'https://api.airtable.com',
            'GET', path, self.key, headers={'Stripe-Version': '2025-03-31.basil'} if stripe else {})
        require(status == 200 and type(raw) is bytes and 0 < len(raw) <= 65536,
                'qualification.readback.provider-unavailable')
        return raw

    def fresh(self, reviewed, recipe_digest):
        closed(reviewed, ['schema', 'actors', 'action_commitment', 'arguments', 'request'])
        arguments = reviewed['arguments']
        require(reviewed['schema'] == 'auths.gateway-submission-review/1'
                and reviewed['request'] == self.reference.request(arguments, self.resources,
                    reviewed['action_commitment'], recipe_digest), 'qualification.readback.review-binding')
        if self.reference is airtable_record:
            path = '/v0/' + airtable_record.BASE + '/' + airtable_record.TABLE + '/' + arguments['record_id']
        else:
            # Discover the refund by its action-derived echo in the exact
            # reviewed payment, rather than borrowing the candidate's locator.
            path = '/v1/refunds?' + urllib.parse.urlencode({'payment_intent': arguments['payment_intent'], 'limit': 100})
            value = decode(self.get(path))
            require(type(value.get('data')) is list and len(value['data']) <= 100
                    and value.get('has_more') is False, 'qualification.readback.refund-bound')
            token = echo(arguments['operator_namespace'], arguments['operation_id'], reviewed['action_commitment'])
            matches = [item for item in value['data'] if type(item) is dict
                and type(item.get('metadata')) is dict and item['metadata'].get('auths_echo') == token]
            require(len(matches) == 1, 'qualification.readback.ambiguous-refund')
            refund = identifier(matches[0].get('id'), r're_[A-Za-z0-9]{1,128}')
            require(matches[0].get('payment_intent') == arguments['payment_intent'],
                    'qualification.readback.payment-binding')
            path = '/v1/refunds/' + refund
        raw = self.get(path)
        witness(self.family, arguments, self.resources, reviewed['action_commitment'], recipe_digest, raw)
        return raw
