"""Independent platform-refund reference. Never imported by shipping code."""

import urllib.parse

from common import closed, digest, echo, idempotency, identifier, integer, require, text

FAMILY = 'stripe-platform-refund-v1'
SERVICE = 'stripe-platform-refunds'
TOOL = 'create_refund_v1'
ENVIRONMENT = 'provider-test-mode'


def resources(value, protected_run):
    closed(value, ['schema', 'protected_run', 'platform', 'payments'])
    require(value['schema'] == 'auths.stripe-platform-qualification-resources/1'
            and value['protected_run'] == protected_run,
            'qualification.reference.resource-binding')
    identifier(value['platform'], r'acct_[A-Za-z0-9]{1,64}')
    payments = value['payments']
    require(type(payments) is list and 1 <= len(payments) <= 32,
            'qualification.reference.resource-bound')
    seen = set()
    for payment in payments:
        closed(payment, ['id', 'amount_received', 'currency', 'livemode', 'run_metadata'])
        payment_id = identifier(payment['id'], r'pi_[A-Za-z0-9]{1,128}')
        require(payment_id not in seen and payment['livemode'] is False
                and payment['currency'] == 'usd' and payment['run_metadata'] == protected_run,
                'qualification.reference.resource-binding')
        integer(payment['amount_received'], 1, 99999999)
        seen.add(payment_id)
    return value


def request(arguments, bound_resources, action_commitment, recipe_digest):
    closed(arguments, ['operator_namespace', 'operation_id', 'recipe_digest',
                       'payment_intent', 'amount', 'currency'])
    require(arguments['operator_namespace'] == SERVICE
            and digest(arguments['recipe_digest']) == digest(recipe_digest),
            'qualification.reference.recipe-binding')
    operation = text(arguments['operation_id'], maximum=128)
    amount = integer(arguments['amount'], 1, 99999999)
    require(arguments['currency'] == 'usd', 'qualification.reference.currency-binding')
    payment = next((item for item in bound_resources['payments']
                    if item['id'] == arguments['payment_intent']), None)
    require(payment is not None, 'qualification.reference.resource-binding')
    # Only bounded actions that the reviewed live run may actually execute
    # enter a permit. Rejected boundary vectors stay in the offline corpus.
    require(amount <= 10000 and amount * 10000 <= payment['amount_received'] * 5000,
            'qualification.reference.ceiling')
    token = echo(SERVICE, operation, action_commitment)
    key = idempotency(SERVICE, operation)
    body = urllib.parse.urlencode([
        ('amount', str(amount)), ('metadata[auths_echo]', token),
        ('payment_intent', payment['id']),
    ])
    return {
        'method': 'POST', 'url': 'https://api.stripe.com/v1/refunds',
        'content_type': 'application/x-www-form-urlencoded', 'body': body,
        'headers': [['Stripe-Version', '2025-03-31.basil'], ['Idempotency-Key', key]],
        'idempotency_key': key,
    }


def recipe(template, bound_resources):
    # No resource or platform header is substituted into this family.
    require(template['service'] == SERVICE and template['tool'] == TOOL
            and template['origin'] == 'https://api.stripe.com'
            and 'account_scope' not in template,
            'qualification.reference.recipe-binding')
    return template
