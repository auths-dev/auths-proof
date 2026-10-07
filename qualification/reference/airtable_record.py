"""Independent Airtable field-update reference, confined to release tooling."""

import copy
import urllib.parse

from common import canonical, closed, digest, echo, identifier, require, text

FAMILY = 'airtable-record-update-v1'
SERVICE = 'airtable-gateway-demo'
TOOL = 'set_demo_status_v1'
ENVIRONMENT = 'disposable-live-resources'

# The owner-authorized dedicated field-lab table. A different fixed base/table
# changes the recipe digest and requires an explicit reference review.
BASE = 'appQD3Qf0YFBCW9bV'
TABLE = 'tblBx2jwe0IsPYRKT'


def resources(value, protected_run):
    closed(value, ['schema', 'protected_run', 'base', 'table', 'records'])
    require(value['schema'] == 'auths.airtable-record-qualification-resources/1'
            and value['protected_run'] == protected_run
            and value['base'] == BASE and value['table'] == TABLE,
            'qualification.reference.resource-binding')
    require(type(value['records']) is list and 1 <= len(value['records']) <= 32,
            'qualification.reference.resource-bound')
    seen = set()
    for record in value['records']:
        closed(record, ['id', 'run_metadata'])
        record_id = identifier(record['id'], r'rec[A-Za-z0-9]{14}')
        require(record_id not in seen and record['run_metadata'] == protected_run,
                'qualification.reference.resource-binding')
        seen.add(record_id)
    return value


def request(arguments, bound_resources, action_commitment, recipe_digest):
    closed(arguments, ['operator_namespace', 'operation_id', 'recipe_digest',
                       'record_id', 'replacement'])
    require(arguments['operator_namespace'] == 'airtable-demo'
            and digest(arguments['recipe_digest']) == digest(recipe_digest),
            'qualification.reference.recipe-binding')
    operation = text(arguments['operation_id'], maximum=128)
    require(any(record['id'] == arguments['record_id'] for record in bound_resources['records']),
            'qualification.reference.resource-binding')
    require(arguments['replacement'] in ['Approved', 'Pending'],
            'qualification.reference.replacement')
    token = echo('airtable-demo', operation, action_commitment)
    path = '/'.join(urllib.parse.quote(segment, safe='') for segment in
                    ['v0', BASE, TABLE, arguments['record_id']])
    return {
        'method': 'PATCH', 'url': 'https://api.airtable.com/' + path,
        'content_type': 'application/json',
        'body': canonical({'fields': {'DemoStatus': arguments['replacement'],
                                     'auths_echo': token}}).decode(),
        'headers': [], 'idempotency_key': None,
    }


def recipe(template, bound_resources):
    require(template['service'] == SERVICE and template['tool'] == TOOL
            and template['origin'] == 'https://api.airtable.com',
            'qualification.reference.recipe-binding')
    result = copy.deepcopy(template)
    expected = [
        {'kind': 'fixed', 'value': 'v0'},
        {'kind': 'fixed', 'value': 'appTEST0000000001'},
        {'kind': 'fixed', 'value': 'tblTEST0000000001'},
        {'kind': 'field', 'name': 'record_id'},
    ]
    for path in [result['write']['path'], result['observation']['path']]:
        require(path == expected, 'qualification.reference.recipe-binding')
        path[1]['value'] = bound_resources['base']
        path[2]['value'] = bound_resources['table']
    return result
