"""Test-only AP074 comparisons against unchanged independent domain references.

The native generator verifies real signed proofs and exact approvals. This
runner compares its closed outputs with the retained references; it cannot
authorize an operation, obtain a credential, or issue a managed receipt.
"""

import argparse
import hashlib
import json
from pathlib import Path

import airtable_record as airtable
import fresh_evidence
from common import Refusal, canonical, require, sha256
from provider_readback import ReadBack
import stripe_platform as stripe


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'bindings/fixtures/gateway'
NATIVE = FIXTURES / 'native-independent-mutation-differential.json'
REPORT = FIXTURES / 'independent-mutation-differential-report.json'
REFERENCES = {airtable.FAMILY: airtable, stripe.FAMILY: stripe}


def request_cases(family):
    cases = {name: 'both-refuse' for name in [
        'wrong-namespace', 'wrong-recipe', 'extra-field', 'empty-operation',
        'long-operation', 'missing-operation',
    ]}
    cases.update({'baseline': 'equal-request', 'other-operation': 'equal-request',
                  'unowned-resource': 'reference-pool-refuses'})
    if family == airtable.FAMILY:
        cases.update({'other-value': 'equal-request', 'invalid-value': 'both-refuse',
                      'wrong-value-type': 'both-refuse'})
    else:
        cases.update({name: 'equal-request' for name in [
            'minimum-amount', 'maximum-amount', 'other-currency',
        ]})
        cases.update({name: 'both-refuse' for name in [
            'zero-amount', 'negative-amount', 'boolean-amount', 'over-grant-ceiling',
        ]})
    return cases


def indexed(rows, names):
    require(type(rows) is list and len(rows) == len(names),
            'ap074.differential.case-count')
    result = {row['name']: row for row in rows}
    require(len(result) == len(rows) and set(result) == set(names),
            'ap074.differential.case-inventory')
    return result


def reference_request(reference, row, resources, recipe_digest):
    try:
        result = reference.request(row['arguments'], resources,
            row.get('action_commitment', '0' * 64), recipe_digest)
        return result, None
    except Refusal as error:
        return None, str(error)


def compare_requests(family):
    reference = REFERENCES[family['family']]
    resources = reference.resources(family['resources'], 'ap074-independent-differential')
    expected = request_cases(family['family'])
    rows = indexed(family['cases'], expected)
    compared = []
    for name, contract in expected.items():
        row = rows[name]
        require(row['contract'] == contract
                and row['native_accepted'] is (contract != 'both-refuse'),
                'ap074.differential.native-request-decision')
        result, code = reference_request(reference, row, resources, family['recipe_digest'])
        if contract == 'equal-request':
            # Includes exact bytes, URL, ordered headers, echo and idempotency.
            require(result == row['request'], 'ap074.differential.closed-request')
        else:
            require(result is None, 'ap074.differential.reference-refusal')
        compared.append({'name': name, 'contract': contract,
                         'native_accepted': row['native_accepted'],
                         'reference_accepted': result is not None, 'reference_code': code})
    if reference is stripe:
        # Encoding a closed request does not satisfy the separately fenced,
        # fresh provider-read guard. Retain that distinction in the report.
        guards = {name: stripe.entry_policy(rows[name]['arguments'], resources)
                  for name in ['baseline', 'maximum-amount', 'other-currency']}
        require(guards == {'baseline': None,
            'maximum-amount': 'gateway.relative-ceiling.above',
            'other-currency': 'gateway.relative-ceiling.binding-mismatch'},
            'ap074.differential.reference-guard')
    else:
        guards = None
    return rows['baseline'], compared, guards


def compare_observations(family, baseline):
    reference = REFERENCES[family['family']]
    expected = {'exact': ('echo-linked', True),
        'wrong-value': ('state-mismatch', False),
        'wrong-echo': ('echo-mismatch', False),
        'null-echo': ('state-match', False),
        'different-resource': ('echo-linked', False),
        'duplicate-member': ('unavailable', False),
        'malformed': ('unavailable', False),
        'nonfinite': ('unavailable', False),
        'at-limit': ('echo-linked', True),
        'over-limit': ('unavailable', True),
        'over-reference-limit': ('unavailable', False)}
    if reference is stripe:
        # A refund is discovered by action-bound echo, rather than a caller's
        # claimed refund ID. Another safe refund ID alone is not a mismatch.
        expected['different-resource'] = ('echo-linked', True)
        expected.update({name: ('echo-linked', False) for name in [
            'pending-refund', 'other-payment', 'other-currency', 'live-refund',
        ]})
    rows = indexed(family['observations'], expected)
    compared = []
    for name, (native, accepted) in expected.items():
        row = rows[name]
        require(row['native'] == native, 'ap074.differential.native-response')
        padding = row['trailing_space_bytes']
        require(type(padding) is int and 0 <= padding <= 65537
                and row['native_maximum_response_bytes'] == 16384,
                'ap074.differential.response-padding-bound')
        raw = row['response'].encode() + b' ' * padding
        if name in ['at-limit', 'over-limit', 'over-reference-limit']:
            length = {'at-limit': 16384, 'over-limit': 16385, 'over-reference-limit': 65537}[name]
            require(len(raw) == length and json.loads(raw) == json.loads(rows['exact']['response']),
                    'ap074.differential.valid-json-byte-boundary')
        try:
            witness = fresh_evidence.witness(family['family'], baseline['arguments'],
                family['resources'], baseline['action_commitment'], family['recipe_digest'],
                raw)
            actual, code = True, None
            require(witness['response_sha256'] == sha256(raw),
                    'ap074.differential.reference-response-digest')
        except Refusal as error:
            actual, code = False, str(error)
        require(actual is accepted, 'ap074.differential.reference-response')
        compared.append({'name': name, 'native': native, 'response_bytes': len(raw),
                         'native_maximum_response_bytes': row['native_maximum_response_bytes'],
                         'reference_complete_domain_witness': actual, 'reference_code': code})
    return rows['exact']['response'].encode(), compared


def compare_recovery(family, baseline, response):
    reference = REFERENCES[family['family']]
    calls = []

    def exchange(origin, method, path, key, *, headers):
        require(method == 'GET' and key == 'public-test-only-no-credential',
                'ap074.differential.reference-read-only')
        expected_origin = 'https://api.stripe.com' if reference is stripe else 'https://api.airtable.com'
        expected_headers = {'Stripe-Version': '2025-03-31.basil'} if reference is stripe else {}
        require(origin == expected_origin and headers == expected_headers,
                'ap074.differential.reference-read-binding')
        calls.append(path)
        if reference is stripe and len(calls) == 1:
            require(path == '/v1/refunds?payment_intent=pi_TEST123&limit=100',
                    'ap074.differential.reference-discovery-binding')
            return 200, canonical({'data': [json.loads(response)], 'has_more': False})
        return 200, response

    reviewed = {'schema': 'auths.gateway-submission-review/1', 'actors': [],
                'action_commitment': baseline['action_commitment'],
                'arguments': baseline['arguments'], 'request': baseline['request']}
    result = ReadBack(family['family'], family['resources'],
        'public-test-only-no-credential', exchange=exchange).fresh(reviewed, family['recipe_digest'])
    require(result == response, 'ap074.differential.reference-read-bytes')
    recovery = family['recovery']
    locator = 'response' if reference is stripe else 'verified'
    require(recovery['capability'] == {
        'class': 'linked-after-response' if reference is stripe else 'linked',
        'state_locator': locator, 'provider_link': locator,
        'unknown_reobservation': reference is airtable,
        'declared_idempotency_retention_seconds': 86400 if reference is stripe else None,
        'pre_entry_reread': False, 'write_is_conditional': False,
    }, 'ap074.differential.recovery-capability')
    final_url = ('https://api.stripe.com' if reference is stripe else 'https://api.airtable.com') + calls[-1]
    require(final_url == recovery['with_write_response_url'],
            'ap074.differential.closed-observation-url')
    if reference is airtable:
        require(len(calls) == 1 and recovery['without_write_response_url'] == final_url,
                'ap074.differential.verified-locator')
        contract = 'same known record can be read without a write response'
    else:
        require(len(calls) == 2 and recovery['without_write_response_url'] is None
                and recovery['dot_segment_response_locator_refused'] is True
                and recovery['separator_response_locator_url'] == 'https://api.stripe.com/v1/refunds/..%2Fother',
                'ap074.differential.response-locator')
        contract = ('native needs its recorded response locator; independent reference discovers '
                    'one refund from an action-bound bounded listing; discovery is not a native recovery permit')
    return {'contract': contract, 'reference_read_paths': calls,
            'native_capability': recovery['capability'],
            'native_without_response_target': recovery['without_write_response_url'],
            'native_with_response_target': recovery['with_write_response_url']}


def compare(corpus):
    require(corpus['schema'] == 'auths.ap074-native-mutation-differential/1'
            and len(corpus['families']) == 2,
            'ap074.differential.native-schema')
    require({family['family'] for family in corpus['families']} == set(REFERENCES),
            'ap074.differential.family-inventory')
    families = []
    for family in corpus['families']:
        baseline, requests, guards = compare_requests(family)
        response, observations = compare_observations(family, baseline)
        recovery = compare_recovery(family, baseline, response)
        families.append({'family': family['family'], 'requests': requests,
                         'observations': observations, 'independent_entry_guards': guards,
                         'recovery': recovery})
    return families


def generate(native_path=NATIVE):
    raw = native_path.read_bytes()
    require(0 < len(raw) <= 2 * 1024 * 1024, 'ap074.differential.corpus-bound')
    sources = ['qualification/reference/' + name for name in [
        'airtable_record.py', 'stripe_platform.py', 'fresh_evidence.py', 'provider_readback.py',
        'common.py', 'ap074_differential.py',
    ]]
    sources.append('product/runtime/auths-gateway/src/native_differential_tests.rs')
    return {'schema': 'auths.ap074-independent-mutation-differential/1',
            'scope': 'test-only native verified compilation and response classification compared with retained independent references; no admission, provider I/O, production qualification or AP070 guarantee',
            'native_corpus_sha256': hashlib.sha256(raw).hexdigest(),
            'source_sha256': {name: sha256((ROOT / name).read_bytes()) for name in sources},
            'families': compare(json.loads(raw))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--update', action='store_true', help='construct the retained comparison artifact')
    parser.add_argument('--output', type=Path, help='also retain this execution report as a CI artifact')
    args = parser.parse_args()
    report = generate()
    encoded = json.dumps(report, indent=2, sort_keys=True).encode() + b'\n'
    if args.update:
        REPORT.write_bytes(encoded)
    require(REPORT.read_bytes() == encoded, 'ap074.differential.retained-report-drift')
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(encoded)
    print(json.dumps({'schema': report['schema'], 'families': len(report['families']),
                      'request_cases': sum(len(f['requests']) for f in report['families']),
                      'response_cases': sum(len(f['observations']) for f in report['families'])}))


if __name__ == '__main__':
    main()
