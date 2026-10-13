"""Independent selection and raw-byte boundaries using synthetic providers."""

import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import airtable_record as airtable
import stripe_platform as stripe
from common import canonical, echo, Refusal
from provider_readback import ReadBack


class ProviderReads(unittest.TestCase):
    def setUp(self):
        self.digest, self.commitment = '1' * 64, '2' * 64
        self.run = 'recipe-qualification/123/1'
        self.resources = {'schema': 'auths.stripe-platform-qualification-resources/1',
            'protected_run': self.run, 'platform': 'acct_SYNTHETIC', 'payments': [
                {'id': 'pi_SYNTHETIC', 'amount_received': 2000, 'currency': 'usd',
                 'livemode': False, 'run_metadata': self.run}]}
        arguments = {'operator_namespace': stripe.SERVICE, 'operation_id': 'synthetic-only-operation',
            'recipe_digest': self.digest, 'payment_intent': 'pi_SYNTHETIC', 'amount': 500, 'currency': 'usd'}
        self.review = {'schema': 'auths.gateway-submission-review/1', 'actors': ['raw:synthetic-only-actor'],
            'action_commitment': self.commitment, 'arguments': arguments,
            'request': stripe.request(arguments, self.resources, self.commitment, self.digest)}
        self.refund = {'id': 're_SYNTHETIC', 'object': 'refund', 'livemode': False,
            'payment_intent': 'pi_SYNTHETIC', 'amount': 500, 'currency': 'usd', 'status': 'succeeded',
            'metadata': {'auths_echo': echo(stripe.SERVICE, arguments['operation_id'], self.commitment)}}

    def test_refund_locator_is_discovered_independently_and_raw_read_bytes_are_retained(self):
        calls, raw = [], json.dumps(self.refund, indent=2).encode()
        def exchange(origin, method, path, key, **kwargs):
            calls.append((origin, method, path))
            if '?' in path:
                return 200, canonical({'data': [dict(self.refund, id='re_OTHER', metadata={}), self.refund], 'has_more': False})
            return 200, raw
        reader = ReadBack(stripe.FAMILY, self.resources, 'synthetic-only-key', exchange=exchange)
        self.assertEqual(reader.fresh(self.review, self.digest), raw)
        self.assertEqual(calls, [('https://api.stripe.com', 'GET', '/v1/refunds?payment_intent=pi_SYNTHETIC&limit=100'),
                                 ('https://api.stripe.com', 'GET', '/v1/refunds/re_SYNTHETIC')])

    def test_ambiguous_paginated_wrong_payment_and_changed_fresh_state_refuse(self):
        for problem in ['duplicate', 'pagination', 'wrong-payment', 'changed-fresh', 'status']:
            listing = {'data': [copy.deepcopy(self.refund)], 'has_more': False}
            fresh = copy.deepcopy(self.refund)
            if problem == 'duplicate': listing['data'].append(copy.deepcopy(self.refund))
            if problem == 'pagination': listing['has_more'] = True
            if problem == 'wrong-payment': listing['data'][0]['payment_intent'] = 'pi_OTHER'
            if problem == 'changed-fresh': fresh['metadata']['auths_echo'] = 'changed'
            def exchange(origin, method, path, key, **kwargs):
                return (403 if problem == 'status' else 200), canonical(listing if '?' in path else fresh)
            with self.subTest(problem=problem), self.assertRaises(Refusal):
                ReadBack(stripe.FAMILY, self.resources, 'synthetic-only-key', exchange=exchange).fresh(self.review, self.digest)

    def test_airtable_reads_only_the_exact_owned_record_and_never_an_off_pool_record(self):
        resources = {'schema': 'auths.airtable-record-qualification-resources/1', 'protected_run': self.run,
            'base': airtable.BASE, 'table': airtable.TABLE,
            'records': [{'id': 'recTEST0000000001', 'run_metadata': self.run}]}
        arguments = {'operator_namespace': 'airtable-demo', 'operation_id': 'synthetic-only-operation',
            'recipe_digest': self.digest, 'record_id': 'recTEST0000000001', 'replacement': 'Approved'}
        reviewed = dict(self.review, arguments=arguments,
            request=airtable.request(arguments, resources, self.commitment, self.digest))
        raw = canonical({'id': arguments['record_id'], 'fields': {'DemoStatus': 'Approved',
            'auths_echo': echo('airtable-demo', arguments['operation_id'], self.commitment)}})
        calls = []
        def exchange(origin, method, path, key, **kwargs):
            calls.append(path)
            return 200, raw
        reader = ReadBack(airtable.FAMILY, resources, 'synthetic-only-key', exchange=exchange)
        self.assertEqual(reader.fresh(reviewed, self.digest), raw)
        self.assertEqual(calls, ['/v0/' + airtable.BASE + '/' + airtable.TABLE + '/' + arguments['record_id']])
        changed = copy.deepcopy(reviewed)
        changed['arguments']['record_id'] = 'recOTHER000000001'
        with self.assertRaises(Refusal): reader.fresh(changed, self.digest)
        self.assertEqual(len(calls), 1)


if __name__ == '__main__':
    unittest.main()
