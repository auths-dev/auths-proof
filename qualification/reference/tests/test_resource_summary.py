"""Native record resource projection keeps exact, owned provider identities."""

import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import airtable_record as airtable
import stripe_platform as stripe
from resource_summary import summary
from common import Refusal

RUN = 'recipe-qualification/123/1'


class Summary(unittest.TestCase):
    def stripe(self):
        return {'schema': 'auths.stripe-platform-qualification-resources/1',
                'protected_run': RUN, 'platform': 'acct_SYNTHETIC', 'payments': [
                    {'id': 'pi_SYNTHETIC', 'amount_received': 2000, 'currency': 'usd',
                     'livemode': False, 'run_metadata': RUN}]}

    def airtable(self):
        return {'schema': 'auths.airtable-record-qualification-resources/1',
                'protected_run': RUN, 'base': airtable.BASE, 'table': airtable.TABLE,
                'records': [{'id': 'recSYNTHETIC00001', 'run_metadata': RUN}]}

    def test_exact_provider_names_are_sorted_native_bounded_strings(self):
        self.assertEqual(summary(stripe.FAMILY, self.stripe()),
                         ['stripe:test-payment:pi_SYNTHETIC', 'stripe:test-platform:acct_SYNTHETIC'])
        table = airtable.BASE + '/' + airtable.TABLE
        self.assertEqual(summary(airtable.FAMILY, self.airtable()), sorted([
            'airtable:base:' + airtable.BASE, 'airtable:table:' + table,
            'airtable:record:' + table + '/recSYNTHETIC00001']))

    def test_foreign_run_duplicate_live_and_open_ledger_cannot_be_summarized(self):
        changes = [lambda v: v['payments'][0].update(run_metadata='recipe-qualification/999/1'),
                   lambda v: v['payments'].append(copy.deepcopy(v['payments'][0])),
                   lambda v: v['payments'][0].update(livemode=True),
                   lambda v: v.update(provider_resources=['unreviewed']),
                   lambda v: v.update(protected_run='../../another-run')]
        for change in changes:
            value = self.stripe()
            change(value)
            with self.assertRaises(Refusal): summary(stripe.FAMILY, value)
        with self.assertRaises(Refusal): summary(airtable.FAMILY, self.stripe())
        with self.assertRaises(Refusal): summary('unknown-family', self.stripe())
        with self.assertRaises(Refusal): summary(stripe.FAMILY, ['unreviewed'])

    def test_oversized_native_name_is_refused_without_truncation(self):
        value = self.stripe()
        value['payments'][0]['id'] = 'pi_' + 'A' * 128
        with self.assertRaises(Refusal): summary(stripe.FAMILY, value)

    def test_record_bound_includes_platform_base_and_table_names(self):
        value = self.stripe()
        value['payments'] = [dict(value['payments'][0], id='pi_SYNTHETIC' + str(i)) for i in range(31)]
        self.assertEqual(len(summary(stripe.FAMILY, value)), 32)
        value['payments'].append(dict(value['payments'][0], id='pi_SYNTHETIC31'))
        with self.assertRaises(Refusal): summary(stripe.FAMILY, value)
        value = self.airtable()
        value['records'] = [{'id': 'recSYNTHETIC' + str(i).zfill(5), 'run_metadata': RUN} for i in range(30)]
        self.assertEqual(len(summary(airtable.FAMILY, value)), 32)
        value['records'].append({'id': 'recSYNTHETIC00030', 'run_metadata': RUN})
        with self.assertRaises(Refusal): summary(airtable.FAMILY, value)


if __name__ == '__main__':
    unittest.main()
