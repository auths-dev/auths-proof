"""Mutation controls for the AP075 census; these are not product-security evidence."""
import copy
import json
from pathlib import Path
import unittest

from validate import validate


class CensusControls(unittest.TestCase):
    def setUp(self):
        self.inventory = json.loads(Path(__file__).with_name('inventory.json').read_text())
        self.head = 'assessment-target'
        self.boundary = {'schema': 'auths.security-assessment-stripe/1',
                         'target_revision': self.head, 'attacker_uid': 62004,
                         'native_policy_replaced': False, 'production_qualification': False,
                         'cases': [{'id': name, 'status': 'pass', 'target_revision': self.head,
                                    'backend': 'file', 'provider_write_requests': 1,
                                    'distinct_effects_in_interval': 1}
                                   for name in self.inventory['stripe_probe_cases']]}
        self.comparison = {'schema': 'auths.security-assessment-comparison/1',
                           'commercial_demand_validated': False,
                           'baseline_cases': [{'case': name, 'status': 'pass'}
                                              for name in self.inventory['baseline_cases']]}

    def check(self, boundary=None, comparison=None):
        return validate(boundary or self.boundary, comparison or self.comparison,
                        self.inventory, self.head)

    def test_complete_control(self):
        self.assertEqual(self.check()['independent_transport_cases'], 33)

    def test_missing_duplicate_failed_and_wrong_source_are_refused(self):
        variants = []
        for mutation in ['missing', 'duplicate', 'failed', 'source', 'backend']:
            value = copy.deepcopy(self.boundary)
            if mutation == 'missing':
                value['cases'].pop()
            elif mutation == 'duplicate':
                value['cases'].append(value['cases'][0])
            elif mutation == 'failed':
                value['cases'][0]['status'] = 'not-run'
            elif mutation == 'source':
                value['cases'][0]['target_revision'] = 'another-source'
            else:
                value['cases'][0]['backend'] = 'unconfigured-postgres'
            variants.append(value)
        for value in variants:
            with self.subTest(value=value['cases'][0]['id']):
                with self.assertRaises(ValueError):
                    self.check(boundary=value)

    def test_missing_positive_effect_and_unsupported_claim_are_refused(self):
        for field, bad in [('provider_write_requests', 0), ('distinct_effects_in_interval', 0)]:
            value = copy.deepcopy(self.boundary)
            next(row for row in value['cases'] if row['id'] == self.inventory['positive_control'])[field] = bad
            with self.assertRaises(ValueError):
                self.check(boundary=value)
        value = copy.deepcopy(self.boundary)
        value['production_qualification'] = True
        with self.assertRaises(ValueError):
            self.check(boundary=value)

    def test_incomplete_baseline_and_fabricated_customer_claim_are_refused(self):
        value = copy.deepcopy(self.comparison)
        value['baseline_cases'].pop()
        with self.assertRaises(ValueError):
            self.check(comparison=value)
        value = copy.deepcopy(self.comparison)
        value['commercial_demand_validated'] = True
        with self.assertRaises(ValueError):
            self.check(comparison=value)

    def test_wrong_inventory_version_and_duplicate_requirement_are_refused(self):
        for mutation in ['version', 'duplicate']:
            inventory = copy.deepcopy(self.inventory)
            if mutation == 'version':
                inventory['schema'] = 'unsupported'
            else:
                inventory['stripe_probe_cases'].append(inventory['stripe_probe_cases'][0])
            with self.assertRaises(ValueError):
                validate(self.boundary, self.comparison, inventory, self.head)


if __name__ == '__main__':
    unittest.main()
