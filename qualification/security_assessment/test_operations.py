"""Evidence controls for installed recovery drills; no product-security proof."""
import copy
import json
from pathlib import Path
import unittest

from validate import validate_operations


class OperationalEvidenceControls(unittest.TestCase):
    def test_drill_census_and_mutations(self):
        inventory = json.loads(Path(__file__).with_name('inventory.json').read_text())
        value = {'schema': 'auths.security-assessment-operations/1', 'target_revision': 'target',
                 'binary_sha256': 'binary', 'native_policy_replaced': False,
                 'production_qualification': False, 'attacker_uid': 62004, 'backend': 'file',
                 'cases': [{'id': name, 'status': 'pass', 'target_revision': 'target',
                            'provider_write_requests': 1, 'distinct_effects_in_interval': 1}
                           for name in inventory['operations_cases']]}
        self.assertEqual(validate_operations(value, inventory, 'target', 'binary'), 3)
        for mutation in ['missing', 'duplicate', 'source', 'effect', 'failed', 'binary']:
            altered = copy.deepcopy(value)
            if mutation == 'missing':
                altered['cases'].pop()
            elif mutation == 'duplicate':
                altered['cases'].append(altered['cases'][0])
            elif mutation == 'source':
                altered['target_revision'] = 'other'
            elif mutation == 'effect':
                altered['cases'][0]['provider_write_requests'] = 2
            elif mutation == 'failed':
                altered['cases'][0]['status'] = 'not-run'
            else:
                altered['binary_sha256'] = 'other'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_operations(altered, inventory, 'target', 'binary')


if __name__ == '__main__':
    unittest.main()
