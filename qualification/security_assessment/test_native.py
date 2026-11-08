"""Prevent support helpers and missing fixture consumers becoming scenario counts."""
import copy
import json
from pathlib import Path
import unittest

from native import select


class NativeSelectionControls(unittest.TestCase):
    def test_support_inventory_is_not_scenario_evidence(self):
        support = json.loads(Path(__file__).with_name('support-entrypoints.json').read_text())
        names = [row['id'] for row in support['entries']] + ['actual::property']
        selected, workers, consumers = select(names, support)
        self.assertEqual(selected, ['actual::property'])
        self.assertEqual(len(workers), 20)
        self.assertEqual(consumers, ['qualification_tests::verify_simulation_reports'])
        for mutation in ['missing', 'duplicate', 'kind']:
            changed = copy.deepcopy(support)
            current = list(names)
            if mutation == 'missing':
                current.remove(changed['entries'][0]['id'])
            elif mutation == 'duplicate':
                changed['entries'].append(changed['entries'][0])
            else:
                changed['entries'][0]['kind'] = 'unknown'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                select(current, changed)


if __name__ == '__main__':
    unittest.main()
