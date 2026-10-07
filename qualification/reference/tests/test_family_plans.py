"""Source/artifact drift and refusal boundaries, without provider evidence."""

import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import generate_families
import family_corpus
import family_harness
from common import Refusal, canonical


class Plans(unittest.TestCase):
    def test_generated_source_plans_are_current_and_any_changed_member_refuses(self):
        generate_families.generate(check=True)
        original = generate_families.read
        for name in ['contract.json', 'record.json', 'corpus-manifest.json', 'harness', 'decision-record.md']:
            def altered(path, maximum):
                raw = original(path, maximum)
                return raw + b' ' if path.name == name else raw
            with patch.object(generate_families, 'read', side_effect=altered):
                with self.assertRaisesRegex(Refusal, 'reviewed-plan-drift'):
                    generate_families.generate(check=True)

    def test_complete_plan_requires_the_entire_fixed_resource_pool(self):
        for family in family_harness.REFERENCES:
            resources = family_harness.synthetic_resources(family, 'recipe-qualification/123/1')
            member = 'payments' if 'payments' in resources else 'records'
            self.assertEqual(len(resources[member]), 16)
            for count in [0, 1, 15, 17]:
                changed = copy.deepcopy(resources)
                changed[member] = [dict(resources[member][0], id=(
                    'pi_SYNTHETIC' + str(index) if member == 'payments' else 'recTEST' + str(index).zfill(10)))
                    for index in range(count)]
                with self.assertRaises(Refusal):
                    family_corpus.compile_plan(family, changed, {}, '1' * 64)

    def test_a_protected_step_cannot_emit_a_placeholder_observation(self):
        with patch.object(family_harness, 'write') as written:
            with self.assertRaises(SystemExit):
                family_harness.main('stripe-platform-refund-v1',
                    ['step', 'live-proof-replay', '0', 'submit', '/unconfigured', '/unconfigured-output'])
            written.assert_not_called()


if __name__ == '__main__':
    unittest.main()
