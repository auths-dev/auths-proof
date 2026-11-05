"""The AP074 comparator must detect drift, missing cases and altered contracts."""

import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ap074_differential as differential
from common import Refusal


class DifferentialContract(unittest.TestCase):
    def test_comparator_rejects_request_response_inventory_and_recovery_drift(self):
        original = json.loads(differential.NATIVE.read_bytes())

        def request(value):
            value['families'][0]['cases'][0]['request']['body'] += ' '

        def decision(value):
            value['families'][0]['cases'][2]['native_accepted'] = True

        def missing(value):
            value['families'][0]['cases'].pop()

        def duplicated(value):
            value['families'][0]['cases'][-1] = copy.deepcopy(value['families'][0]['cases'][0])

        def response(value):
            value['families'][0]['observations'][0]['native'] = 'state-match'

        def locator(value):
            value['families'][1]['recovery']['without_write_response_url'] = 'https://api.stripe.com/v1/refunds/re_TEST123'

        def scope(value):
            value['families'][0]['resources']['base'] = 'appOTHER'

        def capability(value):
            value['families'][1]['recovery']['capability']['unknown_reobservation'] = True

        def byte_boundary(value):
            row = next(row for row in value['families'][0]['observations'] if row['name'] == 'at-limit')
            row['trailing_space_bytes'] -= 1

        for mutate in [request, decision, missing, duplicated, response, locator, scope, capability, byte_boundary]:
            with self.subTest(mutation=mutate.__name__):
                changed = copy.deepcopy(original)
                mutate(changed)
                with self.assertRaises(Refusal):
                    differential.compare(changed)


if __name__ == '__main__':
    unittest.main()
