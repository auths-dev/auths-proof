"""Packet confinement and refresh protocol; no protected evidence is claimed."""

import copy
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import airtable_record
import author_packets
import packet_plan
from common import Refusal, canonical


class Packets(unittest.TestCase):
    def plan(self):
        resources = {'schema': 'auths.airtable-record-qualification-resources/1',
            'protected_run': 'recipe-qualification/123/1', 'base': airtable_record.BASE,
            'table': airtable_record.TABLE, 'records': [
                {'id': 'recTEST0000000001', 'run_metadata': 'recipe-qualification/123/1'}]}
        return {'schema': 'auths.qualification-packet-plan/1', 'family': airtable_record.FAMILY,
            'protected_run': resources['protected_run'], 'evaluated_at': 1000, 'not_after': 8200,
            'configuration': '1' * 64, 'extension': None, 'resources': resources,
            'packets': packet_plan.arguments(airtable_record.FAMILY, resources, '2' * 64)}

    def test_resource_action_and_phase_changes_cannot_choose_refresh_authority(self):
        plan = self.plan()
        self.assertEqual(packet_plan.validate(plan), plan)
        changes = [lambda p: p['packets'][0]['arguments'].update(record_id='recOTHER000000001'),
            lambda p: p['packets'][0]['arguments'].update(replacement='Deleted'),
            lambda p: p['packets'][0]['arguments'].update(operation_id='another-run'),
            lambda p: p['packets'][0].update(label='../../provider-secret'),
            lambda p: p['resources'].update(base='appOTHER'),
            lambda p: p.update(not_after=9000), lambda p: p.update(evaluated_at=True),
            lambda p: p.update(credential='synthetic-forbidden-input'),
            lambda p: p['packets'].reverse(), lambda p: p['packets'].pop()]
        for change in changes:
            changed = copy.deepcopy(plan)
            change(changed)
            with self.assertRaises(Refusal): packet_plan.validate(changed)

    def test_refresh_input_is_closed_bounded_and_monotonic(self):
        value = {'command': 'refresh', 'label': 'live-00', 'generation': 1}
        self.assertEqual(author_packets.command(canonical(value) + b'\n', 0), value)
        self.assertIsNone(author_packets.command(b'{"command":"close"}\n', 0))
        for changed in [dict(value, generation=2), dict(value, generation=True),
                        dict(value, arguments={}), dict(value, credential='synthetic-forbidden-input'),
                        dict(value, label=[]), dict(value, command='sign-arbitrary')]:
            with self.assertRaises(Refusal): author_packets.command(canonical(changed) + b'\n', 0)
        for raw in [canonical(value), b' ' * 513 + b'\n', b'{"command":"close","command":"refresh"}\n']:
            with self.assertRaises(Refusal): author_packets.command(raw, 0)

    def test_an_unanticipated_credential_name_refuses_before_importing_the_sdk(self):
        with patch.dict(os.environ, {'UNANTICIPATED_PROVIDER_KEY': 'synthetic-forbidden-input'}, clear=True):
            with self.assertRaisesRegex(Refusal, 'consumer-environment'):
                author_packets.installed_native()


if __name__ == '__main__':
    unittest.main()
