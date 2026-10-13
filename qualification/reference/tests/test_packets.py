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
import stripe_platform
from common import Refusal, canonical


class Packets(unittest.TestCase):
    def plan(self):
        resources = {'schema': 'auths.airtable-record-qualification-resources/1',
            'protected_run': 'recipe-qualification/123/1', 'base': airtable_record.BASE,
            'table': airtable_record.TABLE, 'records': [
                {'id': 'recTEST0000000001', 'run_metadata': 'recipe-qualification/123/1'}]}
        return {'schema': 'auths.qualification-packet-plan/4', 'family': airtable_record.FAMILY,
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
            lambda p: p.update(schema='auths.qualification-packet-plan/2'),
            lambda p: p.update(schema='auths.qualification-packet-plan/3'),
            lambda p: p['packets'][0].update(context='fresh'),
            lambda p: p['packets'][1]['arguments'].update(operation_id='new-operation'),
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

    def test_signing_pool_refuses_omitted_added_rebound_and_reordered_actions(self):
        plan = self.plan()
        packets = [{'label': item['label'], 'proof': item['label'] + '.proof',
                    'action': item['label'] + '.action',
                    'trusted_context': 'context-' + str(['initial', 'fresh'].index(item['context'])) + '.cbor',
                    'arguments': item['arguments']} for item in plan['packets']]
        carrier = {'schema': 'auths.qualification-public-packets/4',
                   'protected_run': plan['protected_run'], 'evaluated_at': 1000, 'not_after': 1300,
                   'trusted_contexts': ['context-0.cbor', 'context-1.cbor'], 'packets': packets}
        self.assertEqual(packet_plan.public_pool(plan['family'], plan['resources'], '2' * 64, carrier), packets)
        changes = [lambda c: c['packets'].pop(), lambda c: c['packets'].reverse(),
                   lambda c: c['packets'].append(copy.deepcopy(c['packets'][0])),
                   lambda c: c['packets'][0].update(proof='another.proof'),
                   lambda c: c['packets'][1].update(trusted_context='context-0.cbor'),
                   lambda c: c['packets'][0]['arguments'].update(operation_id='different-operation'),
                   lambda c: c['trusted_contexts'].pop(), lambda c: c.update(protected_run='recipe-qualification/999/1')]
        for change in changes:
            changed = copy.deepcopy(carrier)
            change(changed)
            with self.assertRaises(Refusal):
                packet_plan.public_pool(plan['family'], plan['resources'], '2' * 64, changed)

    def test_stripe_guard_probes_are_fixed_valid_requests_with_independent_refusals(self):
        run = 'recipe-qualification/123/1'
        resources = {'schema': 'auths.stripe-platform-qualification-resources/1',
            'protected_run': run, 'platform': 'acct_TEST123', 'payments': [
                {'id': 'pi_TEST123', 'amount_received': 2000, 'currency': 'usd',
                 'livemode': False, 'run_metadata': run}]}
        packets = packet_plan.arguments(stripe_platform.FAMILY, resources, '2' * 64)
        self.assertEqual(len(packets), 8)
        for phase in ['commissioning', 'live']:
            probes = {item['label']: item for item in packets if item['label'].startswith(phase + '-guard-')}
            self.assertEqual(set(probes), {phase + '-guard-ceiling', phase + '-guard-currency'})
            for kind, code in [('ceiling', 'gateway.relative-ceiling.above'),
                               ('currency', 'gateway.relative-ceiling.binding-mismatch')]:
                value = probes[phase + '-guard-' + kind]['arguments']
                self.assertEqual(stripe_platform.request(value, resources, '1' * 64, '2' * 64)['method'], 'POST')
                self.assertEqual(stripe_platform.entry_policy(value, resources), code)
        for count, accepted in [(25, True), (26, False)]:
            many = dict(resources, payments=[dict(resources['payments'][0], id='pi_TEST' + str(i)) for i in range(count)])
            expanded = packet_plan.arguments(stripe_platform.FAMILY, many, '2' * 64)
            carrier = {'schema': 'auths.qualification-public-packets/4', 'protected_run': run,
                'evaluated_at': 1000, 'not_after': 1300,
                'trusted_contexts': ['context-0.cbor', 'context-1.cbor'], 'packets': [
                    {'label': p['label'], 'proof': p['label'] + '.proof', 'action': p['label'] + '.action',
                     'trusted_context': 'context-' + str(['initial', 'fresh'].index(p['context'])) + '.cbor',
                     'arguments': p['arguments']} for p in expanded]}
            if accepted:
                self.assertEqual(len(packet_plan.public_pool(stripe_platform.FAMILY, many, '2' * 64, carrier)), 64)
            else:
                with self.assertRaises(Refusal): packet_plan.public_pool(stripe_platform.FAMILY, many, '2' * 64, carrier)

    def test_count_and_sum_experiments_have_distinct_fixed_native_windows(self):
        run = 'recipe-qualification/123/1'
        resources = {'schema': 'auths.stripe-platform-qualification-resources/1',
            'protected_run': run, 'platform': 'acct_TEST123', 'payments': [
                {'id': 'pi_TEST' + str(index), 'amount_received': 2000, 'currency': 'usd',
                 'livemode': False, 'run_metadata': run} for index in range(16)]}
        packets = packet_plan.arguments(stripe_platform.FAMILY, resources, '2' * 64)
        self.assertEqual(len(packets), 54)
        self.assertEqual(len(set(packet_plan.BUDGET_WINDOWS.values()) | {86400}), 5)
        for phase in ['commissioning', 'live']:
            by_label = {p['label']: p for p in packets}
            for kind, resource in [('count', 'pi_TEST14'), ('sum', 'pi_TEST15')]:
                label = phase + '-budget-' + kind
                positive, overflow = [by_label[label + suffix]['arguments'] for suffix in ['', '-over']]
                self.assertEqual(positive['payment_intent'], resource)
                self.assertEqual(positive['amount'], 1000)
                self.assertEqual(overflow['amount'], 500)
                self.assertNotEqual(positive['operation_id'], overflow['operation_id'])
                self.assertEqual(packet_plan.grant_for(label), phase + '-' + kind)
                self.assertEqual(packet_plan.grant_for(label + '-over'), phase + '-' + kind)
                self.assertEqual(packet_plan.grant_for(phase + '-00'), 'default')
                self.assertIsNone(stripe_platform.entry_policy(positive, resources))
            for kind in ['kind', 'generation', 'commitment', 'version']:
                probe = by_label[phase + '-custody-' + kind]
                self.assertEqual(probe['arguments']['payment_intent'], 'pi_TEST13')
                self.assertEqual(packet_plan.grant_for(probe['label']), 'default')

    def test_an_unanticipated_credential_name_refuses_before_importing_the_sdk(self):
        with patch.dict(os.environ, {'UNANTICIPATED_PROVIDER_KEY': 'synthetic-forbidden-input'}, clear=True):
            with self.assertRaisesRegex(Refusal, 'consumer-environment'):
                author_packets.installed_native()


if __name__ == '__main__':
    unittest.main()
