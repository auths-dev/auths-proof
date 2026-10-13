"""Provider-reference refusal boundaries using synthetic responses only."""

from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import canonical, echo, Refusal
import family_operations as operations
from native_observation import Effects
import stripe_platform as stripe


class Capabilities(unittest.TestCase):
    def operation(self, root):
        value = object.__new__(operations.Operations)
        value.family, value.reference = stripe.FAMILY, stripe
        value.tuple = {'recipe_family': stripe.FAMILY, 'compiled_recipe_sha256': '1' * 64}
        run = 'recipe-qualification/123/1'
        value.resources = {'schema': 'auths.stripe-platform-qualification-resources/1',
            'protected_run': run, 'platform': 'acct_SYNTHETIC', 'payments': [
                {'id': 'pi_SYNTHETIC', 'amount_received': 2000, 'currency': 'usd',
                 'livemode': False, 'run_metadata': run}]}
        arguments = {'operator_namespace': stripe.SERVICE, 'operation_id': 'synthetic-only',
            'recipe_digest': '1' * 64, 'payment_intent': 'pi_SYNTHETIC', 'amount': 500, 'currency': 'usd'}
        review = {'schema': 'auths.gateway-submission-review/1', 'actors': ['raw:synthetic-only'],
            'action_commitment': '2' * 64, 'arguments': arguments,
            'request': stripe.request(arguments, value.resources, '2' * 64, '1' * 64)}
        value.reviewed = {'commissioning-10': review}
        value.effects = Effects()
        value.effects.entries[(value.family, run, stripe.SERVICE, arguments['operation_id'])] = {'confirmed': True}
        response = {'id': 're_SYNTHETIC', 'object': 'refund', 'livemode': False,
            'payment_intent': 'pi_SYNTHETIC', 'amount': 500, 'currency': 'usd', 'status': 'succeeded',
            'metadata': {'auths_echo': echo(stripe.SERVICE, arguments['operation_id'], '2' * 64)}}
        value.oracle = SimpleNamespace(fresh=lambda *_args: canonical(response))
        before = {'schema': 'auths.gateway-execution-witness/1', 'scope': '1' * 32,
            'credential_lease_calls': 0, 'write_transport_entries': 0, 'read_transport_entries': 0}
        value.deployment = SimpleNamespace(work=root, witness=lambda *_args: before)
        value.current_credential = b'rk_test_SYNTHETIC_ONLY_RUNTIME'
        return value, response

    def test_duplicate_probe_records_its_fixture_entry_and_verifies_the_existing_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            value, response = self.operation(Path(directory))
            calls = []
            def request(origin, method, path, key, body=None, headers=None):
                calls.append((method, path, body, headers))
                if path == '/v1/balance': return {'livemode': False}
                if path == '/v1/account': return {'id': value.resources['platform']}
                self.assertEqual((method, path), ('POST', '/v1/refunds'))
                return response
            with patch.object(operations.resource_io, 'request', request), \
                    patch.object(operations.resource_io, 'exchange', return_value=(403, b'synthetic-only-denial')):
                report = value.capabilities('commissioning')
            self.assertEqual(report['observed']['provider_entries'], 0, 'this is the actual native counter scope')
            self.assertEqual(len([call for call in calls if call[0] == 'POST']), 1)
            native = value.reviewed['commissioning-10']['request']
            self.assertEqual(calls[-1][2], native['body'].encode())
            self.assertEqual(calls[-1][3]['Idempotency-Key'], native['idempotency_key'])
            import json
            retained = json.loads((Path(directory) / 'provider-capability-probes/commissioning.json').read_bytes())
            self.assertEqual(retained['fixture_duplicate_api_entries'], 1)
            self.assertEqual(retained['additional_effects'], 0)

    def test_wrong_effect_or_overbroad_key_cannot_complete_the_capability_case(self):
        for problem in ['new-refund', 'unexpected-permission', 'unconfirmed-native-effect']:
            with tempfile.TemporaryDirectory() as directory:
                value, response = self.operation(Path(directory))
                if problem == 'unconfirmed-native-effect':
                    next(iter(value.effects.entries.values()))['confirmed'] = False
                calls = []
                def request(origin, method, path, key, body=None, headers=None):
                    calls.append(method)
                    if path == '/v1/balance': return {'livemode': False}
                    if path == '/v1/account': return {'id': value.resources['platform']}
                    return dict(response, id='re_CHANGED')
                with patch.object(operations.resource_io, 'request', request), \
                        patch.object(operations.resource_io, 'exchange',
                            return_value=(200 if problem == 'unexpected-permission' else 403, b'synthetic-only')), \
                        self.assertRaises(Refusal):
                    value.capabilities('commissioning')
                self.assertFalse((Path(directory) / 'provider-capability-probes').exists())
                if problem != 'new-refund': self.assertNotIn('POST', calls)


if __name__ == '__main__':
    unittest.main()
