"""Closed native/result projection boundaries; synthetic, never qualification."""

import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import airtable_record as airtable
from common import Refusal, canonical, echo, sha256
from native_observation import Effects, result


class Observations(unittest.TestCase):
    def setUp(self):
        self.run = 'recipe-qualification/123/1'
        self.resources = {'schema': 'auths.airtable-record-qualification-resources/1',
            'protected_run': self.run, 'base': airtable.BASE, 'table': airtable.TABLE,
            'records': [{'id': 'recTEST0000000001', 'run_metadata': self.run}]}
        self.tuple = {'recipe_family': airtable.FAMILY, 'compiled_recipe_sha256': '1' * 64}
        self.arguments = {'operator_namespace': 'airtable-demo', 'operation_id': 'qualified-1',
            'recipe_digest': '1' * 64, 'record_id': 'recTEST0000000001', 'replacement': 'Approved'}
        self.review = {'schema': 'auths.gateway-submission-review/1',
            'actors': ['raw:synthetic-test-only-actor'], 'action_commitment': '2' * 64,
            'arguments': self.arguments,
            'request': airtable.request(self.arguments, self.resources, '2' * 64, '1' * 64)}
        self.before = {'schema': 'auths.gateway-execution-witness/1', 'scope': '1' * 32,
            'credential_lease_calls': 0, 'write_transport_entries': 0, 'read_transport_entries': 0}
        self.after = dict(self.before, credential_lease_calls=1, write_transport_entries=1,
                          read_transport_entries=1)
        token = echo('airtable-demo', 'qualified-1', '2' * 64)
        self.response = canonical({'id': 'recTEST0000000001',
            'fields': {'DemoStatus': 'Approved', 'auths_echo': token}})
        self.observed = {'outcome': 'observed-by-provider', 'status': 200,
            'evidence': {'channel': 'read-back', 'echo': token,
                         'evidence_digest': sha256(self.response), 'observed_at': 1000}}

    def project(self, ledger, value, before=None, after=None, response=None, review=None):
        return ledger.project(self.tuple, review or self.review, self.resources, value,
                              before or self.before, after or self.after, response)

    def test_http_success_never_becomes_a_confirmed_effect(self):
        facts, fresh = self.project(Effects(), {'outcome': 'response-recorded', 'status': 200})
        self.assertEqual(facts['verdict']['outcome'], 'response-recorded')
        self.assertEqual(facts['confirmed_by_read_back'], 0)
        self.assertIsNone(fresh)
        self.assertEqual(result({'outcome': 'observed', 'status': 200, 'matched': True})[0], 'response-recorded')
        for value in [{'outcome': 'observed-by-provider', 'status': 200},
                      {'outcome': 'unknown', 'passed': True},
                      {'outcome': 'response-recorded', 'status': True},
                      {'outcome': 'refused', 'code': 'pretend-success'}]:
            with self.assertRaises(Refusal): result(value)

    def test_only_one_actual_entered_write_can_be_confirmed_once(self):
        ledger = Effects()
        facts, fresh = self.project(ledger, self.observed, response=self.response)
        self.assertEqual((facts['provider_entries'], facts['confirmed_by_read_back']), (1, 1))
        self.assertEqual(fresh['response_sha256'], sha256(self.response))
        repeated, _ = self.project(ledger, self.observed, before=self.after, after=self.after,
                                  response=self.response)
        self.assertEqual((repeated['provider_entries'], repeated['confirmed_by_read_back']), (0, 0))
        with self.assertRaisesRegex(Refusal, 'duplicate-entry'):
            self.project(ledger, self.observed, response=self.response)
        with self.assertRaisesRegex(Refusal, 'unmeasured-effect'):
            self.project(Effects(), self.observed, before=self.after, after=self.after, response=self.response)

    def test_a_read_only_recovery_confirms_only_its_measured_unknown_write(self):
        ledger = Effects()
        unknown, fresh = self.project(ledger, {'outcome': 'unknown'})
        self.assertEqual(unknown['confirmed_by_read_back'], 0)
        self.assertIsNone(fresh)
        resumed = dict(self.after, credential_lease_calls=2, read_transport_entries=2)
        recovered, _ = self.project(ledger, dict(self.observed, status=None),
            before=self.after, after=resumed, response=self.response)
        self.assertEqual((recovered['credential_leases'], recovered['provider_entries'],
                          recovered['confirmed_by_read_back']), (1, 0, 1))
        again, _ = self.project(ledger, self.observed, before=resumed, after=resumed,
                                response=self.response)
        self.assertEqual(again['confirmed_by_read_back'], 0)

    def test_wrong_response_echo_request_scope_and_ambiguous_claims_refuse(self):
        for problem in ['raw-bytes', 'echo', 'request', 'scope', 'extra-field', 'refused-entry']:
            ledger, value, review = Effects(), copy.deepcopy(self.observed), copy.deepcopy(self.review)
            after, response = dict(self.after), self.response
            if problem == 'raw-bytes': response += b' '
            if problem == 'echo': value['evidence']['echo'] = 'forged-echo'
            if problem == 'request': review['request']['url'] = 'https://attacker.invalid/write'
            if problem == 'scope': after['scope'] = '2' * 32
            if problem == 'extra-field': value['evidence']['provider_token'] = 'synthetic-forbidden-input'
            if problem == 'refused-entry': value = {'outcome': 'not-entered', 'code': 'gateway.attempt.replay'}; response = None
            with self.subTest(problem=problem), self.assertRaises(Refusal):
                self.project(ledger, value, after=after, response=response, review=review)
            self.assertEqual(ledger.entries, {})

    def test_candidate_or_action_drift_cannot_confirm_an_earlier_measured_entry(self):
        ledger = Effects()
        self.project(ledger, {'outcome': 'unknown'})
        changed_tuple = dict(self.tuple, gateway_semantic_closure_sha256='3' * 64)
        with self.assertRaisesRegex(Refusal, 'changed-tuple'):
            ledger.project(changed_tuple, self.review, self.resources, self.observed,
                           self.after, self.after, self.response)
        changed = copy.deepcopy(self.review)
        changed['action_commitment'] = '3' * 64
        changed['request'] = airtable.request(self.arguments, self.resources, '3' * 64, '1' * 64)
        with self.assertRaisesRegex(Refusal, 'changed-action'):
            self.project(ledger, self.observed, before=self.after, after=self.after,
                         response=self.response, review=changed)
        self.assertFalse(next(iter(ledger.entries.values()))['confirmed'])


if __name__ == '__main__':
    unittest.main()
