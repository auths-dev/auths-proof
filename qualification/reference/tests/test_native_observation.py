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

    def support(self):
        self.tuple.update(profile_lock_sha256='3' * 64, gateway_semantic_closure_sha256='4' * 64,
            target={'gateway_package': 'auths-gateway', 'gateway_version': 'synthetic-only',
                'gateway_build_sha256': '5' * 64, 'store_kind': 'postgresql-v1',
                'store_schema': 'auths.lifecycle.postgresql/6', 'credential_store_kind': 'aws-secrets-manager-v1'})
        key = sha256(b'auths.gateway-logical-operation/1\0' + self.arguments['operator_namespace'].encode()
                     + b'\0' + self.arguments['operation_id'].encode())
        return {'schema': 'auths.gateway-support-bundle/1', 'gateway_package': 'auths-gateway',
            'gateway_version': 'synthetic-only', 'semantic_closure_sha256': '4' * 64,
            'build_sha256': '5' * 64, 'recipe_sha256': '1' * 64, 'profile_lock_sha256': '3' * 64,
            'trusted_context_sha256': '6' * 64, 'deployment': 'production',
            'credential_store_kind': 'aws-secrets-manager-v1',
            'qualification': {'policy': 'required', 'state': 'unqualified', 'code': 'gateway.qualification.missing'},
            'connection': None, 'attempts': {'listed': 1, 'truncated': False, 'by_stage': {'unknown': 1},
                'identifiers': [{'key_sha256': key, 'stage': 'unknown'}]},
            'codes': ['gateway.qualification.missing', 'gateway.support.connection-unavailable']}

    def test_killed_client_is_not_evidence_without_exact_durable_native_unknown_and_entry(self):
        support = self.support()
        ledger = Effects()
        facts, fresh = ledger.project_interrupted(self.tuple, self.review, self.resources, '6' * 64,
            support, self.before, self.after)
        self.assertEqual((facts['verdict']['outcome'], facts['provider_entries'], facts['confirmed_by_read_back']),
                         ('unknown', 1, 0))
        self.assertIsNone(fresh)
        for problem in ['wrong-build', 'wrong-context', 'different-operation', 'not-unknown', 'truncated',
                        'unavailable', 'no-entry', 'false-count']:
            value, after = copy.deepcopy(support), self.after
            if problem == 'wrong-build': value['build_sha256'] = '7' * 64
            if problem == 'wrong-context': value['trusted_context_sha256'] = '7' * 64
            if problem == 'different-operation': value['attempts']['identifiers'][0]['key_sha256'] = '7' * 64
            if problem == 'not-unknown': value['attempts']['identifiers'][0]['stage'] = 'response-recorded'
            if problem == 'truncated': value['attempts']['truncated'] = True
            if problem == 'unavailable': value['attempts'] = None
            if problem == 'no-entry': after = self.before
            if problem == 'false-count': value['attempts']['by_stage']['unknown'] = True
            with self.subTest(problem=problem), self.assertRaises(Refusal):
                Effects().project_interrupted(self.tuple, self.review, self.resources, '6' * 64,
                    value, self.before, after)

    def test_an_unobservable_admin_refusal_cannot_invent_a_recovered_effect(self):
        support = self.support()
        response = {'schema': 'auths.gateway-admin-response/1', 'ok': False,
                    'code': 'gateway.reobserve.not-observable'}
        ledger = Effects()
        ledger.project(self.tuple, self.review, self.resources, {'outcome': 'unknown'}, self.before, self.after)
        unknown, fresh = ledger.project_stored_unknown(self.tuple, self.review, self.resources, '6' * 64,
                                                       support, self.after, self.after)
        self.assertEqual((unknown['verdict']['outcome'], unknown['provider_entries']), ('unknown', 0))
        self.assertIsNone(fresh)
        with self.assertRaisesRegex(Refusal, 'unmeasured-unknown'):
            Effects().project_stored_unknown(self.tuple, self.review, self.resources, '6' * 64,
                                             support, self.after, self.after)
        refused, fresh = ledger.project_admin_refusal(self.tuple, self.review, self.resources,
                                                      response, self.after, self.after)
        self.assertEqual(refused['verdict'], {'outcome': 'refused', 'code': 'gateway.reobserve.not-observable',
                                           'request_sha256': None, 'evidence_sha256': None})
        self.assertIsNone(fresh)
        with self.assertRaises(Refusal):
            ledger.project_admin_refusal(self.tuple, self.review, self.resources,
                dict(response, code='gateway.admin.socket-unavailable'), self.after, self.after)

    def test_race_aggregates_distinct_actual_native_scopes_without_counting_a_second_confirmation(self):
        second = dict(self.before, scope='2' * 32)
        recovered = dict(second, credential_lease_calls=1, read_transport_entries=1)
        ledger = Effects()
        facts, fresh = ledger.project_race(self.tuple, self.review, self.resources,
            [{'outcome': 'unknown'}, dict(self.observed, status=None)],
            [(self.before, self.after), (second, recovered)], self.response)
        self.assertEqual((facts['credential_leases'], facts['provider_entries'], facts['confirmed_by_read_back']), (2, 1, 1))
        self.assertEqual(fresh['response_sha256'], sha256(self.response))
        for other in [{'outcome': 'denied', 'code': 'action-outside-validity'},
                      {'outcome': 'not-entered', 'code': 'gateway.attempt.persistence'}]:
            with self.assertRaises(Refusal):
                Effects().project_race(self.tuple, self.review, self.resources,
                    [self.observed, other], [(self.before, self.after), (second, recovered)], self.response)
        with self.assertRaisesRegex(Refusal, 'duplicate-host'):
            Effects().project_race(self.tuple, self.review, self.resources,
                [self.observed, {'outcome': 'unknown'}],
                [(self.before, self.after), (self.before, self.after)], self.response)

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
