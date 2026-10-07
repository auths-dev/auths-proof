"""Independent request mappings and finite input boundaries; no live claim."""

import copy
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import airtable_record as airtable
import stripe_platform as stripe
from common import Refusal, echo, idempotency
from common import canonical, sha256
import measure
import fresh_evidence as fresh
import expand as expansion
import packet_plan
from expand import decode, unique_object


RUN = 'recipe-qualification/123/1'
DIGEST = '1' * 64
COMMITMENT = '2' * 64


class References(unittest.TestCase):
    def stripe_resources(self):
        return {'schema': 'auths.stripe-platform-qualification-resources/1', 'protected_run': RUN,
                'platform': 'acct_TEST123', 'payments': [
                    {'id': 'pi_TEST123', 'amount_received': 2000, 'currency': 'usd',
                     'livemode': False, 'run_metadata': RUN}]}

    def stripe_arguments(self):
        return {'operator_namespace': stripe.SERVICE, 'operation_id': 'qualified-1',
                'recipe_digest': DIGEST, 'payment_intent': 'pi_TEST123', 'amount': 1000,
                'currency': 'usd'}

    def airtable_resources(self):
        return {'schema': 'auths.airtable-record-qualification-resources/1', 'protected_run': RUN,
                'base': airtable.BASE, 'table': airtable.TABLE,
                'records': [{'id': 'recTEST0000000001', 'run_metadata': RUN}]}

    def airtable_arguments(self):
        return {'operator_namespace': 'airtable-demo', 'operation_id': 'qualified-1',
                'recipe_digest': DIGEST, 'record_id': 'recTEST0000000001',
                'replacement': 'Approved'}

    def test_native_measurements_refuse_restart_wrap_and_duplicate_hosts(self):
        before = {'schema': 'auths.gateway-execution-witness/1', 'scope': '1' * 32,
                  'credential_lease_calls': 0, 'write_transport_entries': 0,
                  'read_transport_entries': 0}
        after = dict(before, credential_lease_calls=1, write_transport_entries=1,
                     read_transport_entries=2)
        self.assertEqual(measure.delta(before, after)['write_transport_entries'], 1)
        for bad in [dict(after, scope='2' * 32),
                    dict(after, credential_lease_calls=(1 << 64) - 1),
                    dict(after, credential_lease_calls=True), dict(after, reset=False)]:
            with self.assertRaises(Refusal): measure.delta(before, bad)
        with self.assertRaises(Refusal): measure.delta(after, before)
        with self.assertRaises(Refusal): measure.aggregate([(before, after), (before, after)])
        other = dict(before, scope='2' * 32)
        self.assertEqual(measure.aggregate([(before, after), (other, other)])['credential_lease_calls'], 1)

    def test_fresh_stripe_evidence_checks_state_echo_and_raw_bytes(self):
        resources, arguments = self.stripe_resources(), self.stripe_arguments()
        value = {'id': 're_TEST123', 'object': 'refund',
                 'payment_intent': arguments['payment_intent'], 'amount': arguments['amount'],
                 'currency': 'usd', 'status': 'succeeded',
                 'metadata': {'auths_echo': echo(stripe.SERVICE, arguments['operation_id'], COMMITMENT)}}
        response = canonical(value)
        witness = fresh.witness(stripe.FAMILY, arguments, resources, COMMITMENT, DIGEST, response)
        self.assertEqual(witness['response_sha256'], sha256(response))
        self.assertEqual(witness['subject_sha256'], fresh.subject(stripe.FAMILY, arguments, resources, COMMITMENT, DIGEST))
        for field, bad in [('amount', True), ('amount', 999), ('livemode', True),
                           ('payment_intent', 'pi_OTHER'), ('status', 'pending'),
                           ('metadata', {'auths_echo': 'forged'})]:
            changed = dict(value, **{field: bad})
            with self.assertRaises(Refusal):
                fresh.witness(stripe.FAMILY, arguments, resources, COMMITMENT, DIGEST, canonical(changed))
        # Equal semantic JSON with different bytes still has a different witness.
        spaced = json.dumps(value).encode()
        self.assertNotEqual(fresh.witness(stripe.FAMILY, arguments, resources, COMMITMENT, DIGEST, spaced)['response_sha256'], witness['response_sha256'])

    def test_fresh_airtable_evidence_requires_exact_known_record_and_value(self):
        resources, arguments = self.airtable_resources(), self.airtable_arguments()
        value = {'id': arguments['record_id'], 'fields': {
            'DemoStatus': arguments['replacement'],
            'auths_echo': echo('airtable-demo', arguments['operation_id'], COMMITMENT)}}
        witness = fresh.witness(airtable.FAMILY, arguments, resources, COMMITMENT, DIGEST, canonical(value))
        self.assertEqual(witness['response_sha256'], sha256(canonical(value)))
        for changed in [dict(value, id='recOTHER000000001'), dict(value, fields={}),
                        dict(value, fields=dict(value['fields'], DemoStatus='Pending'))]:
            with self.assertRaises(Refusal):
                fresh.witness(airtable.FAMILY, arguments, resources, COMMITMENT, DIGEST, canonical(changed))
        for raw in [b'{"id":"one","id":"two"}', b'{"id":NaN}', b' ' * 65537]:
            with self.assertRaises(Refusal): fresh.decode(raw)

    def test_stripe_boundary_and_exact_form_have_no_connect_header(self):
        resources = stripe.resources(self.stripe_resources(), RUN)
        arguments = self.stripe_arguments()
        request = stripe.request(arguments, resources, COMMITMENT, DIGEST)
        self.assertEqual(request['method'], 'POST')
        self.assertEqual(request['url'], 'https://api.stripe.com/v1/refunds')
        fields = urllib.parse.parse_qsl(request['body'])
        self.assertEqual(fields, [('amount', '1000'),
                                 ('metadata[auths_echo]', echo(stripe.SERVICE, 'qualified-1', COMMITMENT)),
                                 ('payment_intent', 'pi_TEST123')])
        self.assertEqual(request['headers'], [
            ['Stripe-Version', '2025-03-31.basil'],
            ['Idempotency-Key', idempotency(stripe.SERVICE, 'qualified-1')]])
        for amount in [0, -1, True, 10001, 99999999]:
            with self.subTest(amount=amount), self.assertRaises(Refusal):
                stripe.request({**arguments, 'amount': amount}, resources, COMMITMENT, DIGEST)
        self.assertIsNone(stripe.entry_policy(arguments, resources))
        self.assertEqual(stripe.entry_policy({**arguments, 'amount': 1001}, resources),
                         'gateway.relative-ceiling.above')
        self.assertEqual(stripe.entry_policy({**arguments, 'currency': 'eur'}, resources),
                         'gateway.relative-ceiling.binding-mismatch')

    def test_stripe_resources_are_test_only_unique_and_bound_to_the_run(self):
        mutations = [
            lambda value: value.update(protected_run='another-run'),
            lambda value: value['payments'][0].update(livemode=True),
            lambda value: value['payments'][0].update(currency='eur'),
            lambda value: value['payments'][0].update(run_metadata='another-run'),
            lambda value: value['payments'][0].update(id='pi_TEST123/../../other'),
            lambda value: value['payments'].append(copy.deepcopy(value['payments'][0])),
            lambda value: value.update(payments=[]),
            lambda value: value.update(credential='synthetic-forbidden-input'),
        ]
        for mutate in mutations:
            value = self.stripe_resources()
            mutate(value)
            with self.assertRaises(Refusal):
                stripe.resources(value, RUN)

    def test_airtable_mapping_updates_only_the_reviewed_record_field_and_echo(self):
        resources = airtable.resources(self.airtable_resources(), RUN)
        arguments = self.airtable_arguments()
        request = airtable.request(arguments, resources, COMMITMENT, DIGEST)
        self.assertEqual(request['method'], 'PATCH')
        self.assertEqual(request['url'],
                         f'https://api.airtable.com/v0/{airtable.BASE}/{airtable.TABLE}/recTEST0000000001')
        self.assertEqual(json.loads(request['body']), {'fields': {
            'DemoStatus': 'Approved', 'auths_echo': echo('airtable-demo', 'qualified-1', COMMITMENT)}})
        self.assertEqual(request['headers'], [])
        self.assertIsNone(request['idempotency_key'])
        for mutation in [{'replacement': 'Deleted'}, {'record_id': '../other'},
                         {'recipe_digest': '3' * 64}, {'operator_namespace': 'other'},
                         {'authorization': 'synthetic-forbidden-input'}]:
            with self.subTest(mutation=mutation), self.assertRaises(Refusal):
                airtable.request({**arguments, **mutation}, resources, COMMITMENT, DIGEST)

    def test_airtable_resource_expansion_preserves_every_other_recipe_member(self):
        resources = airtable.resources(self.airtable_resources(), RUN)
        root = Path(__file__).resolve().parents[3]
        template = json.loads((root / 'bindings/fixtures/gateway/airtable/recipe.json').read_bytes())
        original = copy.deepcopy(template)
        expanded = airtable.recipe(template, resources)
        self.assertEqual(template, original)
        for kind in ['write', 'observation']:
            self.assertEqual(expanded[kind]['path'][1]['value'], airtable.BASE)
            self.assertEqual(expanded[kind]['path'][2]['value'], airtable.TABLE)
            expanded[kind]['path'] = original[kind]['path']
        self.assertEqual(expanded, original)
        for key in ['base', 'table', 'protected_run']:
            with self.assertRaises(Refusal):
                airtable.resources({**resources, key: 'another-resource'}, RUN)

    def test_duplicate_json_fields_and_nonfinite_numbers_never_choose_authority(self):
        for source in [b'{"resource":1,"resource":2}', b'{"resource":NaN}', b'{"resource":Infinity}']:
            with self.assertRaises(Refusal):
                decode(source)
        with self.assertRaises(Refusal):
            unique_object([('member', 'conformance'), ('member', 'differential')])

    def test_binding_is_rederived_and_altered_source_or_native_observations_refuse(self):
        # This isolated unit stub checks expansion plumbing, not cryptographic
        # proof validity or a production tuple. Real native proof review has a
        # separate Rust test over the frozen quorum corpus.
        root = Path(__file__).resolve().parents[3]
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            source = root / 'qualification/simulation/live/stripe-platform'
            for name in ['recipe.json', 'profile.lock.json']:
                (work / name).write_bytes((source / name).read_bytes())
            (work / 'candidate').write_bytes(b'synthetic test-only candidate, not an executable')
            (work / 'context-0.cbor').write_bytes(b'synthetic test-only context')
            (work / 'context-1.cbor').write_bytes(b'synthetic fresh test-only context')
            planned = packet_plan.arguments(stripe.FAMILY, self.stripe_resources(), DIGEST)
            packets = []
            for packet in planned:
                label = packet['label']
                (work / (label + '.proof')).write_bytes(b'synthetic test-only proof')
                (work / (label + '.action')).write_bytes(b'synthetic test-only action')
                packets.append({'label': label, 'trusted_context':
                    'context-' + str(['initial', 'fresh'].index(packet['context'])) + '.cbor',
                    'proof': label + '.proof', 'action': label + '.action', 'arguments': packet['arguments']})
            (work / 'resources.json').write_bytes(canonical(self.stripe_resources()))
            (work / 'packets.json').write_bytes(canonical({
                'schema': 'auths.qualification-public-packets/3', 'protected_run': RUN,
                'evaluated_at': 1000, 'not_after': 1300,
                'trusted_contexts': ['context-0.cbor', 'context-1.cbor'], 'packets': packets}))
            artifacts = json.loads((root / 'bindings/fixtures/qualification/commissioning-v2.json').read_bytes())
            tuple_value = json.loads(artifacts['permit'])['statement']['binding']['tuple']
            tuple_value['recipe_family'] = stripe.FAMILY
            tuple_value['compiled_recipe_sha256'] = DIGEST
            tuple_value['target']['gateway_build_sha256'] = sha256((work / 'candidate').read_bytes())
            tuple_value['target']['store_schema'] = 'auths.lifecycle.postgresql/6'
            (work / 'tuple.json').write_bytes(canonical(tuple_value))
            tuple_digest = sha256(b'auths.qualification-tuple/1\0' + canonical(tuple_value))
            for member_name in ['conformance', 'differential']:
                (work / (member_name + '.json')).write_bytes(canonical({
                    'schema': 'auths.qualification-evidence/1', 'member': member_name,
                    'commit': '1' * 40, 'tuple_sha256': tuple_digest, 'cases': [],
                }))
            args = SimpleNamespace(source_commit='1' * 40, protected_run=RUN,
                tuple=work / 'tuple.json', candidate=work / 'candidate', reviewer=work / 'not-an-executable',
                recipe=work / 'recipe.json', profile_lock=work / 'profile.lock.json',
                resources=work / 'resources.json', packets=work / 'packets.json',
                conformance=work / 'conformance.json', differential=work / 'differential.json',
                out_dir=work / 'expanded')
            def review(_binary, arguments):
                if arguments[0] == 'qualification-candidate':
                    return copy.deepcopy(tuple_value)
                label = Path(arguments[arguments.index('--proof') + 1]).stem
                value = next(packet['arguments'] for packet in packets if packet['label'] == label)
                commitment = sha256(canonical(value))
                return {'schema': 'auths.gateway-submission-review/1',
                        'actors': ['raw:synthetic-test-only-actor'], 'action_commitment': commitment,
                        'arguments': value,
                        'request': stripe.request(value, self.stripe_resources(), commitment, DIGEST)}
            with patch.dict(os.environ, {'GITHUB_SHA': '1' * 40, 'GITHUB_RUN_ID': '123',
                                         'GITHUB_RUN_ATTEMPT': '1'}), patch('expand.child', side_effect=review), \
                    patch('expand.time.time', return_value=1000):
                expansion.expand(args)
                binding = json.loads((args.out_dir / 'binding.json').read_bytes())
                self.assertEqual(binding['allowed_actions'], sorted({sha256(canonical(packet['arguments'])) for packet in packets}))
                self.assertEqual(binding['maximum_credential_leases'], 64)
                self.assertEqual(binding['principal_sha256'], sha256(b'raw:synthetic-test-only-actor'))
                self.assertEqual(binding['resources_sha256'], sha256((work / 'resources.json').read_bytes()))
                self.assertEqual(binding['trusted_contexts_sha256'], sorted([
                    sha256(b'synthetic test-only context'), sha256(b'synthetic fresh test-only context')]))
                self.assertFalse(json.loads((args.out_dir / 'oracle-commitments.json').read_bytes())['qualification_issued'])
                original_packets = json.loads(args.packets.read_bytes())
                for problem in ['unused', 'duplicate', 'unknown', 'empty', 'obsolete']:
                    changed = copy.deepcopy(original_packets)
                    if problem == 'unused': changed['trusted_contexts'].append('context-2.cbor')
                    if problem == 'duplicate': changed['trusted_contexts'].append('context-0.cbor')
                    if problem == 'unknown': changed['packets'][0]['trusted_context'] = 'context-2.cbor'
                    if problem == 'empty': changed['trusted_contexts'] = []
                    if problem == 'obsolete': changed['schema'] = 'auths.qualification-public-packets/2'
                    args.packets.write_bytes(canonical(changed))
                    args.out_dir = work / ('refused-context-' + problem)
                    with self.assertRaises(Refusal): expansion.expand(args)
                    self.assertFalse(args.out_dir.exists())
                args.packets.write_bytes(canonical(original_packets))
                args.out_dir = work / 'changed'
                recipe = json.loads((work / 'recipe.json').read_bytes())
                del recipe['credential']['guard']
                (work / 'recipe.json').write_bytes(canonical(recipe))
                with self.assertRaisesRegex(Refusal, 'reviewed-source'):
                    expansion.expand(args)
                self.assertFalse(args.out_dir.exists())
                (work / 'recipe.json').write_bytes((source / 'recipe.json').read_bytes())
                def mismatched_review(binary, arguments):
                    value = review(binary, arguments)
                    if arguments[0] == 'review-submission':
                        value['request']['url'] = 'https://attacker.invalid/write'
                    return value
                with patch('expand.child', side_effect=mismatched_review), self.assertRaisesRegex(Refusal, 'oracle-mismatch'):
                    expansion.expand(args)
                self.assertFalse(args.out_dir.exists())
                (work / 'candidate').write_bytes(b'changed synthetic candidate')
                with self.assertRaisesRegex(Refusal, 'candidate-bytes'):
                    expansion.expand(args)


if __name__ == '__main__':
    unittest.main()
