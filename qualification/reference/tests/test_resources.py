"""Disposable setup recovery and ownership boundaries; synthetic providers only."""

import copy
import contextlib
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import airtable_resources as airtable
import resource_io
import stripe_resources as stripe
from common import Refusal

RUN = 'recipe-qualification/123/1'


class Stripe:
    def __init__(self):
        self.payments = {}
        self.charges = {}
        self.keys = {}
        self.refunds = 0
        self.lose_create = False

    def api(self, method, path, fields=None, idempotency=None, runtime=False):
        if path == '/v1/account':
            return {'id': 'acct_SYNTHETIC'}
        if path == '/v1/balance':
            return {'livemode': False}
        if path == '/v1/payment_intents':
            assert method == 'POST' and fields['payment_method'] == 'pm_card_visa'
            if idempotency in self.keys:
                return copy.deepcopy(self.payments[self.keys[idempotency]])
            number = str(len(self.payments) + 1)
            payment_id, charge_id = 'pi_SYNTHETIC' + number, 'ch_SYNTHETIC' + number
            payment = {'id': payment_id, 'livemode': False, 'status': 'succeeded',
                       'amount': 2000, 'amount_received': 2000, 'currency': 'usd',
                       'metadata': {'auths_qualification': fields['metadata[auths_qualification]']},
                       'latest_charge': charge_id}
            self.payments[payment_id] = payment
            self.keys[idempotency] = payment_id
            self.charges[charge_id] = {'id': charge_id, 'payment_intent': payment_id,
                                      'livemode': False, 'amount': 2000,
                                      'amount_refunded': 0, 'refunded': False}
            if self.lose_create:
                self.lose_create = False
                raise Refusal('synthetic-lost-response')
            return copy.deepcopy(payment)
        if path.startswith('/v1/payment_intents/'):
            return copy.deepcopy(self.payments[path.rsplit('/', 1)[1]])
        if path.startswith('/v1/charges/'):
            return copy.deepcopy(self.charges[path.rsplit('/', 1)[1]])
        assert method == 'POST' and path == '/v1/refunds'
        payment = self.payments[fields['payment_intent']]
        charge = self.charges[payment['latest_charge']]
        assert 0 < fields['amount'] <= 2000 - charge['amount_refunded']
        self.refunds += 1
        charge['amount_refunded'] += fields['amount']
        charge['refunded'] = charge['amount_refunded'] == 2000
        return {'status': 'succeeded', 'payment_intent': payment['id']}


class Airtable:
    def __init__(self):
        self.records = {'recUNRELATED00001': {'id': 'recUNRELATED00001',
                        'fields': {'Name': 'Unrelated owner record', 'DemoStatus': 'Pending'}}}
        self.deleted = []
        self.lose_create = False
        self.change_before_delete = False

    def api(self, method, path, fields=None):
        assert path.startswith(airtable.TABLE_PATH)
        if method == 'GET' and '?' in path:
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
            names = re.findall(r"\{Name\}='([^']+)'", query['filterByFormula'][0])
            assert names
            return {'records': copy.deepcopy([record for record in self.records.values()
                    if record['fields']['Name'] in names])}
        if method == 'POST':
            record_id = 'recSYNTHETIC' + str(len(self.records)).zfill(5)
            record = {'id': record_id, 'fields': copy.deepcopy(fields['fields'])}
            self.records[record_id] = record
            if self.lose_create:
                self.lose_create = False
                raise Refusal('synthetic-lost-response')
            return copy.deepcopy(record)
        record_id = path.rsplit('/', 1)[1]
        if method == 'GET':
            result = copy.deepcopy(self.records[record_id])
            if self.change_before_delete:
                result['fields']['Name'] = 'Changed ownership'
            return result
        assert method == 'DELETE'
        self.deleted.append(record_id)
        del self.records[record_id]
        return {'id': record_id, 'deleted': True}


class Resources(unittest.TestCase):
    def test_airtable_pacing_preserves_spacing_after_oversleep_and_idle(self):
        clock, waits = [100.0], []

        def sleep(delay):
            waits.append(delay)
            clock[0] += delay + 0.25

        with patch.object(resource_io, '_airtable_next', 0.0), \
             patch.object(resource_io.time, 'monotonic', lambda: clock[0]), \
             patch.object(resource_io.time, 'sleep', sleep):
            resource_io.pace_airtable()
            self.assertFalse(waits)
            resource_io.pace_airtable()
            self.assertAlmostEqual(waits[0], resource_io.AIRTABLE_INTERVAL)
            second_start = clock[0]
            resource_io.pace_airtable()
            self.assertGreaterEqual(clock[0] - second_start, resource_io.AIRTABLE_INTERVAL)
            clock[0] += 10
            resource_io.pace_airtable()
            self.assertEqual(len(waits), 2, 'idle source traffic consumes no catch-up burst')

    def workspace(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        work = Path(temporary.name)
        os.chmod(work, 0o700)
        return work

    def test_stripe_lost_creation_response_replays_only_the_same_test_fixture(self):
        work, provider = self.workspace(), Stripe()
        resources = stripe.Resources({}, provider.api)
        provider.lose_create = True
        with self.assertRaises(Refusal):
            resources.prepare(RUN, 1, work / 'journal.json', work / 'resources.json')
        self.assertFalse((work / 'resources.json').exists())
        self.assertEqual(len(provider.payments), 1)
        resources.cleanup(work / 'journal.json')
        self.assertEqual(len(provider.payments), 1, 'same idempotency key recovers the pending response')
        self.assertEqual(provider.refunds, 1)
        resources.cleanup(work / 'journal.json')
        self.assertEqual(provider.refunds, 1, 'retired cleanup is idempotent')

    def test_stripe_setup_and_cleanup_refuse_changed_owner_and_live_mode(self):
        work, provider = self.workspace(), Stripe()
        resources = stripe.Resources({}, provider.api)
        resources.prepare(RUN, 2, work / 'journal.json', work / 'resources.json')
        self.assertEqual(len(resource_io.read(work / 'resources.json')['payments']), 2)
        payment = next(iter(provider.payments.values()))
        payment['metadata']['auths_qualification'] = 'another-run'
        with self.assertRaises(Refusal): resources.cleanup(work / 'journal.json')
        self.assertEqual(provider.refunds, 0)
        payment['metadata']['auths_qualification'] = RUN
        payment['livemode'] = True
        with self.assertRaises(Refusal): resources.cleanup(work / 'journal.json')
        self.assertEqual(provider.refunds, 0)
        payment['livemode'] = False
        resources.cleanup(work / 'journal.json')
        self.assertEqual(provider.refunds, 2)

    def test_airtable_partial_setup_cleanup_discovers_only_owned_records(self):
        work, provider = self.workspace(), Airtable()
        resources = airtable.Resources('synthetic', provider.api)
        provider.lose_create = True
        with self.assertRaises(Refusal):
            resources.prepare(RUN, 2, work / 'journal.json', work / 'resources.json')
        resources.cleanup(work / 'journal.json')
        self.assertEqual(set(provider.records), {'recUNRELATED00001'})
        self.assertEqual(len(provider.deleted), 1)
        resources.cleanup(work / 'journal.json')
        self.assertEqual(len(provider.deleted), 1)

    def test_airtable_changed_ownership_and_duplicate_names_cannot_qualify(self):
        work, provider = self.workspace(), Airtable()
        resources = airtable.Resources('synthetic', provider.api)
        resources.prepare(RUN, 1, work / 'journal.json', work / 'resources.json')
        provider.change_before_delete = True
        with self.assertRaises(Refusal): resources.cleanup(work / 'journal.json')
        self.assertFalse(provider.deleted)
        provider.change_before_delete = False
        owned = next(record for record in provider.records.values() if record['fields']['Name'].startswith('Auths'))
        provider.records['recDUPLICATE00001'] = dict(copy.deepcopy(owned), id='recDUPLICATE00001')
        with self.assertRaises(Refusal):
            resources.prepare(RUN, 1, work / 'journal.json', work / 'another-output.json')
        self.assertFalse((work / 'another-output.json').exists())
        resources.cleanup(work / 'journal.json')
        self.assertEqual(set(provider.records), {'recUNRELATED00001'})

    def test_cli_reports_closed_domain_codes_without_external_exception_text(self):
        for error, expected in [(Refusal('qualification.resources.payment-binding'),
                                 'qualification.resources.payment-binding'),
                                (ValueError('synthetic-sensitive-external-detail'),
                                 'qualification.resources.refused'),
                                (Refusal('synthetic-sensitive-external-detail'),
                                 'qualification.resources.refused')]:
            def fail(): raise error
            output = io.StringIO()
            with contextlib.redirect_stderr(output), self.assertRaises(SystemExit):
                resource_io.finish(fail)
            self.assertEqual(output.getvalue().strip(), expected)

    def test_ledger_outputs_refuse_symlinks_public_directories_and_overwrite(self):
        work = self.workspace()
        target = work / 'target.json'
        target.write_text('{}')
        linked = work / 'linked.json'
        linked.symlink_to(target)
        with self.assertRaises(OSError): resource_io.read(linked)
        with self.assertRaises(Refusal): resource_io.write(linked, {})
        with self.assertRaises(OSError): resource_io.write(target, {}, new=True)
        os.chmod(work, 0o755)
        with self.assertRaises(Refusal): resource_io.write(work / 'new.json', {}, new=True)


if __name__ == '__main__':
    unittest.main()
