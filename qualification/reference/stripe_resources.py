"""Create and retire only this run's platform-account Stripe test payments."""

import argparse
import hashlib
import time
import urllib.parse
from pathlib import Path

from common import closed, identifier, integer, require
import resource_io as io
import stripe_platform as reference

SCHEMA = 'auths.stripe-platform-resource-preparation/1'


def key(run, index, operation):
    return 'auths-resource-' + hashlib.sha256(
        (run + '\0' + str(index) + '\0' + operation).encode()).hexdigest()


class Resources:
    def __init__(self, keys, api=None):
        self.keys = keys
        self.api = api or self.http

    def http(self, method, path, fields=None, idempotency=None, runtime=False):
        headers = {'Stripe-Version': '2025-03-31.basil'}
        if idempotency:
            headers['Idempotency-Key'] = idempotency
        body = None
        if fields is not None:
            body = urllib.parse.urlencode(fields).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        return io.request('https://api.stripe.com', method, path,
                          self.keys['runtime' if runtime else 'setup'], body, headers)

    def account(self):
        platform = self.api('GET', '/v1/account', runtime=True).get('id')
        identifier(platform, r'acct_[A-Za-z0-9]{1,64}')
        require(self.api('GET', '/v1/account').get('id') == platform
                and self.api('GET', '/v1/balance', runtime=True).get('livemode') is False,
                'qualification.resources.platform-binding')
        return platform

    def create(self, run, index):
        return self.api('POST', '/v1/payment_intents', {
            'amount': 2000, 'currency': 'usd', 'payment_method': 'pm_card_visa',
            'confirm': 'true', 'automatic_payment_methods[enabled]': 'true',
            'automatic_payment_methods[allow_redirects]': 'never',
            'metadata[auths_qualification]': run,
        }, idempotency=key(run, index, 'prepare'))

    @staticmethod
    def payment(value, run, payment_id):
        require(value.get('id') == payment_id and value.get('livemode') is False
                and value.get('status') == 'succeeded' and value.get('amount') == 2000
                and value.get('amount_received') == 2000 and value.get('currency') == 'usd'
                and type(value.get('metadata')) is dict
                and value['metadata'].get('auths_qualification') == run,
                'qualification.resources.payment-binding')

    def journal(self, path):
        value = io.read(path)
        closed(value, ['schema', 'protected_run', 'platform', 'created_at', 'entries'])
        require(value['schema'] == SCHEMA and self.account() == value['platform'],
                'qualification.resources.ledger-binding')
        io.run_id(value['protected_run'])
        integer(value['created_at'], 1, int(time.time()))
        require(type(value['entries']) is list and 1 <= len(value['entries']) <= 32,
                'qualification.resources.resource-bound')
        seen = set()
        for entry in value['entries']:
            closed(entry, ['id', 'retired'])
            require(type(entry['retired']) is bool, 'qualification.resources.ledger-binding')
            if entry['id'] is not None:
                identifier(entry['id'], r'pi_[A-Za-z0-9]{1,128}')
                require(entry['id'] not in seen, 'qualification.resources.duplicate-payment')
                seen.add(entry['id'])
        return value

    def prepare(self, run, count, journal, output):
        io.run_id(run)
        integer(count, 1, 32)
        journal, output = Path(journal), Path(output)
        require(not output.exists(), 'qualification.resources.output-exists')
        if journal.exists():
            value = self.journal(journal)
            require(value['protected_run'] == run and len(value['entries']) == count
                    and not any(entry['retired'] for entry in value['entries']),
                    'qualification.resources.ledger-binding')
        else:
            value = {'schema': SCHEMA, 'protected_run': run, 'platform': self.account(),
                     'created_at': int(time.time()),
                     'entries': [{'id': None, 'retired': False} for _ in range(count)]}
            io.write(journal, value, new=True)
        # A pending provider response may be recovered only within its finite
        # idempotency window; an old journal must never create a duplicate.
        require(int(time.time()) - value['created_at'] <= 3600,
                'qualification.resources.preparation-expired')
        payments = []
        for index, entry in enumerate(value['entries']):
            payment = self.create(run, index) if entry['id'] is None else self.api(
                'GET', '/v1/payment_intents/' + entry['id'])
            payment_id = identifier(payment.get('id'), r'pi_[A-Za-z0-9]{1,128}')
            entry['id'] = payment_id
            io.write(journal, value)
            self.payment(payment, run, payment_id)
            payments.append({'id': payment_id, 'amount_received': 2000, 'currency': 'usd',
                             'livemode': False, 'run_metadata': run})
        ledger = {'schema': 'auths.stripe-platform-qualification-resources/1',
                  'protected_run': run, 'platform': value['platform'], 'payments': payments}
        reference.resources(ledger, run)
        io.write(output, ledger, new=True)

    def cleanup(self, journal):
        value = self.journal(journal)
        run = value['protected_run']
        for index, entry in enumerate(value['entries']):
            if entry['retired']:
                continue
            if entry['id'] is None:
                # Replay only this run's pre-journaled test intent after an
                # ambiguous preparation response. It may create then retire
                # that one test fixture; it never searches unrelated payments.
                require(int(time.time()) - value['created_at'] <= 3600,
                        'qualification.resources.preparation-expired')
                created = self.create(run, index)
                entry['id'] = identifier(created.get('id'), r'pi_[A-Za-z0-9]{1,128}')
                io.write(journal, value)
            payment = self.api('GET', '/v1/payment_intents/' + entry['id'])
            self.payment(payment, run, entry['id'])
            charge_id = identifier(payment.get('latest_charge'), r'ch_[A-Za-z0-9]{1,128}')
            charge = self.api('GET', '/v1/charges/' + charge_id)
            require(charge.get('id') == charge_id and charge.get('payment_intent') == entry['id']
                    and charge.get('livemode') is False and charge.get('amount') == 2000,
                    'qualification.resources.charge-binding')
            remaining = 2000 - integer(charge.get('amount_refunded'), 0, 2000)
            if remaining:
                refund = self.api('POST', '/v1/refunds', {
                    'payment_intent': entry['id'], 'amount': remaining,
                    'metadata[auths_qualification_cleanup]': run,
                }, idempotency=key(run, index, 'cleanup-' + str(remaining)))
                require(refund.get('status') == 'succeeded' and refund.get('livemode', False) is False
                        and refund.get('payment_intent') == entry['id'],
                        'qualification.resources.cleanup-refused')
            fresh = self.api('GET', '/v1/charges/' + charge_id)
            require(fresh.get('livemode') is False and fresh.get('payment_intent') == entry['id']
                    and fresh.get('amount_refunded') == 2000 and fresh.get('refunded') is True,
                    'qualification.resources.cleanup-unconfirmed')
            entry['retired'] = True
            io.write(journal, value)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    prepare = sub.add_parser('prepare')
    prepare.add_argument('--protected-run', required=True)
    prepare.add_argument('--count', type=int, default=1)
    prepare.add_argument('--out', type=Path, required=True)
    for command in [prepare, sub.add_parser('cleanup')]:
        command.add_argument('--journal', type=Path, required=True)
    args = parser.parse_args()
    resources = Resources(io.credentials({'setup': 'sk_test_', 'runtime': 'rk_test_'}))
    if args.command == 'prepare':
        resources.prepare(args.protected_run, args.count, args.journal, args.out)
    else:
        resources.cleanup(args.journal)
    print('qualification.resources.' + args.command + '-complete')


if __name__ == '__main__':
    io.finish(main)
