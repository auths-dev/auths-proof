"""Reconstruct public record resource names from a closed, run-bound ledger."""

import argparse
from pathlib import Path

import airtable_record as airtable
import stripe_platform as stripe
from common import require, text
import resource_io as io


def summary(family, ledger):
    require(type(ledger) is dict, 'qualification.reference.resource-binding')
    run = io.run_id(ledger.get('protected_run'))
    if family == stripe.FAMILY:
        stripe.resources(ledger, run)
        values = ['stripe:test-platform:' + ledger['platform']]
        values += ['stripe:test-payment:' + payment['id'] for payment in ledger['payments']]
    elif family == airtable.FAMILY:
        airtable.resources(ledger, run)
        table = ledger['base'] + '/' + ledger['table']
        values = ['airtable:base:' + ledger['base'], 'airtable:table:' + table]
        values += ['airtable:record:' + table + '/' + record['id'] for record in ledger['records']]
    else:
        require(False, 'qualification.reference.family-unknown')
    # Match the native record's BoundedText<96>. Refuse rather than truncate,
    # hash away, or stringify an arbitrary object supplied by a harness.
    for value in values:
        text(value, maximum=96)
    require(len(values) == len(set(values)) and 1 <= len(values) <= 32,
            'qualification.reference.resource-bound')
    return sorted(values)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--family', required=True)
    parser.add_argument('--resources', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    io.write(args.out, summary(args.family, io.read(args.resources)), new=True)


if __name__ == '__main__':
    io.finish(main)
