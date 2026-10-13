"""Prepare/retire owned records only in the reviewed disposable Airtable table."""

import argparse
from pathlib import Path
import urllib.parse

from common import canonical, closed, identifier, integer, require
import airtable_record as reference
import resource_io as io

SCHEMA = 'auths.airtable-resource-preparation/1'
TABLE_PATH = '/v0/' + reference.BASE + '/' + reference.TABLE


class Resources:
    def __init__(self, token, api=None):
        self.token = token
        self.api = api or self.http

    def http(self, method, path, fields=None):
        return io.request('https://api.airtable.com', method, path, self.token,
                          None if fields is None else canonical(fields),
                          {'Content-Type': 'application/json'} if fields is not None else None)

    @staticmethod
    def names(run, count):
        return ['Auths qualification ' + run + ' #' + str(index).zfill(2)
                for index in range(count)]

    def discover(self, names):
        # Names contain no quotes: run grammar is checked before constructing
        # this exact predicate. No unrelated record is downloaded or selected.
        formula = 'OR(' + ','.join("{Name}='" + name + "'" for name in names) + ')'
        value = self.api('GET', TABLE_PATH + '?' + urllib.parse.urlencode({
            'filterByFormula': formula, 'pageSize': 100,
        }))
        require(type(value.get('records')) is list and len(value['records']) <= 64
                and 'offset' not in value, 'qualification.resources.discovery-bound')
        seen = set()
        for record in value['records']:
            record_id = identifier(record.get('id'), r'rec[A-Za-z0-9]{14}')
            require(record_id not in seen and type(record.get('fields')) is dict
                    and record['fields'].get('Name') in names,
                    'qualification.resources.record-binding')
            seen.add(record_id)
        return value['records']

    def journal(self, path):
        value = io.read(path)
        closed(value, ['schema', 'protected_run', 'base', 'table', 'count', 'retired'])
        require(value['schema'] == SCHEMA and value['base'] == reference.BASE
                and value['table'] == reference.TABLE and type(value['retired']) is bool,
                'qualification.resources.ledger-binding')
        io.run_id(value['protected_run'])
        integer(value['count'], 1, 32)
        return value

    def prepare(self, run, count, journal, output):
        io.run_id(run)
        integer(count, 1, 32)
        journal, output = Path(journal), Path(output)
        require(not output.exists(), 'qualification.resources.output-exists')
        if journal.exists():
            value = self.journal(journal)
            require(value['protected_run'] == run and value['count'] == count
                    and not value['retired'], 'qualification.resources.ledger-binding')
        else:
            value = {'schema': SCHEMA, 'protected_run': run, 'base': reference.BASE,
                     'table': reference.TABLE, 'count': count, 'retired': False}
            # The complete ownership predicate is durable before a POST. This
            # also covers a lost creation response or interruption before save.
            io.write(journal, value, new=True)
        names = self.names(run, count)
        existing = self.discover(names)
        indexed = {}
        for record in existing:
            name = record['fields']['Name']
            require(name not in indexed, 'qualification.resources.ambiguous-record')
            indexed[name] = record
        for name in names:
            if name in indexed:
                continue
            record = self.api('POST', TABLE_PATH, {'fields': {'Name': name, 'DemoStatus': 'Pending'}})
            identifier(record.get('id'), r'rec[A-Za-z0-9]{14}')
            require(type(record.get('fields')) is dict and record['fields'].get('Name') == name
                    and record['fields'].get('DemoStatus') == 'Pending',
                    'qualification.resources.record-binding')
        # The fresh query, rather than a successful POST or remembered locator,
        # determines the exact records the qualification ledger may expose.
        fresh = self.discover(names)
        require(len(fresh) == count and {record['fields']['Name'] for record in fresh} == set(names),
                'qualification.resources.ambiguous-record')
        ledger = {'schema': 'auths.airtable-record-qualification-resources/1',
                  'protected_run': run, 'base': reference.BASE, 'table': reference.TABLE,
                  'records': [{'id': record['id'], 'run_metadata': run}
                              for record in sorted(fresh, key=lambda record: record['fields']['Name'])]}
        reference.resources(ledger, run)
        io.write(output, ledger, new=True)

    def cleanup(self, journal):
        value = self.journal(journal)
        if value['retired']:
            return
        names = self.names(value['protected_run'], value['count'])
        # Includes ambiguous creations not retained in the public ledger. Even
        # duplicate owned names are retired; no unrelated record is touched.
        for record in self.discover(names):
            fresh = self.api('GET', TABLE_PATH + '/' + record['id'])
            require(fresh.get('id') == record['id'] and type(fresh.get('fields')) is dict
                    and fresh['fields'].get('Name') == record['fields']['Name'],
                    'qualification.resources.record-binding')
            removed = self.api('DELETE', TABLE_PATH + '/' + record['id'])
            require(removed.get('id') == record['id'] and removed.get('deleted') is True,
                    'qualification.resources.cleanup-refused')
        require(not self.discover(names), 'qualification.resources.cleanup-unconfirmed')
        value['retired'] = True
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
    resources = Resources(io.credentials({'token': 'pat'})['token'])
    if args.command == 'prepare':
        resources.prepare(args.protected_run, args.count, args.journal, args.out)
    else:
        resources.cleanup(args.journal)
    print('qualification.resources.' + args.command + '-complete')


if __name__ == '__main__':
    io.finish(main)
