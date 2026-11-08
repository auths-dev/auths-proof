#!/usr/bin/env python3
"""Refuse missing, duplicated, failed or misattributed AP075 execution evidence."""
import argparse
import json
from pathlib import Path


def validate_operations(value, inventory, head, binary):
    rows = value.get('cases', [])
    ids = [row['id'] for row in rows]
    if (value.get('schema') != 'auths.security-assessment-operations/1'
            or value.get('target_revision') != head or value.get('binary_sha256') != binary
            or value.get('native_policy_replaced') is not False
            or value.get('production_qualification') is not False
            or value.get('attacker_uid') != 62004 or value.get('backend') != 'file'
            or len(inventory['operations_cases']) != len(set(inventory['operations_cases']))
            or len(ids) != len(set(ids)) or set(ids) != set(inventory['operations_cases'])):
        raise ValueError('operational evidence inventory/source/boundary mismatch')
    if any(row.get('status') != 'pass' or row.get('target_revision') != head
           or type(row.get('provider_write_requests')) is not int
           or type(row.get('distinct_effects_in_interval')) is not int
           or row['provider_write_requests'] != 1 or row.get('distinct_effects_in_interval') != 1
           for row in rows):
        raise ValueError('operational drill failed or lacks one independently observed effect')
    return len(rows)


def validate(boundary, comparison, inventory, expected_head):
    if (inventory.get('schema') != 'auths.security-assessment-execution-inventory/1'
            or len(inventory['stripe_probe_cases']) != len(set(inventory['stripe_probe_cases']))
            or len(inventory['baseline_cases']) != len(set(inventory['baseline_cases']))):
        raise ValueError('invalid or duplicated expected execution inventory')
    if (boundary.get('schema') != 'auths.security-assessment-stripe/1'
            or boundary.get('target_revision') != expected_head
            or boundary.get('attacker_uid') != 62004
            or boundary.get('native_policy_replaced') is not False
            or boundary.get('production_qualification') is not False):
        raise ValueError('target, identity or claim mismatch')
    rows = boundary.get('cases', [])
    names = [row['id'] for row in rows]
    expected = inventory['stripe_probe_cases']
    if len(names) != len(set(names)) or set(names) != set(expected):
        raise ValueError('missing, duplicated or unexpected case execution')
    if any(row.get('status') != 'pass' or row.get('target_revision') != expected_head
           or row.get('backend') != 'file' for row in rows):
        raise ValueError('case failed or has wrong source/backend')
    positive = next(row for row in rows if row['id'] == inventory['positive_control'])
    if (type(positive.get('provider_write_requests')) is not int
            or type(positive.get('distinct_effects_in_interval')) is not int
            or positive['provider_write_requests'] != 1 or positive['distinct_effects_in_interval'] != 1):
        raise ValueError('positive control did not reach one effect')
    if comparison.get('schema') != 'auths.security-assessment-comparison/1':
        raise ValueError('missing baseline report')
    base = comparison.get('baseline_cases', [])
    actual = [row['case'] for row in base]
    if (len(actual) != len(set(actual)) or set(actual) != set(inventory['baseline_cases'])
            or any(row.get('status') != 'pass' for row in base)
            or comparison.get('commercial_demand_validated') is not False):
        raise ValueError('incomplete baseline or unsupported market claim')
    return {'schema': 'auths.security-assessment-census/1', 'target_revision': expected_head,
            'independent_transport_cases': len(rows), 'baseline_cases': len(base),
            'zero_missing_or_duplicate_cases': True, 'production_qualification': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--boundary', type=Path, required=True)
    parser.add_argument('--comparison', type=Path, required=True)
    parser.add_argument('--operations', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, default=Path(__file__).with_name('inventory.json'))
    parser.add_argument('--head', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    boundary = json.loads(args.boundary.read_text())
    inventory = json.loads(args.inventory.read_text())
    report = validate(boundary, json.loads(args.comparison.read_text()), inventory, args.head)
    report['operational_drills'] = validate_operations(json.loads(args.operations.read_text()),
                                                     inventory, args.head, boundary['binary_sha256'])
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
