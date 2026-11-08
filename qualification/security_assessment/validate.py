#!/usr/bin/env python3
"""Refuse missing, duplicated, failed or misattributed AP075 execution evidence."""
import argparse
import json
from pathlib import Path


def validate(boundary, comparison, inventory, expected_head):
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
    if positive.get('provider_write_requests') != 1 or positive.get('distinct_effects_in_interval') != 1:
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
    parser.add_argument('--inventory', type=Path, default=Path(__file__).with_name('inventory.json'))
    parser.add_argument('--head', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = validate(json.loads(args.boundary.read_text()), json.loads(args.comparison.read_text()),
                      json.loads(args.inventory.read_text()), args.head)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
