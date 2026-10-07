#!/usr/bin/env python3
"""Credential-free installed-author/native-review operator check.

The resource carriers are explicitly synthetic; no provider is contacted and
no qualification is issued. The shipping gateway and installed SDK are real.
"""

import argparse
import json
import os
from pathlib import Path
import select
import re
import subprocess
import time

import airtable_record
import stripe_platform
from common import Refusal, canonical, require, sha256
from expand import child, decode, read
from packet_plan import prepare
from resource_io import finish, write


def response(process):
    require(bool(select.select([process.stdout], [], [], 30)[0]), 'qualification.packets.author-timeout')
    raw = process.stdout.readline(513)
    if not raw:
        _, stderr = process.communicate(timeout=10)
        codes = re.findall(rb'qualification\.[a-z0-9.-]{1,128}', stderr[:65536])
        raise Refusal(codes[-1].decode() if codes else 'qualification.packets.author-refused')
    require(0 < len(raw) <= 512 and raw.endswith(b'\n'), 'qualification.packets.author-response')
    return decode(raw)


def review(binary, work, packet, evaluated_at):
    return child(binary, ['review-submission', '--recipe', work / 'recipe.json',
        '--profile-lock', work / 'profile.lock.json', '--trusted-context', work / packet['trusted_context'],
        '--proof', work / packet['proof'], '--action', work / packet['action'],
        '--evaluated-at', str(evaluated_at)])


def check(args):
    require(not args.work.exists(), 'qualification.packets.output-exists')
    args.work.mkdir(mode=0o700)
    run = 'packet-operator-rehearsal/' + str(int(time.time())) + '/1'
    reports = []
    for reference in [stripe_platform, airtable_record]:
        work = args.work / reference.FAMILY
        work.mkdir(mode=0o700)
        resources = {'schema': 'auths.stripe-platform-qualification-resources/1',
            'protected_run': run, 'platform': 'acct_SYNTHETIC', 'payments': [
                {'id': 'pi_SYNTHETIC', 'amount_received': 2000, 'currency': 'usd',
                 'livemode': False, 'run_metadata': run}]} if reference is stripe_platform else {
            'schema': 'auths.airtable-record-qualification-resources/1', 'protected_run': run,
            'base': airtable_record.BASE, 'table': airtable_record.TABLE, 'records': [
                {'id': 'recTEST0000000001', 'run_metadata': run}]}
        write(work / 'resources.json', resources, new=True)
        prepare(argparse.Namespace(family=reference.FAMILY, resources=work / 'resources.json',
                                   gateway=args.gateway, work=work))
        # Python runs outside the checkout, with no editable package, provider
        # token, home directory, ambient PYTHONPATH or repository import path.
        process = subprocess.Popen([str(args.python), str(Path(__file__).with_name('author_packets.py')),
            '--plan', str(work / 'packet-plan.json'), '--work', str(work), '--serve'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd='/', env={'PATH': '/usr/bin:/bin', 'PYTHONNOUSERSITE': '1'})
        try:
            require(response(process) == {'schema': 'auths.qualification-author-session/1', 'state': 'ready'},
                    'qualification.packets.author-response')
            plan = decode(read(work / 'public-packets.json', 65536))
            reviewed = []
            for packet in plan['packets']:
                value = review(args.gateway, work, packet, plan['evaluated_at'])
                expected = reference.request(packet['arguments'], resources, value['action_commitment'],
                                             packet['arguments']['recipe_digest'])
                require(value['schema'] == 'auths.gateway-submission-review/1'
                        and value['arguments'] == packet['arguments'] and value['request'] == expected,
                        'qualification.packets.oracle-mismatch')
                reviewed.append(value)
            require(plan['trusted_contexts'] == ['context-0.cbor', 'context-1.cbor']
                    and read(work / 'context-0.cbor', 4 * 1024 * 1024)
                        != read(work / 'context-1.cbor', 4 * 1024 * 1024),
                    'qualification.packets.challenge-binding')
            by_label = {packet['label']: (packet, actual) for packet, actual in zip(plan['packets'], reviewed)}
            for phase in ['commissioning', 'live']:
                original_packet, original_review = by_label[phase + '-00']
                fresh_packet, fresh_review = by_label[phase + '-00-fresh']
                require(original_packet['arguments'] == fresh_packet['arguments']
                        and original_packet['trusted_context'] != fresh_packet['trusted_context']
                        and original_review['actors'] == fresh_review['actors'],
                        'qualification.packets.challenge-binding')
            # The old proof must really expire at the ordinary five-minute
            # bound. This is offline review, never a production clock override.
            expired = review(args.gateway, work, plan['packets'][0], plan['not_after'] + 1)
            require(expired.get('schema') != 'auths.gateway-submission-review/1',
                    'qualification.packets.expiry-not-enforced')
            time.sleep(1.05)
            process.stdin.write(canonical({'command': 'refresh', 'label': plan['packets'][0]['label'],
                                          'generation': 1}) + b'\n')
            process.stdin.flush()
            require(response(process)['state'] == 'refreshed', 'qualification.packets.author-response')
            fresh = work / 'refresh-0001'
            # Refresh uses the same reviewed recipe and exact installed trust.
            for name in ['recipe.json', 'profile.lock.json']:
                (fresh / name).write_bytes(read(work / name, 65536))
            fresh_plan = decode(read(fresh / 'public-packets.json', 65536))
            actual = review(args.gateway, fresh, fresh_plan['packets'][0], fresh_plan['evaluated_at'])
            require(actual == reviewed[0]
                    and read(fresh / plan['packets'][0]['trusted_context'], 4 * 1024 * 1024)
                        == read(work / plan['packets'][0]['trusted_context'], 4 * 1024 * 1024)
                    and read(fresh / plan['packets'][0]['action'], 65536) == read(work / plan['packets'][0]['action'], 65536)
                    and read(fresh / plan['packets'][0]['proof'], 4 * 1024 * 1024) != read(work / plan['packets'][0]['proof'], 4 * 1024 * 1024),
                    'qualification.packets.refresh-binding')
            process.stdin.write(b'{"command":"close"}\n')
            process.stdin.flush()
            _, stderr = process.communicate(timeout=10)
            require(process.returncode == 0 and not stderr, 'qualification.packets.author-refused')
            reports.append({'family': reference.FAMILY, 'packet_count': len(reviewed),
                'same_actor_action_request_and_trust_after_refresh': True,
                'fresh_challenges_keep_exact_actor_and_logical_operation': True,
                'original_five_minute_expiry_enforced': True,
                'author': decode(read(work / 'author-report.json', 65536))})
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=10)
    write(args.work / 'report.json', {'schema': 'auths.qualification-packet-operator-rehearsal/1',
        'gateway_sha256': sha256(read(args.gateway, 256 * 1024 * 1024)),
        'synthetic_resources': True, 'provider_contacted': False, 'protected_qualification': False,
        'qualification_issued': False, 'stable_launch_ready': False, 'families': reports}, new=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['gateway', 'python', 'work']:
        parser.add_argument('--' + name, type=lambda value: Path(value).absolute(), required=True)
    args = parser.parse_args()
    finish(lambda: check(args))


if __name__ == '__main__':
    main()
