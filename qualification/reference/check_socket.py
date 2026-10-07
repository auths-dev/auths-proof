#!/usr/bin/env python3
"""Exercise the real installed author under a separate Linux UID.

Uses synthetic resources and no provider/network/qualification authority.
The root controller reconnects between steps, as a protected Actions runner
will after waiting for a signing artifact. Only public bytes leave the author.
"""

import argparse
import os
from pathlib import Path
import subprocess
import time

import airtable_record
import stripe_platform
from author_socket import exchange, refresh
from check_packets import review
from common import require, sha256
from expand import decode, read
from packet_plan import prepare, public_pool
from resource_io import finish, write

AUTHOR_UID = 62002


def isolate():
    os.setgroups([])
    os.setgid(AUTHOR_UID)
    os.setuid(AUTHOR_UID)


def ready(process, work):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        require(process.poll() is None, 'qualification.packets.author-refused')
        if (work / 'author.sock').exists():
            exchange(work, 'inspect')
            return
        time.sleep(0.1)
    require(False, 'qualification.packets.author-timeout')


def check(args):
    require(os.getuid() == 0 and not args.work.exists(), 'qualification.packets.socket-isolation')
    args.work.mkdir(mode=0o700)
    reports = []
    for reference in [stripe_platform, airtable_record]:
        work = args.work / reference.FAMILY
        work.mkdir(mode=0o700)
        run = 'socket-operator-rehearsal/' + str(int(time.time())) + '/1'
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
        # All author inputs are public, and every private ancestor belongs to
        # the dedicated author. Its UID has no access to the controller's
        # root-owned credential files or process environment.
        for path in work.iterdir():
            os.chown(path, AUTHOR_UID, AUTHOR_UID)
        os.chown(work, AUTHOR_UID, AUTHOR_UID)
        os.chown(args.work, AUTHOR_UID, AUTHOR_UID)
        process = subprocess.Popen([str(args.python), str(Path(__file__).with_name('author_socket.py')),
            'serve', '--plan', str(work / 'packet-plan.json'), '--work', str(work)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd='/', env={'PATH': '/usr/bin:/bin', 'PYTHONNOUSERSITE': '1'}, preexec_fn=isolate)
        try:
            ready(process, work)
            original = decode(read(work / 'public-packets.json', 65536))
            public_pool(reference.FAMILY, resources, original['packets'][0]['arguments']['recipe_digest'], original)
            initial = review(args.gateway, work, original['packets'][0], original['evaluated_at'])
            # Separate connections and fresh output directories simulate the
            # runner handing public packets across independent job steps.
            for generation, packet in enumerate(original['packets'], 1):
                destination = args.work / (reference.FAMILY + '-public-' + str(generation))
                refresh(work, packet['label'], destination)
                fresh = decode(read(destination / 'public-packets.json', 65536))
                for name in ['recipe.json', 'profile.lock.json']:
                    (destination / name).write_bytes(read(work / name, 65536))
                actual = review(args.gateway, destination, fresh['packets'][0], fresh['evaluated_at'])
                expected = reference.request(packet['arguments'], resources,
                                             actual['action_commitment'], packet['arguments']['recipe_digest'])
                require(actual['request'] == expected and actual['actors'] == initial['actors'],
                        'qualification.packets.refresh-binding')
                require(exchange(work, 'inspect')['generation'] == generation,
                        'qualification.packets.generation')
            exchange(work, 'close')
            process.wait(timeout=10)
            require(process.returncode == 0 and not (work / 'author.sock').exists(),
                    'qualification.packets.author-refused')
            reports.append({'family': reference.FAMILY, 'author_uid': AUTHOR_UID,
                'controller_uid': 0, 'separate_connections': len(original['packets']),
                'same_actor_action_request_and_trust': True, 'socket_removed_on_close': True})
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
            os.chown(args.work, 0, 0)
    write(args.report, {'schema': 'auths.qualification-author-socket-rehearsal/1',
        'gateway_sha256': sha256(read(args.gateway, 256 * 1024 * 1024)),
        'synthetic_resources': True, 'provider_contacted': False,
        'protected_qualification': False, 'qualification_issued': False,
        'stable_launch_ready': False, 'families': reports}, new=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['gateway', 'python', 'work', 'report']:
        parser.add_argument('--' + name, type=lambda value: Path(value).absolute(), required=True)
    args = parser.parse_args()
    finish(lambda: check(args))


if __name__ == '__main__':
    main()
