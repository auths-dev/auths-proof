#!/usr/bin/env python3
"""Private fixed-phase IPC for one hosted operator, across workflow steps.

Only the root peer can advance the source-owned sequence or request its status.
Commands cannot select scripts, packets, expectations or secret destinations.
The artifact reader is a separate credential-minimal source-owned process.
"""

import argparse
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time
from types import SimpleNamespace

from common import canonical, closed, Refusal, require, sha256
import controller_socket as controller
from expand import read
from production_journey import Journey, PHASES, GITHUB_INPUTS
from resource_io import finish, write_bytes

import artifact_wait
import scan_publication

REQUEST = 'auths.qualification-journey-command/1'
REPLY = 'auths.qualification-journey-reply/1'
COMMANDS = [*PHASES, 'status', 'abort']
INPUT_NAMES = ['family', 'root', 'binary', 'issuer', 'python', 'kit', 'wheel', 'node', 'script', 'package',
               'exports', 'runner_uid', 'runner_gid']
PROVIDER_NAMES = ['STRIPE_QUALIFICATION_SETUP_KEY', 'STRIPE_QUALIFICATION_RUNTIME_KEY',
    'STRIPE_QUALIFICATION_NEXT_RUNTIME_KEY', 'AIRTABLE_QUALIFICATION_TOKEN', 'AIRTABLE_QUALIFICATION_NEXT_TOKEN']


def checked_command(value, family):
    closed(value, ['schema', 'family', 'command'])
    require(value['schema'] == REQUEST and value['family'] == family and value['command'] in COMMANDS,
            'qualification.journey.command')
    return value['command']


def endpoint(root, existing=True):
    return controller.endpoint(Path(root).absolute() / 'control/session.sock', existing=existing)


def call(root, family, command):
    request = {'schema': REQUEST, 'family': family, 'command': command}
    checked_command(request, family)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3600)
        connection.connect(str(endpoint(root)))
        controller.peer(connection)
        connection.sendall(canonical(request) + b'\n')
        reply = controller.receive(connection, 4096)
    closed(reply, ['schema', 'ok', 'code', 'family', 'not_after', 'next_phase', 'retired'])
    require(reply['schema'] == REPLY and type(reply['ok']) is bool and reply['family'] == family
            and type(reply['not_after']) is int and type(reply['next_phase']) is int
            and 0 <= reply['next_phase'] <= len(PHASES) and type(reply['retired']) is bool,
            'qualification.journey.reply')
    if not reply['ok']:
        code = reply['code']
        require(type(code) is str and re.fullmatch(r'qualification\.[a-z0-9.-]{1,128}', code),
                'qualification.journey.reply')
        raise Refusal(code)
    require(reply['code'] is None, 'qualification.journey.reply')
    return reply


def export(journey, kind, destination, owner, group):
    require(kind in ['commissioning-inputs', 'first-proposal', 'final-proposal']
            and not destination.exists() and not destination.is_symlink(),
            'qualification.journey.export-directory')
    journey.scan()
    if kind == 'commissioning-inputs':
        from expand import decode
        carrier = decode(read(journey.work / 'public-packets.json', 65536))
        names = {name: name for name in ['tuple.json', 'recipe.json', 'profile.lock.json', 'resources.json']}
        names.update({'offline/' + member + '.json': 'offline/' + member + '.json'
                      for member in ['conformance', 'differential']})
        packets = ['public-packets.json', *carrier['trusted_contexts']]
        packets += [packet[field] for packet in carrier['packets'] for field in ['proof', 'action']]
        names.update({'packets/' + name: name for name in packets})
    else:
        inventory = scan_publication.sources(journey.work / 'proposal')
        names = {name: 'proposal/' + name for name, _kind, _digest in inventory}
    require(0 < len(names) <= scan_publication.MAX_FILES, 'qualification.journey.export-bound')
    destination.mkdir(mode=0o700)
    expected = {}
    try:
        for name, source in sorted(names.items()):
            output = destination / name
            output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            payload = read(journey.work / source, scan_publication.MAX_BYTES)
            require(all(canary not in payload for canary in journey.canaries), 'qualification.journey.secret-exposed')
            write_bytes(output, payload, new=True)
            expected[name] = sha256(payload)
        inventory = scan_publication.sources(destination)
        require({name: digest for name, _kind, digest in inventory} == expected,
                'qualification.journey.export-changed')
        # Scan these actual retained copies, including encoded secret forms,
        # before allowing the runner to read or upload them.
        scan = [journey.issuer, 'stage-redaction', '--canaries', journey.work / 'canaries']
        for name in sorted(names):
            scan += ['--source', 'evidence=' + str(destination / name)]
        journey.call([*scan, '--out', journey.controller / ('export-' + kind + '.json')])
        require(scan_publication.sources(destination) == inventory, 'qualification.journey.export-changed')
        for parent, directories, files in os.walk(destination, topdown=False):
            for name in files:
                os.chown(Path(parent) / name, owner, group)
            for name in directories:
                os.chown(Path(parent) / name, owner, group)
        os.chown(destination, owner, group)
    except BaseException:
        import shutil
        shutil.rmtree(destination)
        raise


def serve(args):
    journey = Journey(args.family, args.root, args.binary, args.issuer, args.python, args.kit,
                      args.wheel, args.node, args.script, args.package, os.environ)
    exports = Path(args.exports).absolute()
    require(not exports.exists() and exports.resolve() == exports and not exports.is_relative_to(journey.root)
            and type(args.runner_uid) is int and 0 < args.runner_uid < (1 << 32) - 1
            and type(args.runner_gid) is int and 0 < args.runner_gid < (1 << 32) - 1,
            'qualification.journey.export-directory')
    exports.mkdir(mode=0o700)
    os.chown(exports, args.runner_uid, args.runner_gid)
    stopping, complete = False, False
    def interrupted(_signal, _frame):
        nonlocal stopping
        stopping = True
    for number in [signal.SIGTERM, signal.SIGINT]:
        signal.signal(number, interrupted)
    path = endpoint(args.root, existing=False)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(path))
            os.chmod(path, 0o600)
            inode = os.lstat(path).st_ino
            server.listen(1)
            server.settimeout(0.25)
            while not stopping and time.monotonic() < journey.deadline:
                try:
                    connection, _ = server.accept()
                except socket.timeout:
                    continue
                with connection:
                    connection.settimeout(3600)
                    code = None
                    try:
                        controller.peer(connection)
                        command = checked_command(controller.receive(connection, 4096), args.family)
                        if command == 'abort':
                            journey.abort()
                            stopping = True
                        elif command != 'status':
                            journey.advance(command)
                            kind = {'prepare': 'commissioning-inputs', 'commission': 'first-proposal',
                                    'final-proposal': 'final-proposal'}.get(command)
                            if kind is not None:
                                export(journey, kind, exports / kind, args.runner_uid, args.runner_gid)
                            if command == 'final-proposal':
                                # Copies were separately scanned with the
                                # retained canaries; now remove them locally.
                                (journey.work / 'canaries').unlink()
                                complete, stopping = True, True
                    except (Refusal, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                        code = str(error) if isinstance(error, Refusal) else 'qualification.journey.refused'
                        if re.fullmatch(r'qualification\.[a-z0-9.-]{1,128}', code) is None:
                            code = 'qualification.journey.refused'
                        journey.failed = True
                        stopping = True
                    reply = {'schema': REPLY, 'ok': code is None, 'code': code, 'family': journey.family,
                        'not_after': journey.not_after, 'next_phase': journey.next_phase, 'retired': journey.retired}
                    try:
                        connection.sendall(canonical(reply) + b'\n')
                    except OSError:
                        journey.failed, stopping, complete = True, True, False
            if path.exists() and os.lstat(path).st_ino == inode:
                path.unlink()
        require(complete, 'qualification.journey.not-complete')
    finally:
        if not complete:
            journey.abort()


def start(args):
    require(os.getuid() == 0 and not args.root.exists(), 'qualification.journey.identity')
    environment = {name: os.environ[name] for name in [*GITHUB_INPUTS,
        'ACTIONS_ID_TOKEN_REQUEST_URL', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN']}
    environment.update({name: os.environ[name] for name in PROVIDER_NAMES if name in os.environ})
    environment['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    if 'RUNNER_TRACKING_ID' in os.environ:
        environment['RUNNER_TRACKING_ID'] = os.environ['RUNNER_TRACKING_ID']
    arguments = [sys.executable, '-B', str(Path(__file__).absolute()), 'serve']
    for name in INPUT_NAMES:
        arguments += ['--' + name.replace('_', '-'), str(getattr(args, name))]
    process = subprocess.Popen(arguments, env=environment, cwd='/', stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    started = False
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            require(process.poll() is None, 'qualification.journey.session-not-started')
            if (args.root / 'control/session.sock').exists():
                call(args.root, args.family, 'status')
                started = True
                return
            time.sleep(0.05)
        raise Refusal('qualification.journey.session-not-started')
    finally:
        if not started and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)


def receive(args):
    require(args.kind in ['commissioning-permit', 'first-release'], 'qualification.journey.mailbox')
    status = call(args.root, args.family, 'status')
    require(status['next_phase'] == (1 if args.kind == 'commissioning-permit' else 2),
            'qualification.journey.mailbox-order')
    artifact_wait.wait(SimpleNamespace(kind=args.kind, family=args.family, not_after=status['not_after'],
                                       out=args.root / 'mailboxes' / args.kind))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='verb', required=True)
    for name in ['start', 'serve']:
        command = commands.add_parser(name)
        for field in INPUT_NAMES:
            command.add_argument('--' + field.replace('_', '-'), required=True,
                type=int if field in ['runner_uid', 'runner_gid'] else str if field == 'family' else
                lambda value: Path(value).absolute())
    for name in ['advance', 'receive']:
        command = commands.add_parser(name)
        command.add_argument('--family', required=True)
        command.add_argument('--root', type=lambda value: Path(value).absolute(), required=True)
        if name == 'advance':
            command.add_argument('--phase', choices=COMMANDS, required=True)
        else:
            command.add_argument('--kind', choices=['commissioning-permit', 'first-release'], required=True)
    args = parser.parse_args()
    def dispatch():
        if args.verb == 'advance':
            call(args.root, args.family, args.phase)
        else:
            {'start': start, 'serve': serve, 'receive': receive}[args.verb](args)
    finish(dispatch)


if __name__ == '__main__':
    main()
