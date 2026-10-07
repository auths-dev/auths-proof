#!/usr/bin/env python3
"""Keep the isolated installed author alive across protected runner steps.

Linux only. The author runs under a dedicated unprivileged UID with an empty
environment; only the root operator controller may connect. This is a local
release tool, never a gateway channel or an executable artifact for a signer.
"""

import argparse
import os
from pathlib import Path
import socket
import stat
import struct
import time

from author_packets import command, create_session
from common import canonical, closed, require
from expand import decode, read
from resource_io import finish, write_bytes

SCHEMA = 'auths.qualification-author-socket/1'


def private_work(work, *, author):
    info = os.lstat(work)
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
            and (info.st_uid == os.getuid() if author else info.st_uid != 0),
            'qualification.packets.socket-directory')
    require(hasattr(socket, 'SO_PEERCRED') and (os.getuid() != 0 if author else os.getuid() == 0),
            'qualification.packets.socket-isolation')


def peer_uid(connection):
    return struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


def receive(connection, deadline):
    pending = b''
    while b'\n' not in pending:
        remaining = min(30, deadline - time.monotonic())
        require(remaining > 0, 'qualification.packets.session-expired')
        connection.settimeout(remaining)
        chunk = connection.recv(513 - len(pending))
        require(bool(chunk), 'qualification.packets.command-bound')
        pending += chunk
        require(len(pending) <= 512, 'qualification.packets.command-bound')
    require(pending.count(b'\n') == 1 and pending.endswith(b'\n'),
            'qualification.packets.command-bound')
    return pending


def send(connection, value):
    payload = canonical(value) + b'\n'
    require(len(payload) <= 512, 'qualification.packets.command-bound')
    connection.sendall(payload)


def serve(plan, work):
    private_work(work, author=True)
    endpoint = work / 'author.sock'
    # bind refuses an existing path. Nothing unlinks an unknown socket, file
    # or symlink; a second launch cannot replace the first author's authority.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(endpoint))
        os.chmod(endpoint, 0o600)
        identity = os.lstat(endpoint)
        try:
            server.listen(1)
            emit, end = create_session(plan)
            emit(work)
            deadline = time.monotonic() + max(0, end - time.time())
            last_clock = time.time()
            generation = 0
            while True:
                now = time.time()
                require(now >= last_clock, 'qualification.packets.session-expired')
                last_clock = now
                remaining = min(end - now, deadline - time.monotonic())
                require(remaining > 0, 'qualification.packets.session-expired')
                server.settimeout(remaining)
                connection, _ = server.accept()
                with connection:
                    require(peer_uid(connection) == 0, 'qualification.packets.socket-peer')
                    connection.settimeout(min(30, remaining))
                    send(connection, {'schema': SCHEMA, 'state': 'ready', 'generation': generation})
                    raw = receive(connection, deadline)
                    if decode(raw) == {'command': 'inspect'}:
                        send(connection, {'schema': SCHEMA, 'state': 'ready', 'generation': generation})
                        continue
                    value = command(raw, generation)
                    if value is None:
                        send(connection, {'schema': SCHEMA, 'state': 'closed'})
                        return
                    generation = value['generation']
                    destination = work / ('refresh-' + str(generation).zfill(4))
                    destination.mkdir(mode=0o700)
                    emit(destination, value['label'])
                    send(connection, {'schema': SCHEMA, 'state': 'refreshed',
                                      'generation': generation, 'label': value['label']})
        finally:
            # Only remove the exact socket we bound, even during failed setup.
            if endpoint.exists():
                current = os.lstat(endpoint)
                if stat.S_ISSOCK(current.st_mode) and (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                    endpoint.unlink()


def exchange(work, action, label=None):
    private_work(work, author=False)
    endpoint = work / 'author.sock'
    info = os.lstat(endpoint)
    require(stat.S_ISSOCK(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_uid == os.lstat(work).st_uid, 'qualification.packets.socket-identity')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(30)
        connection.connect(str(endpoint))
        require(peer_uid(connection) == info.st_uid, 'qualification.packets.socket-peer')
        ready = decode(receive(connection, time.monotonic() + 30))
        closed(ready, ['schema', 'state', 'generation'])
        require(ready['schema'] == SCHEMA and ready['state'] == 'ready'
                and type(ready['generation']) is int and 0 <= ready['generation'] <= 1024,
                'qualification.packets.socket-response')
        value = {'command': action}
        if action == 'refresh':
            value.update(label=label, generation=ready['generation'] + 1)
        else:
            require(action in ['inspect', 'close'], 'qualification.packets.command-bound')
        send(connection, value)
        result = decode(receive(connection, time.monotonic() + 30))
        expected = dict(ready) if action == 'inspect' else {'schema': SCHEMA, 'state': 'closed'}
        if action == 'refresh':
            expected = {'schema': SCHEMA, 'state': 'refreshed',
                        'generation': value['generation'], 'label': label}
        require(result == expected, 'qualification.packets.socket-response')
        return result


def refresh(work, label, destination):
    # A label can select only an original source-derived action. Check it
    # before contacting the key holder; no caller-supplied arguments or paths
    # enter its protocol. The root controller copies only public bytes out.
    original = decode(read(work / 'public-packets.json', 65536))
    matches = [packet for packet in original['packets'] if packet['label'] == label]
    require(len(matches) == 1, 'qualification.packets.unknown-label')
    packet = matches[0]
    require(packet['proof'] == label + '.proof' and packet['action'] == label + '.action'
            and packet['trusted_context'] in ['context-0.cbor', 'context-1.cbor']
            and packet['trusted_context'] in original['trusted_contexts'], 'qualification.packets.socket-response')
    require(not destination.exists(), 'qualification.packets.output-exists')
    result = exchange(work, 'refresh', label)
    source = work / ('refresh-' + str(result['generation']).zfill(4))
    fresh = decode(read(source / 'public-packets.json', 65536))
    now = int(time.time())
    require(set(fresh) == set(original) and fresh['schema'] == original['schema']
            and fresh['protected_run'] == original['protected_run']
            and fresh['trusted_contexts'] == [packet['trusted_context']] and fresh['packets'] == [packet]
            and type(fresh['evaluated_at']) is int and type(fresh['not_after']) is int
            and now - 30 <= fresh['evaluated_at'] <= now
            and now + 60 <= fresh['not_after'] <= fresh['evaluated_at'] + 300,
            'qualification.packets.refresh-binding')
    payloads = {name: read(source / name, bound) for name, bound in [
        (packet['proof'], 4 * 1024 * 1024), (packet['action'], 65536),
        (packet['trusted_context'], 4 * 1024 * 1024), ('public-packets.json', 65536)]}
    require(payloads[packet['action']] == read(work / packet['action'], 65536)
            and payloads[packet['trusted_context']] == read(work / packet['trusted_context'], 4 * 1024 * 1024),
            'qualification.packets.refresh-binding')
    destination.mkdir(mode=0o700)
    for name, payload in payloads.items():
        write_bytes(destination / name, payload, new=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest='command', required=True)
    for action in ['serve', 'inspect', 'refresh', 'close']:
        command_parser = subparsers.add_parser(action)
        command_parser.add_argument('--work', type=lambda value: Path(value).absolute(), required=True)
        if action == 'serve':
            command_parser.add_argument('--plan', type=lambda value: Path(value).absolute(), required=True)
        if action == 'refresh':
            command_parser.add_argument('--label', required=True)
            command_parser.add_argument('--out', type=lambda value: Path(value).absolute(), required=True)
    args = parser.parse_args()
    def execute():
        if args.command == 'serve':
            serve(args.plan, args.work)
        elif args.command == 'refresh':
            refresh(args.work, args.label, args.out)
        else:
            exchange(args.work, args.command)
    finish(execute)


if __name__ == '__main__':
    main()
