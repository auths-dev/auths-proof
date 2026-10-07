#!/usr/bin/env python3
"""Release-only transparent TLS response fault, outside the shipping gateway.

Run in the gateway's disposable Linux network namespace with UID-scoped
REDIRECT rules for the reviewed provider's IPv4 addresses and port 443. The
original destination is retained. This relay has no TLS key, terminates no TLS,
and never decodes a provider request, response, credential or proof. Only the
unencrypted ServerHello selects the record boundary after the TLS handshake.

An actual native write-counter change arms the response hold. A separate root
controller must independently observe the effect before sending `drop`. Cipher
bytes and traffic counts are not evidence that the provider applied a write.
The case additionally needs the native result and fresh provider read-back.
"""

import argparse
import asyncio
import hashlib
import ipaddress
import os
from pathlib import Path
import socket
import stat
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'reference'))
from common import closed, require
from expand import decode
import measure
from resource_io import finish

ORIGINS = {'stripe-platform-refund-v1': 'api.stripe.com',
           'airtable-record-update-v1': 'api.airtable.com'}
MAX_RECORD = 18432
MAX_HELLO = 65536
MAX_BUFFER = 2 * 1024 * 1024
MAX_CONNECTIONS = 16


class Hello:
    """Read only plaintext TLS negotiation metadata, never encrypted content."""

    def __init__(self):
        self.pending = bytearray()
        self.version = None

    def server(self, kind, payload):
        if kind != 22 or self.version is not None:
            return
        self.pending.extend(payload)
        require(len(self.pending) <= MAX_HELLO, 'qualification.fault.hello-bound')
        if len(self.pending) < 4:
            return
        length = int.from_bytes(self.pending[1:4], 'big')
        require(self.pending[0] == 2 and 38 <= length <= MAX_HELLO - 4,
                'qualification.fault.server-hello')
        if len(self.pending) < length + 4:
            return
        body = bytes(self.pending[4:length + 4])
        require(body[:2] == b'\x03\x03', 'qualification.fault.tls-version')
        sid = body[34]
        offset = 35 + sid + 3
        require(sid <= 32 and offset <= len(body) and body[offset - 1] == 0,
                'qualification.fault.server-hello')
        selected = None
        if offset != len(body):
            require(offset + 2 <= len(body), 'qualification.fault.server-hello')
            size = int.from_bytes(body[offset:offset + 2], 'big')
            offset += 2
            require(offset + size == len(body), 'qualification.fault.server-hello')
            while offset < len(body):
                require(offset + 4 <= len(body), 'qualification.fault.server-hello')
                extension = int.from_bytes(body[offset:offset + 2], 'big')
                size = int.from_bytes(body[offset + 2:offset + 4], 'big')
                offset += 4
                require(offset + size <= len(body), 'qualification.fault.server-hello')
                if extension == 43:
                    require(selected is None and size == 2, 'qualification.fault.tls-version')
                    selected = body[offset:offset + size]
                offset += size
        require(selected in [None, b'\x03\x03', b'\x03\x04'], 'qualification.fault.tls-version')
        self.version = 'tls13' if selected == b'\x03\x04' else 'tls12'
        self.pending.clear()

    def client_boundary(self, kind):
        # TLS 1.3's first encrypted client record contains Finished. It can
        # be forwarded while subsequent server application records are held.
        # TLS 1.2 keeps Finished as content type 22; type 23 follows it.
        return self.version is not None and kind == 23


async def record(reader):
    header = await reader.readexactly(5)
    kind, version, size = header[0], header[1:3], int.from_bytes(header[3:5], 'big')
    require(kind in [20, 21, 22, 23] and version in [b'\x03\x01', b'\x03\x02', b'\x03\x03']
            and 0 < size <= MAX_RECORD, 'qualification.fault.record-bound')
    payload = await reader.readexactly(size)
    return kind, payload, header + payload


class Witness:
    """Pin one private, append-only native counter stream and its initial scope."""

    def __init__(self, path, owner):
        self.path, self.owner = Path(path), owner
        self.inode, self.previous_size, self.before, self.last = None, 0, None, None
        self.prefix_sha256 = None

    def entered(self):
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and info.st_uid == self.owner and stat.S_IMODE(info.st_mode) == 0o600
                    and 0 < info.st_size <= 256 * 1024,
                    'qualification.fault.witness-file')
            inode = info.st_dev, info.st_ino
            require(self.inode in [None, inode] and info.st_size >= self.previous_size,
                    'qualification.fault.changed-witness')
            raw = stream.read(256 * 1024 + 1)
        require(len(raw) <= 256 * 1024, 'qualification.fault.witness-bound')
        require(self.prefix_sha256 is None or hashlib.sha256(raw[:self.previous_size]).digest()
                == self.prefix_sha256, 'qualification.fault.changed-witness')
        # A concurrent append may end halfway through one bounded frame.
        frames = raw.split(b'\n')[:-1]
        require(1 <= len(frames) <= 256 and all(0 < len(frame) < 1024 for frame in frames)
                and len(raw.rsplit(b'\n', 1)[-1]) < 1024, 'qualification.fault.witness-bound')
        values = [measure.snapshot(decode(frame)) for frame in frames]
        for before, after in zip(values, values[1:]):
            measure.delta(before, after)
        require(self.before in [None, values[0]], 'qualification.fault.changed-witness')
        if self.last is not None:
            measure.delta(self.last, values[-1])
        self.inode, self.previous_size = inode, len(raw)
        self.prefix_sha256 = hashlib.sha256(raw).digest()
        self.before, self.last = values[0], values[-1]
        count = measure.delta(self.before, self.last)['write_transport_entries']
        require(count <= 1, 'qualification.fault.multiple-writes')
        return count == 1


class Fault:
    def __init__(self, witness):
        self.witness = witness
        self.decision = asyncio.Event()
        self.command = None
        self.buffered = self.held_connections = self.connections = 0
        self.armed = False

    def decide(self, value):
        closed(value, ['command'])
        require(value['command'] in ['drop', 'release'] and self.command is None
                and self.armed and self.held_connections > 0,
                'qualification.fault.control-state')
        self.command = value['command']
        self.decision.set()

    def status(self):
        return {'schema': 'auths.qualification-tls-fault/1', 'armed': self.armed,
                'held_connections': self.held_connections, 'buffered_bytes': self.buffered,
                'command': self.command}


def destination(writer, approved):
    stream = writer.get_extra_info('socket')
    # Linux SO_ORIGINAL_DST preserves the gateway-selected address across
    # REDIRECT. No command or artifact may select another upstream endpoint.
    raw = stream.getsockopt(socket.SOL_IP, 80, 16)
    family = struct.unpack_from('H', raw)[0]
    port = int.from_bytes(raw[2:4], 'big')
    address = socket.inet_ntoa(raw[4:8])
    require(family == socket.AF_INET and port == 443 and address in approved,
            'qualification.fault.destination')
    return address, port


async def relay(reader, writer, fault, approved):
    fault.connections += 1
    remote = None
    tasks = []
    try:
        require(fault.connections <= MAX_CONNECTIONS and fault.command is None,
                'qualification.fault.connection-bound')
        upstream, remote = await asyncio.wait_for(
            asyncio.open_connection(*destination(writer, approved), limit=MAX_RECORD * 2), 5)
        hello = Hello()
        held = False

        async def client():
            nonlocal held
            while True:
                kind, _payload, raw = await record(reader)
                if not held and hello.client_boundary(kind) and fault.witness.entered():
                    # Arm before forwarding Finished/the request so a fast
                    # upstream response cannot overtake this boundary.
                    held = True
                    fault.armed = True
                    fault.held_connections += 1
                remote.write(raw)
                await remote.drain()

        async def server():
            while True:
                kind, payload, raw = await record(upstream)
                hello.server(kind, payload)
                if held and kind == 23:
                    fault.buffered += len(raw)
                    require(fault.buffered <= MAX_BUFFER, 'qualification.fault.buffer-bound')
                    await fault.decision.wait()
                    if fault.command == 'drop':
                        return
                writer.write(raw)
                await writer.drain()

        tasks = [asyncio.create_task(client()), asyncio.create_task(server())]
        _done, pending = await asyncio.wait(tasks, timeout=45, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        # Neither TLS ciphertext nor path/provider exception text is emitted.
        pass
    finally:
        for task in tasks:
            task.cancel()
        for connection in [writer, remote]:
            if connection is not None:
                connection.close()
                try:
                    await connection.wait_closed()
                except OSError:
                    pass


async def control(reader, writer, fault):
    try:
        stream = writer.get_extra_info('socket')
        _pid, uid, _gid = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(uid == 0, 'qualification.fault.control-peer')
        raw = await asyncio.wait_for(reader.readuntil(b'\n'), 5)
        require(len(raw) <= 128, 'qualification.fault.control-bound')
        value = decode(raw)
        if value == {'command': 'status'}:
            pass
        else:
            fault.decide(value)
        from common import canonical
        writer.write(canonical(fault.status()) + b'\n')
        await writer.drain()
    except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def serve(args):
    require(sys.platform == 'linux' and os.getuid() == 0, 'qualification.fault.linux-root')
    origin = ORIGINS[args.family]
    approved = {result[4][0] for result in socket.getaddrinfo(origin, 443, socket.AF_INET, socket.SOCK_STREAM)}
    require(1 <= len(approved) <= 16 and all(ipaddress.ip_address(value).is_global for value in approved),
            'qualification.fault.provider-address')
    parent = os.lstat(args.control.parent)
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0
            and stat.S_IMODE(parent.st_mode) == 0o700 and not args.control.exists()
            and not args.control.is_symlink() and args.control.parent.resolve() == args.control.parent,
            'qualification.fault.private-control')
    fault = Fault(Witness(args.witness, args.witness_owner))
    # Root's umask keeps the local control socket private at creation.
    os.umask(0o077)
    ipc = await asyncio.start_unix_server(lambda r, w: control(r, w, fault), args.control, limit=128)
    os.chmod(args.control, 0o600)
    inode = os.lstat(args.control).st_ino
    try:
        tcp = await asyncio.start_server(lambda r, w: relay(r, w, fault, approved), '127.0.0.1', args.port,
                                         limit=MAX_RECORD * 2)
        print('qualification.fault.ready', flush=True)
        async with ipc, tcp:
            await asyncio.wait_for(asyncio.gather(ipc.serve_forever(), tcp.serve_forever()), 120)
    finally:
        ipc.close()
        await ipc.wait_closed()
        if args.control.exists() and os.lstat(args.control).st_ino == inode:
            args.control.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family', choices=sorted(ORIGINS), required=True)
    parser.add_argument('--witness', type=lambda v: Path(v).absolute(), required=True)
    parser.add_argument('--witness-owner', type=int, required=True)
    parser.add_argument('--control', type=lambda v: Path(v).absolute(), required=True)
    parser.add_argument('--port', type=int, default=44443)
    args = parser.parse_args()
    require(1 <= args.port <= 65535 and 1 <= args.witness_owner <= (1 << 32) - 2,
            'qualification.fault.configuration')
    finish(lambda: asyncio.run(serve(args)))


if __name__ == '__main__':
    main()
