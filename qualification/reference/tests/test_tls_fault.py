"""Transparent fault mechanics with synthetic counters and disposable TLS.

These tests demonstrate transport behavior, not native gateway/provider facts.
"""

import asyncio
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'run'))
import tls_fault as fault


def snapshot(entries=0, scope='1' * 32):
    return {'schema': 'auths.gateway-execution-witness/1', 'scope': scope,
            'credential_lease_calls': entries, 'write_transport_entries': entries,
            'read_transport_entries': 0}


def server_hello(version=None):
    body = b'\x03\x03' + b'\0' * 32 + b'\0\x13\x01\0'
    if version is not None:
        extension = b'\0\x2b\0\x02' + version
        body += len(extension).to_bytes(2, 'big') + extension
    return b'\x02' + len(body).to_bytes(3, 'big') + body


class Parsing(unittest.TestCase):
    def work(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / 'witness.ndjson'
        path.write_text(json.dumps(snapshot()) + '\n')
        path.chmod(0o600)
        return path

    def test_fragmented_negotiation_keeps_handshake_records_unmodified(self):
        for version, expected in [(None, 'tls12'), (b'\x03\x04', 'tls13')]:
            hello = fault.Hello()
            payload = server_hello(version)
            hello.server(22, payload[:7])
            self.assertIsNone(hello.version)
            hello.server(22, payload[7:])
            self.assertEqual(hello.version, expected)
            self.assertFalse(hello.client_boundary(22))
            self.assertTrue(hello.client_boundary(23))
            hello.server(23, b'opaque-ciphertext-never-decoded')
            self.assertEqual(hello.version, expected)

    def test_malformed_or_unknown_tls_negotiation_refuses(self):
        for value in [server_hello(b'\x03\x05'), b'\x01\0\0\x26' + b'\0' * 38,
                      b'\x02\xff\xff\xff', server_hello(b'\x03\x04')[:-1] + b'\xff']:
            with self.assertRaises(ValueError): fault.Hello().server(22, value)

    def test_witness_requires_actual_changed_scope_local_counters_without_saturation(self):
        path = self.work()
        witness = fault.Witness(path, os.getuid())
        self.assertFalse(witness.entered())
        with path.open('a') as out:
            out.write(json.dumps(snapshot(1)) + '\n' + '{"schema":')
        self.assertTrue(witness.entered(), 'a concurrent partial tail is not a new fact')
        path.write_text(json.dumps(snapshot()) + '\n')
        with self.assertRaises(ValueError): witness.entered()
        for changed in [snapshot(1, scope='2' * 32), snapshot(2),
                        dict(snapshot(1), write_transport_entries=(1 << 64) - 1),
                        dict(snapshot(1), passed=True)]:
            path = self.work()
            with path.open('a') as out: out.write(json.dumps(changed) + '\n')
            with self.assertRaises(ValueError): fault.Witness(path, os.getuid()).entered()

    def test_changed_inode_links_and_public_witness_are_refused(self):
        for mode in ['replacement', 'symlink', 'hardlink', 'public']:
            path = self.work()
            witness = fault.Witness(path, os.getuid())
            witness.entered()
            if mode == 'replacement':
                replacement = path.with_name('replacement')
                replacement.write_text(json.dumps(snapshot()) + '\n')
                replacement.chmod(0o600)
                os.replace(replacement, path)
            elif mode == 'symlink':
                target = path.with_name('target')
                path.rename(target)
                path.symlink_to(target)
            elif mode == 'hardlink':
                os.link(path, path.with_name('linked'))
            else:
                path.chmod(0o644)
            with self.assertRaises((ValueError, OSError)): witness.entered()

    def test_control_cannot_invent_entry_or_choose_an_endpoint(self):
        state = fault.Fault(None)
        for command in [{'command': 'drop'}, {'command': 'drop', 'provider_url': 'unreviewed'},
                        {'command': 'passed'}, {'passed': True}]:
            with self.assertRaises(ValueError): state.decide(command)
        state.armed, state.held_connections = True, 1
        state.decide({'command': 'drop'})
        self.assertEqual(state.status()['command'], 'drop')
        with self.assertRaises(ValueError): state.decide({'command': 'release'})


class Transport(unittest.IsolatedAsyncioTestCase):
    async def test_disposable_tls12_and_tls13_drop_or_release_real_encrypted_records(self):
        for version in [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]:
            for command in ['release', 'drop']:
                with self.subTest(version=version, command=command), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    # Ephemeral local test material stays outside the repository.
                    made = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ed25519', '-nodes',
                        '-subj', '/CN=localhost', '-days', '1', '-keyout', str(root / 'key.pem'),
                        '-out', str(root / 'cert.pem')], capture_output=True, timeout=10)
                    self.assertEqual(made.returncode, 0)
                    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    server_context.minimum_version = server_context.maximum_version = version
                    server_context.load_cert_chain(root / 'cert.pem', root / 'key.pem')
                    client_context = ssl.create_default_context(cafile=str(root / 'cert.pem'))
                    client_context.minimum_version = client_context.maximum_version = version
                    received = asyncio.Event()
                    request = b'POST /synthetic HTTP/1.1\r\nHost: localhost\r\n\r\n'
                    response = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'
                    async def provider(reader, writer):
                        try:
                            self.assertEqual(await reader.readuntil(b'\r\n\r\n'), request)
                            received.set()
                            writer.write(response)
                            await writer.drain()
                        finally:
                            writer.close()
                    upstream = await asyncio.start_server(provider, '127.0.0.1', 0, ssl=server_context)
                    endpoint = upstream.sockets[0].getsockname()
                    witness = root / 'witness.ndjson'
                    witness.write_text(json.dumps(snapshot()) + '\n' + json.dumps(snapshot(1)) + '\n')
                    witness.chmod(0o600)
                    state = fault.Fault(fault.Witness(witness, os.getuid()))
                    with patch.object(fault, 'destination', return_value=endpoint):
                        relay = await asyncio.start_server(lambda r, w: fault.relay(r, w, state, set()),
                                                           '127.0.0.1', 0)
                        endpoint = relay.sockets[0].getsockname()
                        reader, writer = await asyncio.wait_for(asyncio.open_connection(
                            *endpoint, ssl=client_context, server_hostname='localhost'), 5)
                        writer.write(request)
                        await writer.drain()
                        await asyncio.wait_for(received.wait(), 5)
                        pending = asyncio.create_task(reader.read(len(response)))
                        await asyncio.sleep(0.05)
                        self.assertFalse(pending.done(), 'response must be held after upstream receipt')
                        # A racing gateway's recovery connection must retain
                        # its independent route while the owner stays held.
                        follower, follower_writer = await asyncio.wait_for(asyncio.open_connection(
                            *endpoint, ssl=client_context, server_hostname='localhost'), 5)
                        follower_writer.write(request)
                        await follower_writer.drain()
                        self.assertEqual(await asyncio.wait_for(follower.readexactly(len(response)), 5), response)
                        self.assertFalse(pending.done())
                        self.assertEqual(state.held_connections, 1)
                        follower_writer.close()
                        try:
                            await follower_writer.wait_closed()
                        except OSError:
                            pass
                        state.decide({'command': command})
                        returned = await asyncio.wait_for(pending, 5)
                        self.assertEqual(returned, response if command == 'release' else b'')
                        self.assertTrue(state.armed)
                        self.assertGreater(state.buffered, 0)
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except OSError:
                            pass
                        relay.close()
                        await relay.wait_closed()
                    upstream.close()
                    await upstream.wait_closed()


if __name__ == '__main__':
    unittest.main()
