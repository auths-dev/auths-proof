"""Local author channel refuses peers, framing and changed public handoffs."""

import os
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import author_socket
from common import Refusal, canonical
from resource_io import write, write_bytes


class AuthorSocket(unittest.TestCase):
    def test_frames_are_bounded_complete_and_serial(self):
        for raw in [b'{"command":"inspect"}\n', b'x' * 512]:
            sender, receiver = socket.socketpair()
            with sender, receiver:
                sender.sendall(raw)
                sender.shutdown(socket.SHUT_WR)
                if raw.endswith(b'\n'):
                    self.assertEqual(author_socket.receive(receiver, time.monotonic() + 2), raw)
                else:
                    with self.assertRaises(Refusal): author_socket.receive(receiver, time.monotonic() + 2)
        for raw in [b'x' * 513, b'one\ntwo\n', b'one\nunfinished']:
            sender, receiver = socket.socketpair()
            with sender, receiver:
                sender.sendall(raw)
                with self.assertRaises(Refusal): author_socket.receive(receiver, time.monotonic() + 2)

    @unittest.skipUnless(hasattr(socket, 'SO_PEERCRED'), 'Linux peer credentials required')
    def test_peer_credentials_come_from_the_kernel(self):
        first, second = socket.socketpair()
        with first, second:
            self.assertEqual(author_socket.peer_uid(first), os.getuid())
            self.assertEqual(author_socket.peer_uid(second), os.getuid())

    def test_private_directory_checks_refuse_symlinks_shared_modes_and_root_authors(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            work.chmod(0o755)
            with self.assertRaises(Refusal): author_socket.private_work(work, author=True)
            work.chmod(0o700)
            with patch('author_socket.os.getuid', return_value=0):
                with self.assertRaises(Refusal): author_socket.private_work(work, author=True)
            link = work / 'link'
            link.symlink_to(work, target_is_directory=True)
            with self.assertRaises(Refusal): author_socket.private_work(link, author=True)

    def test_refresh_never_exports_a_changed_action_context_or_aged_packet(self):
        for change in ['action', 'context', 'arguments', 'age', 'extra-field']:
            with tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                work.chmod(0o700)
                packet = {'label': 'live-00', 'proof': 'live-00.proof',
                          'trusted_context': 'context-0.cbor',
                          'action': 'live-00.action', 'arguments': {'closed': 'source'}}
                now = int(time.time())
                original = {'schema': 'auths.qualification-public-packets/4',
                    'protected_run': 'recipe-qualification/123/1', 'evaluated_at': now,
                    'not_after': now + 300, 'trusted_contexts': ['context-0.cbor'], 'packets': [packet]}
                write(work / 'public-packets.json', original, new=True)
                write_bytes(work / 'live-00.action', b'source-action', new=True)
                write_bytes(work / 'context-0.cbor', b'source-context', new=True)
                fresh = work / 'refresh-0001'
                fresh.mkdir(mode=0o700)
                value = dict(original)
                if change == 'arguments': value['packets'] = [dict(packet, arguments={'closed': 'changed'})]
                if change == 'age': value.update(evaluated_at=now-120, not_after=now+30)
                if change == 'extra-field': value['credential'] = 'synthetic-forbidden-input'
                write(fresh / 'public-packets.json', value, new=True)
                write_bytes(fresh / 'live-00.action', b'changed' if change == 'action' else b'source-action', new=True)
                write_bytes(fresh / 'context-0.cbor', b'changed' if change == 'context' else b'source-context', new=True)
                write_bytes(fresh / 'live-00.proof', b'public-proof', new=True)
                with patch('author_socket.exchange', return_value={'generation': 1}):
                    with self.assertRaises(Refusal): author_socket.refresh(work, 'live-00', work / 'output')
                self.assertFalse((work / 'output').exists())


if __name__ == '__main__':
    unittest.main()
