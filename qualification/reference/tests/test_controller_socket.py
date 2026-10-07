"""Closed controller protocol and real root peer transport, no provider I/O."""

import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import canonical, Refusal
import controller_socket as controller

FAMILY = 'stripe-platform-refund-v1'


class Stream:
    def __init__(self, raw): self.raw = raw
    def recv(self, maximum):
        result, self.raw = self.raw[:maximum], self.raw[maximum:]
        return result


class Controller(unittest.TestCase):
    def request(self):
        return {'schema': controller.REQUEST, 'family': FAMILY,
            'case': 'commissioning-proof-replay', 'index': 0, 'operation': 'submit'}

    def test_callers_supply_only_closed_source_case_coordinates(self):
        request = self.request()
        controller.checked_request(request, FAMILY)
        for changed in [dict(request, command='sign'), dict(request, expected={'outcome': 'observed'}),
                        dict(request, provider_key='synthetic-only'), dict(request, family='other-family'),
                        dict(request, case='../escape'), dict(request, index=True),
                        dict(request, index=16), dict(request, operation='install')]:
            with self.assertRaises(Refusal): controller.checked_request(changed, FAMILY)

    def test_messages_refuse_trailing_frames_duplicates_noncanonical_bytes_and_bounds(self):
        raw = canonical(self.request()) + b'\n'
        self.assertEqual(controller.receive(Stream(raw), 4096), self.request())
        for bad in [raw + raw, b'{"index":0,"index":1}\n', b'{} \n', b'{}', b'x' * 4097 + b'\n']:
            with self.assertRaises((Refusal, ValueError)): controller.receive(Stream(bad), 4096)

    @unittest.skipUnless(os.name == 'posix' and os.getuid() == 0 and hasattr(socket, 'SO_PEERCRED'),
                         'the credential-free packet-author job runs this test under root on Linux')
    def test_actual_private_socket_returns_refusals_without_inventing_observations(self):
        class Operations:
            family = FAMILY
            def step(self, case, index, operation):
                raise Refusal('qualification.operations.not-implemented')
        with tempfile.TemporaryDirectory(prefix='auths-controller-') as temporary:
            directory = Path(temporary).resolve()
            directory.chmod(0o700)
            endpoint = directory / 'controller.sock'
            stopping, ready = threading.Event(), threading.Event()
            failures = []
            def run():
                try: controller.serve(endpoint, Operations(), time.monotonic() + 30, stopping, ready)
                except BaseException as error: failures.append(error)
            thread = threading.Thread(target=run)
            thread.start()
            try:
                self.assertTrue(ready.wait(5))
                with self.assertRaisesRegex(Refusal, 'operations.not-implemented'):
                    controller.call(endpoint, FAMILY, 'commissioning-proof-replay', 0, 'submit')
            finally:
                stopping.set()
                thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertFalse(endpoint.exists())
            self.assertEqual(failures, [])


if __name__ == '__main__':
    unittest.main()
