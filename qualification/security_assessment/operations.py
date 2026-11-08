#!/usr/bin/env python3
"""Installed-path recovery drills with an independently scheduled HTTP intermediary.

The intermediary forwards one request to the counting provider unchanged, then
holds its response. It cannot create authorization or replace a native fence.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import socket
import struct
import subprocess
import sys
import threading
import time

from stripe_probe import Campaign, ENV, TARGET, canonical


class Intermediary:
    def __init__(self, upstream):
        self.upstream = upstream
        self.applied = threading.Event()
        self.release = threading.Event()
        self.selected_payment = None
        self.received = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def exchange(self):
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 <= length <= 16384:
                    self.send_error(413)
                    return
                body = self.rfile.read(length)
                upstream = HTTPConnection('127.0.0.1', owner.upstream, timeout=20)
                try:
                    upstream.request(self.command, self.path, body, dict(self.headers))
                    response = upstream.getresponse()
                    payload = response.read(16385)
                    if len(payload) > 16384:
                        raise ValueError('bounded intermediary response')
                    owner.received.append({'method': self.command, 'path': self.path,
                                           'status': response.status,
                                           'request_body_sha256': hashlib.sha256(body).hexdigest()})
                    if (self.command == 'POST' and owner.selected_payment
                            and owner.selected_payment.encode() in body and response.status == 200):
                        # The upstream has completed and returned its successful
                        # response. Independent effects are also checked below.
                        owner.applied.set()
                        if not owner.release.wait(timeout=12):
                            raise TimeoutError('owned response barrier not released')
                    self.send_response(response.status)
                    for name, value in response.getheaders():
                        if name.lower() not in ['server', 'date', 'connection']:
                            self.send_header(name, value)
                    self.end_headers()
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    # Expected when the recipient process was killed or the
                    # caller disconnected. No upstream retry is performed.
                    pass
                finally:
                    upstream.close()

            do_GET = exchange
            do_POST = exchange

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def arm(self, payment):
        self.selected_payment = payment
        self.applied.clear()
        self.release.clear()

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def main():
    if platform.system() != 'Linux' or os.getuid() != 0:
        raise SystemExit('assessment-owned Linux controller required')
    sys.path.insert(0, '/opt/demo')
    from operate import Operator
    metadata = json.loads(Path('/opt/demo/manifest.json').read_text())
    if metadata['source_commit'] != TARGET:
        raise SystemExit('wrong installed source')
    operator = Operator('simulation')
    proxy = None
    try:
        operator.prepare()
        subprocess.run(['iptables', '-A', 'OUTPUT', '-m', 'owner', '--uid-owner', '62004',
                        '-j', 'REJECT'], check=True, capture_output=True)
        proxy = Intermediary(operator.port)
        operator.port = proxy.server.server_address[1]
        for host in range(3):
            operator.restart(host)
        campaign = Campaign(operator)
        plan = json.loads(Path('/run/demo/app/application.json').read_text())

        def frame(label):
            packet = json.loads(Path('/run/demo/app/packet-' + label + '.json').read_text())
            return {'schema': 'auths.gateway-submit/2', 'proof_b64': packet['proof'],
                    'action_b64': packet['action'], 'approval_b64': plan['effect_approvals'][label]}

        def positive():
            before = len(campaign.traffic())
            result = campaign.frame(frame('exact'))['response']
            writes = [x for x in campaign.traffic()[before:] if x['kind'] == 'write']
            assert result['outcome'] == 'response-recorded' and len(writes) == 1
            return {'outcome': result['outcome'], 'intermediary_preserves_native_positive': True}

        campaign.run('OPS-positive-through-scheduled-intermediary', ['SB01', 'SB18'], positive)

        def crash():
            label = 'boundary'
            proxy.arm(plan['cases'][label]['arguments']['payment_intent'])
            steps = []
            with ThreadPoolExecutor(max_workers=1) as pool:
                waiting = pool.submit(campaign.frame, frame(label))
                assert proxy.applied.wait(timeout=8), 'write did not reach held-response point'
                assert len([x for x in campaign.traffic() if x['kind'] == 'write']) == 2
                process, log, host = next(x for x in operator.processes if x[2] == 0)
                started = time.monotonic()
                process.kill()
                process.wait(timeout=5)
                operator.processes.remove((process, log, host))
                log.close()
                steps.append({'command': 'SIGKILL owned gateway0 PID; wait',
                              'elapsed_seconds': time.monotonic() - started})
                proxy.release.set()
                initial = waiting.result(timeout=8)
            before = len(campaign.traffic())
            started = time.monotonic()
            operator.start_gateway(0)
            steps.append({'command': 'serve --state-dir /run/demo/gateway0 '
                                     '--app-socket /run/demo/sockets/app0.sock --loopback-provider <owned-port>',
                          'elapsed_seconds': time.monotonic() - started})
            replay = campaign.frame(frame(label))['response']
            assert replay['outcome'] == 'unknown', 'crash strengthened unrecorded provider result'
            assert len(campaign.traffic()) == before, 'crash replay retried provider I/O'
            return {'kill_after_independently_observed_apply': True, 'initial_transport': initial,
                    'after_restart': replay['outcome'], 'steps': steps,
                    'safe_next_action': 'retain charge; separately authorize evidence or escalate',
                    'prohibited_action': 'repeat mutation to resolve uncertainty',
                    'role': 'trusted controller kills/restarts; restricted UID submits',
                    'human_effort_measured': False}

        campaign.run('OPS-sigkill-after-provider-apply-before-response', ['SB17', 'SB18', 'SB19'], crash)

        def late():
            label = 'race'
            proxy.arm(plan['cases'][label]['arguments']['payment_intent'])
            with ThreadPoolExecutor(max_workers=1) as pool:
                waiting = pool.submit(campaign.frame, frame(label))
                assert proxy.applied.wait(timeout=8), 'late-response operation never applied'
                # The actual restricted caller times out/closes its Unix
                # channel after seven seconds. Keep the native call running.
                initial = waiting.result(timeout=9)
                assert 'closed' in initial, 'caller did not disconnect before delayed result'
            proxy.release.set()
            before = len(campaign.traffic())
            deadline = time.monotonic() + 6
            observed = None
            inspections = 0
            while time.monotonic() < deadline:
                observed = campaign.frame(frame(label))['response']
                inspections += 1
                if observed.get('outcome') == 'response-recorded':
                    break
                threading.Event().wait(0.05)
            assert observed and observed['outcome'] == 'response-recorded', 'late result not durably retained'
            assert len(campaign.traffic()) == before, 'late-result inspection duplicated provider I/O'
            return {'caller_disconnected': True, 'late_response_retained': True,
                    'inspection_commands': inspections,
                    'command': 'restricted raw submit; wait for disconnect; release owned provider response; inspect same operation',
                    'safe_next_action': 'inspect retained response; separately authorize read if needed',
                    'prohibited_action': 'create another operation to retry this effect',
                    'role': 'restricted caller; trusted fault scheduler', 'human_effort_measured': False}

        campaign.run('OPS-late-provider-response-after-caller-disconnect', ['SB18', 'SB19'], late)
        result = {'schema': 'auths.security-assessment-operations/1', 'target_revision': TARGET,
                  'native_policy_replaced': False, 'backend': 'file',
                  'binary_sha256': hashlib.sha256(operator.binary.read_bytes()).hexdigest(),
                  'attacker_uid': 62004, 'human_trial': False, 'production_qualification': False,
                  'intermediary': 'single-forward HTTP; controlled response timing; no upstream retries',
                  'cases': campaign.rows}
        Path('/evidence/operations.json').write_bytes(canonical(result) + b'\n')
        print(json.dumps({'cases': len(campaign.rows),
                          'findings': sum(x['status'] != 'pass' for x in campaign.rows)}))
        if any(x['status'] != 'pass' for x in campaign.rows):
            raise SystemExit(1)
    finally:
        if proxy is not None:
            proxy.close()
        operator.stop()


if __name__ == '__main__':
    main()
