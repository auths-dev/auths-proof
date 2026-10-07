"""Disposable Linux UID isolation and transparent provider-response faults.

Only reviewed provider addresses are redirected. TLS remains end to end, and
an independent provider read, rather than traffic, decides whether a response
can be lost. All rules are removed individually; no shared chain is flushed.
"""

import asyncio
from contextlib import AbstractContextManager
import ipaddress
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

from common import Refusal, require
import measure
from production_setup import APPLICATION_UID, GATEWAY_UID

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'run'))
from tls_fault import Fault, ORIGINS, MAX_RECORD, relay

AUTHOR_UID = 62002


class Rules(AbstractContextManager):
    def __init__(self):
        require(sys.platform == 'linux' and os.getuid() == 0, 'qualification.network.identity')
        self.removals = []

    def add(self, executable, table, arguments):
        require(executable in ['iptables', 'ip6tables'] and table in ['filter', 'nat']
                and arguments[0] == '-A', 'qualification.network.rule')
        self.command(executable, table, arguments)
        self.removals.append((executable, table, ['-D', *arguments[1:]]))

    @staticmethod
    def command(executable, table, arguments):
        result = subprocess.run([executable, '-w', '5', '-t', table, *map(str, arguments)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
        require(result.returncode == 0, 'qualification.network.rule-refused')

    def __exit__(self, kind, value, traceback):
        failures = []
        for executable, table, arguments in reversed(self.removals):
            try:
                self.command(executable, table, arguments)
            except (Refusal, OSError, subprocess.SubprocessError):
                failures.append(True)
        self.removals = []
        require(not failures, 'qualification.network.cleanup-refused')


class Isolation(Rules):
    def __enter__(self):
        try:
            for executable in ['iptables', 'ip6tables']:
                for owner in [AUTHOR_UID, APPLICATION_UID]:
                    self.add(executable, 'filter', ['-A', 'OUTPUT', '-m', 'owner', '--uid-owner', owner,
                        '-m', 'comment', '--comment', 'auths-qualification-' + str(os.getpid()), '-j', 'REJECT'])
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self


class NativeWitness:
    """Read a live gateway's actual diagnostic; never synthesize a counter scope."""
    def __init__(self, deployment, host, context):
        self.deployment, self.host, self.context = deployment, host, context
        self.before = self.last = deployment.witness(host, context)

    def entered(self):
        current = self.deployment.witness(self.host, self.context)
        measure.delta(self.last, current)
        counted = measure.delta(self.before, current)
        require(counted['write_transport_entries'] <= 1, 'qualification.fault.multiple-writes')
        self.last = current
        return counted['write_transport_entries'] == 1


class ResponseFault(Rules):
    def __init__(self, family, witness):
        super().__init__()
        require(family in ORIGINS, 'qualification.fault.family')
        self.witness = witness
        self.approved = {entry[4][0] for entry in socket.getaddrinfo(
            ORIGINS[family], 443, socket.AF_INET, socket.SOCK_STREAM)}
        self.ipv6 = {entry[4][0] for entry in socket.getaddrinfo(
            ORIGINS[family], 443, socket.AF_UNSPEC, socket.SOCK_STREAM) if entry[0] == socket.AF_INET6}
        require(1 <= len(self.approved) <= 16 and len(self.ipv6) <= 16
                and all(ipaddress.ip_address(value).is_global for value in self.approved | self.ipv6),
                'qualification.fault.provider-address')
        self.ready, self.finished = threading.Event(), threading.Event()
        self.failure, self.loop, self.fault, self.port = None, None, None, None
        self.thread = threading.Thread(target=self.run, name='auths-transparent-response-fault', daemon=True)

    async def serving(self):
        self.loop = asyncio.get_running_loop()
        self.fault = Fault(self.witness)
        server = await asyncio.start_server(lambda r, w: relay(r, w, self.fault, self.approved),
            '127.0.0.1', 0, limit=MAX_RECORD * 2)
        self.port = server.sockets[0].getsockname()[1]
        self.ready.set()
        try:
            async with server:
                while not self.finished.is_set():
                    await asyncio.sleep(0.05)
        finally:
            server.close()
            await server.wait_closed()

    def run(self):
        try:
            asyncio.run(self.serving())
        except BaseException:
            self.failure = True
            self.ready.set()

    def __enter__(self):
        self.thread.start()
        try:
            require(self.ready.wait(10) and not self.failure and self.port is not None,
                    'qualification.fault.relay-not-ready')
            for address in sorted(self.approved):
                self.add('iptables', 'nat', ['-A', 'OUTPUT', '-m', 'owner', '--uid-owner', GATEWAY_UID,
                    '-p', 'tcp', '-d', address, '--dport', 443, '-j', 'REDIRECT', '--to-ports', self.port])
            # An alternate IPv6 route must not evade the held response. Reject
            # only this provider's addresses; custody and database stay usable.
            for address in sorted(self.ipv6):
                self.add('ip6tables', 'filter', ['-A', 'OUTPUT', '-m', 'owner', '--uid-owner', GATEWAY_UID,
                    '-p', 'tcp', '-d', address, '--dport', 443, '-j', 'REJECT'])
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def held(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            require(not self.failure and self.thread.is_alive(), 'qualification.fault.relay-refused')
            if self.fault.armed and self.fault.held_connections > 0 and self.fault.buffered > 0:
                require(self.witness.entered(), 'qualification.fault.unmeasured-entry')
                return
            time.sleep(0.05)
        require(False, 'qualification.fault.response-not-held')

    def decide(self, decision):
        require(decision in ['drop', 'release'], 'qualification.fault.control-state')
        completed, failed = threading.Event(), []
        def apply():
            try:
                self.fault.decide({'command': decision})
            except BaseException:
                failed.append(True)
            finally:
                completed.set()
        self.loop.call_soon_threadsafe(apply)
        require(completed.wait(5) and not failed, 'qualification.fault.control-state')

    def __exit__(self, kind, value, traceback):
        # First remove routing, then finish retained encrypted connections.
        try:
            super().__exit__(kind, value, traceback)
        finally:
            self.finished.set()
            self.thread.join(timeout=10)
            require(not self.thread.is_alive(), 'qualification.fault.relay-stop')
