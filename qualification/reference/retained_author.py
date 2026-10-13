"""Root controller adapter for one isolated installed-SDK author session.

The dedicated UID retains its key in memory. The controller copies public
inputs and outputs only; refresh accepts one original source packet label.
"""

import os
from pathlib import Path
import subprocess
import time

from author_socket import exchange, refresh
from common import require
from expand import decode, read
from packet_plan import public_pool
from resource_io import write_bytes

AUTHOR_UID = 62002


class RetainedAuthor:
    def __init__(self, python, kit, work, private):
        require(os.getuid() == 0, 'qualification.packets.controller-identity')
        self.work, self.private = Path(work).absolute(), Path(private).absolute()
        self.python, self.kit = Path(python).absolute(), Path(kit).absolute()
        require(not self.private.exists() and not self.private.is_relative_to(self.work)
                and self.private.resolve() == self.private,
                'qualification.packets.private-session')
        self.private.mkdir(mode=0o711)
        os.chmod(self.private, 0o711)
        self.author = self.private / 'author'
        self.author.mkdir(mode=0o700)
        self.outputs = self.private / 'handoffs'
        self.outputs.mkdir(mode=0o700)
        for name in ['packet-plan.json', 'resources.json', 'recipe.json', 'profile.lock.json']:
            path = self.author / name
            write_bytes(path, read(self.work / name, 65536), new=True)
            os.chown(path, AUTHOR_UID, AUTHOR_UID)
        os.chown(self.author, AUTHOR_UID, AUTHOR_UID)
        plan = decode(read(self.work / 'packet-plan.json', 65536))
        resources = decode(read(self.work / 'resources.json', 65536))
        self.generation = 0
        self.process = subprocess.Popen([str(self.python), '-B', str(self.kit / 'author_socket.py'),
            'serve', '--plan', str(self.author / 'packet-plan.json'), '--work', str(self.author)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd='/', user=AUTHOR_UID, group=AUTHOR_UID, extra_groups=[],
            env={'PATH': '/usr/bin:/bin', 'PYTHONNOUSERSITE': '1'})
        try:
            deadline = time.monotonic() + 30
            while not (self.author / 'author.sock').exists() and time.monotonic() < deadline:
                require(self.process.poll() is None, 'qualification.packets.author-refused')
                time.sleep(0.05)
            require((self.author / 'author.sock').exists(), 'qualification.packets.author-timeout')
            require(exchange(self.author, 'inspect')['generation'] == 0,
                    'qualification.packets.generation')
            carrier = decode(read(self.author / 'public-packets.json', 65536))
            packets = public_pool(plan['family'], resources, plan['packets'][0]['arguments']['recipe_digest'], carrier)
            self.labels = {packet['label'] for packet in packets}
            names = ['public-packets.json', 'author-report.json', *carrier['trusted_contexts']]
            names += [packet[field] for packet in packets for field in ['proof', 'action']]
            for name in names:
                write_bytes(self.work / name, read(self.author / name, 4 * 1024 * 1024), new=True)
        except BaseException:
            self.abort()
            raise

    def refresh(self, label):
        require(label in self.labels and self.process.poll() is None,
                'qualification.packets.unknown-label')
        self.generation += 1
        destination = self.outputs / ('refresh-' + str(self.generation).zfill(4))
        refresh(self.author, label, destination)
        require(exchange(self.author, 'inspect')['generation'] == self.generation,
                'qualification.packets.generation')
        return destination

    def close(self):
        require(self.process.poll() is None, 'qualification.packets.author-refused')
        exchange(self.author, 'close')
        self.process.wait(timeout=10)
        require(self.process.returncode == 0 and not (self.author / 'author.sock').exists(),
                'qualification.packets.author-refused')

    def abort(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=10)
