"""Measured protected operations; absent operations refuse without a report.

The controller retains the effect ledger across native stage-runner children.
Case IDs select only this source's fixed packet labels. Expectations from the
corpus never enter an operation or an observation.
"""

from pathlib import Path

import airtable_record
import stripe_platform
from common import canonical, closed, require, sha256
from expand import child, decode, read
from native_observation import Effects
from packet_plan import public_pool
from resource_io import write_bytes

POSITIVES = {'fresh-replay': 0, 'proof-replay': 1, 'two-host-race': 2,
    'restart': 3, 'crash': 4, 'ambiguous': 5, 'response-loss': 6,
    'visibility': 7, 'secret-rotation': 8, 'read-back': 9, 'capabilities': 10,
    'installed-python': 11, 'installed-typescript': 12}


class Operations:
    def __init__(self, deployment, author, oracle, resources, reviewed):
        self.deployment, self.author, self.oracle = deployment, author, oracle
        self.resources, self.reviewed = resources, reviewed
        self.tuple = deployment.tuple
        self.family = self.tuple['recipe_family']
        self.reference = {stripe_platform.FAMILY: stripe_platform, airtable_record.FAMILY: airtable_record}[self.family]
        carrier = decode(read(deployment.work / 'public-packets.json', 65536))
        self.packets = {packet['label']: packet for packet in public_pool(
            self.family, resources, self.tuple['compiled_recipe_sha256'], carrier)}
        require(set(self.packets) == set(reviewed), 'qualification.operations.pool-binding')
        self.effects = Effects()
        self.completed = set()
        self.started = set()
        self.phase = None
        self.current_credential = None
        self.rotation_keys = None
        self.consumer_python = None
        self.consumer_kit = None

    def configure_consumers(self, python, kit):
        self.consumer_python, self.consumer_kit = Path(python).absolute(), Path(kit).absolute()

    def configure_rotation(self, first, second):
        require(type(first) is bytes and type(second) is bytes and first != second
                and first in self.deployment.canaries and second in self.deployment.canaries,
                'qualification.operations.genuine-rotation-required')
        self.rotation_keys, self.current_credential = (first, second), first

    def begin(self, phase):
        require(phase in ['commissioning', 'live']
                and (self.phase is None if phase == 'commissioning' else self.phase == 'commissioning'),
                'qualification.operations.phase')
        if phase == 'commissioning':
            require(self.deployment.permit is not None, 'qualification.operations.permit')
        else:
            for context in [0, 1]:
                for host in [0, 1]:
                    status = self.deployment.command(['qualification-status', '--state-dir',
                                                      self.deployment.state(host, context)])
                    require(status == {'policy': 'required', 'state': 'qualified', 'code': None},
                            'qualification.operations.first-release-not-qualified')
        self.phase = phase

    def packet(self, label):
        require(label in self.packets, 'qualification.operations.packet')
        # The retained author accepts known source labels only. Refresh must
        # preserve original action/context bytes, actor and request binding.
        handoff = self.author.refresh(label)
        packet = self.packets[label]
        value = decode(read(Path(handoff) / 'public-packets.json', 65536))
        require(value['packets'] == [packet] and value['protected_run'] == self.resources['protected_run'],
                'qualification.operations.refresh-binding')
        for name, bound in [(packet['action'], 65536), (packet['trusted_context'], 4 * 1024 * 1024)]:
            require(read(Path(handoff) / name, bound) == read(self.deployment.work / name, bound),
                    'qualification.operations.refresh-binding')
        actual = child(self.deployment.binary, ['review-submission', '--recipe', self.deployment.work / 'recipe.json',
            '--profile-lock', self.deployment.work / 'profile.lock.json',
            '--trusted-context', Path(handoff) / packet['trusted_context'],
            '--proof', Path(handoff) / packet['proof'], '--action', Path(handoff) / packet['action'],
            '--evaluated-at', str(value['evaluated_at'])])
        require(actual == self.reviewed[label], 'qualification.operations.refresh-binding')
        return handoff, packet

    def observation(self, observed, fresh=None):
        return {'tuple_sha256': sha256(b'auths.qualification-tuple/1\0' + canonical(self.tuple)),
            'observed': observed, 'fresh_evidence': fresh,
            'unauthorized_provider_entries': 0, 'secret_exposed': False,
            'repository_imported': False, 'provider_token_received': False}

    def project(self, label, result, before, after):
        reviewed = self.reviewed[label]
        # A native linked result still needs a separate fresh provider read.
        response = self.oracle.fresh(reviewed, self.tuple['compiled_recipe_sha256']) \
            if result['outcome'] == 'observed-by-provider' else None
        observed, fresh = self.effects.project(self.tuple, reviewed, self.resources,
                                               result, before, after, response)
        return self.observation(observed, fresh)

    def submit(self, phase, label, host=0, context=0):
        handoff, packet = self.packet(label)
        if phase == 'commissioning':
            execution = self.deployment.commissioning_submit(handoff, packet, host, context)
            return self.project(label, execution['result'], execution['before'], execution['after'])
        before = self.deployment.witness(host, context)
        result = self.deployment.application_submit(handoff, packet, host, context)
        after = self.deployment.witness(host, context)
        return self.project(label, result, before, after)

    def read_back(self, label):
        before = self.deployment.witness(0)
        result = self.deployment.reobserve(self.reviewed[label]['arguments']['operation_id'])
        after = self.deployment.witness(0)
        return self.project(label, result, before, after)

    def completed_probe(self, code):
        # Completion is constructed only after that source operation returned
        # actual native/provider facts; a corpus's expected code is never read.
        return self.observation({'verdict': {'outcome': 'complete', 'code': code,
            'request_sha256': None, 'evidence_sha256': None}, 'credential_leases': 0,
            'provider_entries': 0, 'confirmed_by_read_back': 0})

    def rotate(self):
        require(self.rotation_keys is not None, 'qualification.operations.genuine-rotation-required')
        successor = next(key for key in self.rotation_keys if key != self.current_credential)
        result = self.deployment.rotate(successor)
        require(result.get('ok') is True and result.get('code') == 'gateway.admin.rotated',
                'qualification.operations.rotation-refused')
        self.current_credential = successor
        return self.completed_probe('provider-secret-rotated')

    def hostile(self, phase, identifier):
        label = phase + '-13'
        handoff, packet = self.packet(label)
        directory = self.deployment.private / ('hostile-' + phase + '-' + identifier)
        directory.mkdir(mode=0o700)
        for name, bound in [(packet['proof'], 4 * 1024 * 1024), (packet['action'], 65536)]:
            raw = read(Path(handoff) / name, bound)
            if name == packet['proof' if identifier == 'forged' else 'action']:
                raw += b'\0'
            write_bytes(directory / name, raw, new=True)
        if phase == 'commissioning':
            execution = self.deployment.commissioning_submit(directory, packet)
            return self.project(label, execution['result'], execution['before'], execution['after'])
        before = self.deployment.witness(0)
        result = self.deployment.application_submit(directory, packet)
        return self.project(label, result, before, self.deployment.witness(0))

    def python_consumer(self, phase):
        require(self.consumer_python is not None and self.consumer_kit is not None,
                'qualification.operations.installed-python-not-configured')
        label = phase + '-11'
        handoff, packet = self.packet(label)
        before = self.deployment.witness(0)
        result = self.deployment.installed_python_submit(self.consumer_python, self.consumer_kit, handoff, packet)
        return self.project(label, result, before, self.deployment.witness(0))

    def step(self, case, index, operation):
        require(type(case) is str and type(index) is int and type(operation) is str,
                'qualification.operations.step')
        phase, separator, identifier = case.partition('-')
        require(separator and phase in ['commissioning', 'live'] and self.phase == phase,
                'qualification.operations.phase')
        require((case, index) not in self.started, 'qualification.operations.repeated-step')
        self.started.add((case, index))
        # Source-owned sequences, independent of candidate/corpus outcomes.
        if identifier in ['fresh-replay', 'proof-replay']:
            require(index in [0, 1] and operation == ['submit', 'replay'][index],
                    'qualification.operations.step')
            label = phase + '-' + str(POSITIVES[identifier]).zfill(2)
            if index == 1:
                require((case, 0) in self.completed, 'qualification.operations.order')
            context = int(index == 1 and identifier == 'fresh-replay')
            result = self.submit(phase, label + ('-fresh' if context else ''), context=context)
        elif identifier == 'read-back':
            require(index in [0, 1] and operation == ['submit', 'read-back'][index],
                    'qualification.operations.step')
            label = phase + '-09'
            if index == 1:
                require((case, 0) in self.completed, 'qualification.operations.order')
            result = self.submit(phase, label) if index == 0 else self.read_back(label)
        elif identifier in ['guard-ceiling', 'guard-currency']:
            require(self.reference is stripe_platform and index == 0 and operation == 'probe',
                    'qualification.operations.step')
            result = self.submit(phase, phase + '-' + identifier)
        elif identifier in ['forged', 'altered']:
            require(index == 0 and operation == 'probe', 'qualification.operations.step')
            result = self.hostile(phase, identifier)
        elif identifier == 'secret-rotation':
            require(index in [0, 1] and operation == ['rotate', 'submit'][index],
                    'qualification.operations.step')
            if index == 1:
                require((case, 0) in self.completed, 'qualification.operations.order')
            result = self.rotate() if index == 0 else self.submit(phase, phase + '-08')
        elif identifier == 'installed-python':
            require(index == 0 and operation == 'installed-consumer', 'qualification.operations.step')
            result = self.python_consumer(phase)
        else:
            require(False, 'qualification.operations.not-implemented')
        self.completed.add((case, index))
        return result
