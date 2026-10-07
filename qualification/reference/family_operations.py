"""Measured protected operations; absent operations refuse without a report.

The controller retains the effect ledger across native stage-runner children.
Case IDs select only this source's fixed packet labels. Expectations from the
corpus never enter an operation or an observation.
"""

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import time

import airtable_record
import stripe_platform
from common import canonical, closed, Refusal, require, sha256
from expand import child, decode, read
from native_observation import Effects
from network_fault import NativeWitness, ResponseFault
from production_setup import GATEWAY_UID
from tls_fault import Witness
import measure
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
        self.interrupted = set()

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
        response = self.deployment.reobserve(self.reviewed[label]['arguments']['operation_id'])
        after = self.deployment.witness(0)
        if response['ok']:
            return self.project(label, response['result'], before, after)
        if label.endswith('-09'):
            observed, fresh = self.effects.project_admin_refusal(self.tuple, self.reviewed[label], self.resources,
                                                                response, before, after)
        else:
            require(self.reference is stripe_platform, 'qualification.operations.recovery-refused')
            observed, fresh = self.effects.project_stored_unknown(self.tuple, self.reviewed[label], self.resources,
                sha256(read(self.deployment.work / self.packets[label]['trusted_context'], 4 * 1024 * 1024)),
                self.deployment.support(), before, after)
        return self.observation(observed, fresh)

    def wait_for_effect(self, label):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                return self.oracle.fresh(self.reviewed[label], self.tuple['compiled_recipe_sha256'])
            except Refusal:
                # No mismatch can become a confirmation. A bounded retry
                # lets the independent read observe a just-entered write.
                time.sleep(0.5)
        require(False, 'qualification.operations.effect-not-independently-observed')

    def lose_response(self, phase, label, *, crash=False):
        handoff, packet = self.packet(label)
        child = self.deployment.commissioning_child(handoff, packet) if phase == 'commissioning' else None
        witness = Witness(child.witness, GATEWAY_UID) if child is not None else NativeWitness(self.deployment, 0, 0)
        try:
            with ResponseFault(self.family, witness) as fault, ThreadPoolExecutor(max_workers=1) as pool:
                if child is not None:
                    child.start()
                    pending = None
                else:
                    pending = pool.submit(self.deployment.application_submit, handoff, packet)
                fault.held()
                self.wait_for_effect(label)
                if crash:
                    if child is not None:
                        child.crash()
                    else:
                        self.deployment.stop(0, crash=True)
                    # Preserve the killed owner's last actual scope. Its
                    # durable record is read by a separate native command.
                    before, after = witness.before, witness.last
                    support = self.deployment.support()
                    observed, fresh = self.effects.project_interrupted(self.tuple, self.reviewed[label],
                        self.resources, sha256(read(self.deployment.work / packet['trusted_context'], 4 * 1024 * 1024)),
                        support, before, after)
                    self.interrupted.add((phase, label))
                    fault.decide('drop')
                    if pending is not None:
                        try:
                            pending.result(timeout=10)
                        except (Refusal, OSError):
                            pass  # The stored native diagnostic, not this failure, is the evidence.
                    return self.observation(observed, fresh)
                fault.decide('drop')
                if child is not None:
                    execution = child.finish()
                    require(witness.entered() and execution['before'] == witness.before
                            and execution['after'] == witness.last,
                            'qualification.operations.witness-binding')
                    return self.project(label, execution['result'], execution['before'], execution['after'])
                result = pending.result(timeout=90)
                return self.project(label, result, witness.before, self.deployment.witness(0))
        finally:
            if child is not None:
                child.abort()

    def race(self, phase, label):
        handoff, packet = self.packet(label)
        children = [self.deployment.commissioning_child(handoff, packet, host=host)
                    for host in [0, 1]] if phase == 'commissioning' else []
        witness = Witness(children[0].witness, GATEWAY_UID) if children else NativeWitness(self.deployment, 0, 0)
        try:
            with ResponseFault(self.family, witness) as fault, ThreadPoolExecutor(max_workers=2) as pool:
                if children:
                    children[0].start()
                    owner = None
                else:
                    owner = pool.submit(self.deployment.application_submit, handoff, packet, 0)
                fault.held()
                self.wait_for_effect(label)
                # The follower finishes while the entered owner's response
                # remains held. Its actual result and scope cannot be confused
                # with the eventual owner's response or a process-local stub.
                if children:
                    children[1].start()
                    follower = children[1].finish()
                else:
                    follower_before = self.deployment.witness(1)
                    follower_result = self.deployment.application_submit(handoff, packet, 1)
                    follower = {'result': follower_result, 'before': follower_before,
                                'after': self.deployment.witness(1)}
                fault.decide('release')
                if children:
                    first = children[0].finish()
                    require(witness.entered() and first['before'] == witness.before
                            and first['after'] == witness.last, 'qualification.operations.witness-binding')
                else:
                    first = {'result': owner.result(timeout=90), 'before': witness.before,
                             'after': self.deployment.witness(0)}
                observed, fresh = self.effects.project_race(self.tuple, self.reviewed[label], self.resources,
                    [first['result'], follower['result']],
                    [(first['before'], first['after']), (follower['before'], follower['after'])],
                    self.oracle.fresh(self.reviewed[label], self.tuple['compiled_recipe_sha256']))
                return self.observation(observed, fresh)
        finally:
            for child in children:
                child.abort()

    def resume_host(self, phase, label, *, crash):
        if crash:
            require((phase, label) in self.interrupted, 'qualification.operations.owner-not-interrupted')
            if phase == 'live':
                self.deployment.start(0)
            else:
                # The commissioning child was the actual owner. The running
                # application process is deliberately still subject to its
                # required production gate; reload its durable shared state.
                self.deployment.stop(0)
                self.deployment.start(0)
        else:
            before = self.deployment.witness(0)
            self.deployment.stop(0)
            self.deployment.start(0)
            require(self.deployment.witness(0)['scope'] != before['scope'],
                    'qualification.operations.restart-scope')
        return self.completed_probe('gateway-' + ('crash' if crash else 'restart') + '-completed')

    def doctor(self):
        require(self.phase == 'live', 'qualification.operations.phase')
        for host in [0, 1]:
            for context in [0, 1]:
                require(self.deployment.command(['qualification-status', '--state-dir',
                    self.deployment.state(host, context), '--tuple']) == self.tuple,
                    'qualification.operations.doctor-tuple')
        before = self.deployment.witness(0)
        report, raw = self.deployment.doctor()
        closed(report, ['schema', 'ready', 'checks'])
        expected = [{'check': name, 'ready': True, 'code': None} for name in [
            'trust', 'store', 'recipe', 'qualification', 'provider-secret-custody',
            'connection-generation', 'clock', 'transport-policy', 'operator-plane-isolation']]
        expected += [{'check': 'observer-custody', 'state': 'not-configured'}]
        require(report['ready'] is True and type(report['checks']) is list
                and all(type(item) is dict and item.get('ready') is True for item in report['checks'][:-1])
                and report == {'schema': 'auths.gateway-readiness/1', 'ready': True, 'checks': expected},
                'qualification.operations.doctor-not-ready')
        counts = measure.delta(before, self.deployment.witness(0))
        observation = self.observation({'verdict': {'outcome': 'complete', 'code': 'production-readiness-passed',
            'request_sha256': None, 'evidence_sha256': sha256(raw)},
            'credential_leases': counts['credential_lease_calls'], 'provider_entries': counts['write_transport_entries'],
            'confirmed_by_read_back': 0}, {'kind': 'production-doctor',
                'tuple_sha256': sha256(b'auths.qualification-tuple/1\0' + canonical(self.tuple)),
                'report_sha256': sha256(raw)})
        return observation

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
        elif identifier == 'two-host-race':
            require(index == 0 and operation == 'race', 'qualification.operations.step')
            result = self.race(phase, phase + '-02')
        elif identifier in ['restart', 'crash']:
            require(index in [0, 1, 2] and operation == ['submit', identifier, 'replay'][index],
                    'qualification.operations.step')
            label = phase + '-' + str(POSITIVES[identifier]).zfill(2)
            if index:
                require((case, index - 1) in self.completed, 'qualification.operations.order')
            if index == 0:
                result = self.lose_response(phase, label, crash=identifier == 'crash')
            elif index == 1:
                result = self.resume_host(phase, label, crash=identifier == 'crash')
            else:
                result = self.submit(phase, label)
        elif identifier in ['ambiguous', 'response-loss']:
            ending = 'replay' if identifier == 'ambiguous' else 'read-back'
            require(index in [0, 1] and operation == ['drop-response', ending][index],
                    'qualification.operations.step')
            label = phase + '-' + str(POSITIVES[identifier]).zfill(2)
            if index == 0:
                result = self.lose_response(phase, label)
            else:
                require((case, 0) in self.completed, 'qualification.operations.order')
                result = self.submit(phase, label) if ending == 'replay' else self.read_back(label)
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
        elif identifier == 'doctor':
            require(phase == 'live' and index == 0 and operation == 'probe', 'qualification.operations.step')
            result = self.doctor()
        elif identifier == 'installed-python':
            require(index == 0 and operation == 'installed-consumer', 'qualification.operations.step')
            result = self.python_consumer(phase)
        else:
            require(False, 'qualification.operations.not-implemented')
        self.completed.add((case, index))
        return result
