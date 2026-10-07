"""Measured protected operations; absent operations refuse without a report.

The controller retains the effect ledger across native stage-runner children.
Case IDs select only this source's fixed packet labels. Expectations from the
corpus never enter an operation or an observation.
"""

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import socket
import time

import airtable_record
import stripe_platform
from custody_fault import Faults
from common import canonical, closed, Refusal, require, sha256
from expand import child, decode, read
from native_observation import Effects, result as native_result
from network_fault import NativeWitness, ResponseFault
from production_setup import GATEWAY_UID, private_file
from tls_fault import Witness
import measure
from packet_plan import public_pool
from resource_io import write_bytes
import resource_io
import fresh_evidence

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
        self.consumer_node = None
        self.consumer_script = None
        self.budget_refusals = set()
        self.custody_faults = None

    def configure_consumers(self, python, kit):
        self.consumer_python, self.consumer_kit = Path(python).absolute(), Path(kit).absolute()

    def configure_typescript(self, node, script):
        self.consumer_node, self.consumer_script = Path(node).absolute(), Path(script).absolute()

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

    def lose_response(self, phase, label, *, crash=False, observation=False):
        handoff, packet = self.packet(label)
        child = self.deployment.commissioning_child(handoff, packet) if phase == 'commissioning' else None
        witness = Witness(child.witness, GATEWAY_UID, observation=observation) if child is not None \
            else NativeWitness(self.deployment, 0, 0, observation=observation)
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
        resumed = self.deployment.witness(0)
        self.deployment.support()
        return self.completed_probe('gateway-' + ('crash' if crash else 'restart') + '-completed',
                                    resumed, self.deployment.witness(0))

    def budget_race(self, phase, kind):
        require(self.reference is stripe_platform and kind in ['count', 'sum'], 'qualification.operations.step')
        label = phase + '-budget-' + kind
        owner_handoff, packet = self.packet(label)
        other_handoff, other_packet = self.packet(label + '-over')
        require(packet['arguments']['operation_id'] != other_packet['arguments']['operation_id']
                and packet['arguments']['payment_intent'] != other_packet['arguments']['payment_intent'],
                'qualification.operations.budget-binding')
        code = 'gateway.policy.window-exhausted' if kind == 'count' else 'gateway.policy.sum-exhausted'
        children = [self.deployment.commissioning_child(handoff, current, host=host)
                    for host, handoff, current in [(0, owner_handoff, packet), (1, other_handoff, other_packet)]] \
            if phase == 'commissioning' else []
        witness = Witness(children[0].witness, GATEWAY_UID) if children else NativeWitness(self.deployment, 0, 0)
        try:
            with ResponseFault(self.family, witness) as fault, ThreadPoolExecutor(max_workers=1) as pool:
                if children:
                    children[0].start()
                    owner = None
                else:
                    owner = pool.submit(self.deployment.application_submit, owner_handoff, packet, 0)
                fault.held()
                self.wait_for_effect(label)
                if children:
                    children[1].start()
                    competitor = children[1].finish()
                else:
                    before = self.deployment.witness(1)
                    value = self.deployment.application_submit(other_handoff, other_packet, 1)
                    competitor = {'result': value, 'before': before, 'after': self.deployment.witness(1)}
                require(native_result(competitor['result']) == ('refused', code, None),
                        'qualification.operations.budget-refusal')
                fault.decide('release')
                if children:
                    first = children[0].finish()
                    require(witness.entered() and first['before'] == witness.before and first['after'] == witness.last,
                            'qualification.operations.witness-binding')
                else:
                    first = {'result': owner.result(timeout=90), 'before': witness.before,
                             'after': self.deployment.witness(0)}
                observed, fresh = self.effects.project_budget_race(self.tuple, self.reviewed[label], self.resources,
                    first['result'], competitor['result'],
                    [(first['before'], first['after']), (competitor['before'], competitor['after'])],
                    self.oracle.fresh(self.reviewed[label], self.tuple['compiled_recipe_sha256']), code)
                self.budget_refusals.add((phase, kind))
                return self.observation(observed, fresh)
        finally:
            for child in children:
                child.abort()

    def budget_probe(self, phase, kind):
        require((phase, kind) in self.budget_refusals, 'qualification.operations.budget-not-raced')
        handoff, packet = self.packet(phase + '-budget-' + kind + '-over')
        code = 'gateway.policy.window-exhausted' if kind == 'count' else 'gateway.policy.sum-exhausted'
        before = self.deployment.witness(1)
        if phase == 'commissioning':
            execution = self.deployment.commissioning_submit(handoff, packet, host=1)
            value = execution['result']
            measured_before, measured_after = execution['before'], execution['after']
        else:
            value = self.deployment.application_submit(handoff, packet, host=1)
            measured_before, measured_after = before, self.deployment.witness(1)
        require(native_result(value) == ('refused', code, None)
                and all(count == 0 for count in measure.delta(measured_before, measured_after).values()),
                'qualification.operations.budget-refusal')
        return self.completed_probe('budget-' + kind + '-refusal-confirmed', before, self.deployment.witness(1))

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

    def completed_probe(self, code, before, after):
        # Completion is constructed only after that source operation returned
        # actual native/provider facts; a corpus's expected code is never read.
        counted = measure.delta(before, after)
        return self.observation({'verdict': {'outcome': 'complete', 'code': code,
            'request_sha256': None, 'evidence_sha256': None},
            'credential_leases': counted['credential_lease_calls'],
            'provider_entries': counted['write_transport_entries'], 'confirmed_by_read_back': 0})

    def rotate(self):
        require(self.rotation_keys is not None, 'qualification.operations.genuine-rotation-required')
        successor = next(key for key in self.rotation_keys if key != self.current_credential)
        before = self.deployment.witness(0)
        result = self.deployment.rotate(successor)
        require(result.get('ok') is True and result.get('code') == 'gateway.admin.rotated',
                'qualification.operations.rotation-refused')
        self.current_credential = successor
        return self.completed_probe('provider-secret-rotated', before, self.deployment.witness(0))

    def custody(self, phase, kind):
        require(kind in ['kind', 'generation', 'commitment', 'version'] and self.rotation_keys is not None,
                'qualification.operations.custody-input')
        if self.custody_faults is None:
            self.custody_faults = Faults(self.deployment)
        before = self.deployment.witness(0)
        if kind == 'kind':
            self.custody_faults.kind()
            after = self.deployment.witness(0)
        else:
            successor = next(key for key in self.rotation_keys if key != self.current_credential)
            handoff, packet = self.packet(phase + '-custody-' + kind)
            with self.custody_faults.drift(kind, self.current_credential, successor):
                if phase == 'commissioning':
                    execution = self.deployment.commissioning_submit(handoff, packet)
                    result, before, after = execution['result'], execution['before'], execution['after']
                else:
                    result = self.deployment.application_submit(handoff, packet)
                    after = self.deployment.witness(0)
                require(native_result(result) == ('refused', 'gateway.connection.credential-generation-missing', None),
                        'qualification.operations.custody-not-refused')
        counted = measure.delta(before, after)
        require(counted['credential_lease_calls'] == counted['write_transport_entries'] == 0,
                'qualification.operations.custody-entered')
        report = {'schema': 'auths.qualification-custody-probe/1', 'family': self.family,
            'protected_run': self.resources['protected_run'], 'phase': phase, 'kind': kind,
            'native_code': 'gateway.credential.production-plaintext-refused' if kind == 'kind'
                           else 'gateway.connection.credential-generation-missing',
            'credential_leases': counted['credential_lease_calls'], 'provider_entries': counted['write_transport_entries'],
            'fixture_edits_to_connection_or_host_floors': 0}
        directory = self.deployment.work / 'custody-probes'
        directory.mkdir(mode=0o700, exist_ok=True)
        resource_io.write(directory / (phase + '-' + kind + '.json'), report, new=True)
        return self.completed_probe('custody-' + kind + '-refused', before, after)

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

    def typescript_consumer(self, phase):
        require(self.consumer_node is not None and self.consumer_script is not None,
                'qualification.operations.installed-typescript-not-configured')
        label = phase + '-12'
        handoff, packet = self.packet(label)
        before = self.deployment.witness(0)
        result = self.deployment.installed_typescript_submit(self.consumer_node, self.consumer_script, handoff, packet)
        return self.project(label, result, before, self.deployment.witness(0))

    def inspect_consumer(self, language, probe):
        require(probe in ['no-source', 'no-token'], 'qualification.operations.step')
        if language == 'python':
            require(self.consumer_python is not None and self.consumer_kit is not None,
                    'qualification.operations.installed-python-not-configured')
            executable, script = self.consumer_python, self.consumer_kit / 'installed_submit.py'
        else:
            require(language == 'typescript' and self.consumer_node is not None and self.consumer_script is not None,
                    'qualification.operations.installed-typescript-not-configured')
            executable, script = self.consumer_node, self.consumer_script
        before = self.deployment.witness(0)
        value = self.deployment.inspect_consumer(executable, script, language)
        closed(value, ['schema', 'language', 'package_name', 'version', 'installation', 'module_sha256',
                       'repository_imported', 'provider_token_received'])
        require(value['schema'] == 'auths.qualification-consumer-provenance/1'
                and value['language'] == language
                and value['package_name'] == ('auths' if language == 'python' else '@auths-dev/sdk')
                and value['installation'] == ('site-packages' if language == 'python' else 'node_modules')
                and value['repository_imported'] is False and value['provider_token_received'] is False,
                'qualification.operations.consumer-provenance')
        packages = decode(read(self.deployment.work / 'packages.json', 65536))
        require(type(packages) is list and len([package for package in packages
                if package['name'] == value['package_name'] and package['version'] == value['version']]) == 1,
                'qualification.operations.consumer-version')
        from common import digest
        digest(value['module_sha256'])
        counts = measure.delta(before, self.deployment.witness(0))
        return self.observation({'verdict': {'outcome': 'complete',
            'code': 'installed-package-provenance-confirmed' if probe == 'no-source' else 'provider-token-absent',
            'request_sha256': None, 'evidence_sha256': None},
            'credential_leases': counts['credential_lease_calls'], 'provider_entries': counts['write_transport_entries'],
            'confirmed_by_read_back': 0})

    def application_boundary(self, identifier):
        require(self.consumer_python is not None and self.consumer_kit is not None,
                'qualification.operations.installed-python-not-configured')
        if identifier == 'isolation':
            # Root first verifies these actual private files exist with the
            # native owner/mode. ENOENT cannot masquerade as denied access.
            values = [private_file(path, GATEWAY_UID) for path in [
                self.deployment.operator_token, self.deployment.runtime_token,
                self.deployment.state(0) / 'installation.json']]
            kind, code = 'files', 'application-secret-access-refused'
        else:
            require(identifier == 'direct-provider', 'qualification.operations.step')
            origin = 'api.stripe.com' if self.reference is stripe_platform else 'api.airtable.com'
            addresses = {item[4][0] for item in socket.getaddrinfo(origin, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)}
            require(1 <= len(addresses) <= 32 and all(ipaddress.ip_address(value).is_global for value in addresses),
                    'qualification.operations.provider-address')
            values = [address for version in [4, 6] for address in
                sorted(value for value in addresses if ipaddress.ip_address(value).version == version)[:2]]
            require(any(ipaddress.ip_address(value).version == 4 for value in values),
                    'qualification.operations.provider-address')
            kind, code = 'egress', 'direct-provider-access-refused'
        before = self.deployment.witness(0)
        self.deployment.application_probe(self.consumer_python, self.consumer_kit, kind, values)
        return self.completed_probe(code, before, self.deployment.witness(0))

    def guard(self, phase, identifier):
        label = phase + '-' + identifier
        handoff, packet = self.packet(label)
        if phase == 'commissioning':
            execution = self.deployment.commissioning_submit(handoff, packet)
            value, before, after = execution['result'], execution['before'], execution['after']
        else:
            before = self.deployment.witness(0)
            value = self.deployment.application_submit(handoff, packet)
            after = self.deployment.witness(0)
        observed, fresh = self.effects.project_guard_refusal(self.tuple, self.reviewed[label], self.resources,
                                                             value, before, after)
        return self.observation(observed, fresh)

    def capabilities(self, phase):
        label = phase + '-10'
        reviewed = self.reviewed[label]
        effect = (self.family, self.resources['protected_run'], reviewed['arguments']['operator_namespace'],
                  reviewed['arguments']['operation_id'])
        require(effect in self.effects.entries and self.effects.entries[effect]['confirmed'] is True,
                'qualification.operations.capability-unconfirmed-effect')
        before = self.deployment.witness(0)
        # A capability probe follows the actual native linked effect. It
        # cannot pre-seed matching state that would conceal a failed write.
        first = self.oracle.fresh(reviewed, self.tuple['compiled_recipe_sha256'])
        measured = {'schema': 'auths.qualification-provider-capability-probes/1',
            'family': self.family, 'protected_run': self.resources['protected_run'],
            'request_sha256': sha256(canonical(reviewed['request'])),
            'fixture_duplicate_api_entries': 0, 'additional_effects': 0,
            'refused_reads': []}
        if self.reference is stripe_platform:
            require(self.current_credential is not None and self.current_credential.startswith(b'rk_test_'),
                    'qualification.operations.runtime-credential')
            key = self.current_credential.decode()
            headers = {'Stripe-Version': '2025-03-31.basil'}
            balance = resource_io.request('https://api.stripe.com', 'GET', '/v1/balance', key, headers=headers)
            account = resource_io.request('https://api.stripe.com', 'GET', '/v1/account', key, headers=headers)
            require(balance.get('livemode') is False and account.get('id') == self.resources['platform'],
                    'qualification.operations.account-guard')
            for path in ['/v1/customers', '/v1/payouts']:
                status, _private = resource_io.exchange('https://api.stripe.com', 'GET', path, key, headers=headers)
                require(status == 403, 'qualification.operations.denied-read-permission')
                measured['refused_reads'].append({'path': path, 'status': status})
            # The authorized test reference retries only this already observed
            # run-owned request, using the same runtime key and idempotency key.
            # This is explicitly a fixture API call, outside the native counter
            # scope. It is retained rather than hidden in gateway measurements.
            request = stripe_platform.request(reviewed['arguments'], self.resources,
                reviewed['action_commitment'], self.tuple['compiled_recipe_sha256'])
            require(request == reviewed['request'], 'qualification.operations.request-binding')
            duplicate = resource_io.request('https://api.stripe.com', 'POST', '/v1/refunds', key,
                request['body'].encode(), {**dict(request['headers']), 'Content-Type': request['content_type']})
            prior = fresh_evidence.decode(first)
            require(duplicate.get('id') == prior['id'], 'qualification.operations.idempotency-new-effect')
            fresh_evidence.witness(self.family, reviewed['arguments'], self.resources,
                reviewed['action_commitment'], self.tuple['compiled_recipe_sha256'], canonical(duplicate))
            measured['fixture_duplicate_api_entries'] = 1
        final = self.oracle.fresh(reviewed, self.tuple['compiled_recipe_sha256'])
        require(fresh_evidence.decode(final).get('id') == fresh_evidence.decode(first).get('id'),
                'qualification.operations.capability-effect-changed')
        directory = self.deployment.work / 'provider-capability-probes'
        directory.mkdir(mode=0o700, exist_ok=True)
        write_bytes(directory / (phase + '.json'), canonical(measured), new=True)
        return self.completed_probe('provider-capabilities-confirmed', before, self.deployment.witness(0))

    def step(self, case, index, operation):
        require(type(case) is str and type(index) is int and type(operation) is str,
                'qualification.operations.step')
        phase, separator, identifier = case.partition('-')
        require(separator and phase in ['commissioning', 'live'] and self.phase == phase,
                'qualification.operations.phase')
        require((case, index) not in self.started, 'qualification.operations.repeated-step')
        self.started.add((case, index))
        if self.reference is airtable_record:
            resource_io.pace_airtable()
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
        elif identifier == 'capabilities':
            require(index in [0, 1] and operation == ['submit', 'probe'][index], 'qualification.operations.step')
            if index == 1:
                require((case, 0) in self.completed, 'qualification.operations.order')
            result = self.submit(phase, phase + '-10') if index == 0 else self.capabilities(phase)
        elif identifier == 'two-host-race':
            require(index == 0 and operation == 'race', 'qualification.operations.step')
            result = self.race(phase, phase + '-02')
        elif identifier in ['budget-count', 'budget-sum']:
            require(index in [0, 1] and operation == ['race', 'probe'][index], 'qualification.operations.step')
            kind = identifier.removeprefix('budget-')
            if index == 1:
                require((case, 0) in self.completed, 'qualification.operations.order')
            result = self.budget_race(phase, kind) if index == 0 else self.budget_probe(phase, kind)
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
        elif identifier in ['ambiguous', 'response-loss', 'visibility']:
            ending = 'replay' if identifier == 'ambiguous' else 'read-back'
            first = 'delay-visibility' if identifier == 'visibility' else 'drop-response'
            require(index in [0, 1] and operation == [first, ending][index],
                    'qualification.operations.step')
            label = phase + '-' + str(POSITIVES[identifier]).zfill(2)
            if index == 0:
                # Visibility withholds the actual observation response after
                # the second native credential lease. The write response and
                # its verified locator have already reached durable state.
                result = self.lose_response(phase, label, observation=identifier == 'visibility')
            else:
                require((case, 0) in self.completed, 'qualification.operations.order')
                result = self.submit(phase, label) if ending == 'replay' else self.read_back(label)
        elif identifier in ['guard-ceiling', 'guard-currency']:
            require(self.reference is stripe_platform and index == 0 and operation == 'probe',
                    'qualification.operations.step')
            result = self.guard(phase, identifier)
        elif identifier in ['custody-kind', 'custody-generation', 'custody-commitment', 'custody-version']:
            require(index == 0 and operation == 'probe', 'qualification.operations.step')
            result = self.custody(phase, identifier.removeprefix('custody-'))
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
        elif identifier in ['isolation', 'direct-provider']:
            require(index == 0 and operation == 'probe', 'qualification.operations.step')
            result = self.application_boundary(identifier)
        elif identifier == 'installed-typescript':
            require(index == 0 and operation == 'installed-consumer', 'qualification.operations.step')
            result = self.typescript_consumer(phase)
        elif identifier in ['python-no-source', 'python-no-token', 'typescript-no-source', 'typescript-no-token']:
            require(index == 0 and operation == 'installed-consumer', 'qualification.operations.step')
            language, _, probe = identifier.partition('-')
            result = self.inspect_consumer(language, probe)
        elif identifier == 'installed-python':
            require(index == 0 and operation == 'installed-consumer', 'qualification.operations.step')
            result = self.python_consumer(phase)
        else:
            require(False, 'qualification.operations.not-implemented')
        self.completed.add((case, index))
        return result
