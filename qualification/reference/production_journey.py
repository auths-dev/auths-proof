"""One root operator session across separately reviewed authority exchanges.

The original installed author, provider ledger and measurements survive both
protected stages. Mailboxes contain bounded public data only; native authority
verification stays mandatory. No missing operation can close a phase.
"""

import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import airtable_record
import stripe_platform
from common import closed, digest, Refusal, require, sha256
import controller_socket
from expand import child, decode, read
from family_corpus import authenticate, compile_plan, RESOURCES
from family_harness import ROOT
from family_operations import Operations
from custody_fault import Faults
from generate_families import generate
from network_fault import Isolation
from packet_plan import prepare as prepare_packets
from production_environment import Infrastructure
from production_setup import Deployment
from provider_readback import ReadBack
from retained_author import RetainedAuthor
from resource_io import write, write_bytes
from stripe_resources import Resources as StripeResources
from airtable_resources import Resources as AirtableResources

sys.path.insert(0, str(ROOT / 'qualification/run'))
import artifact_wait
import close_proposal
import scan_publication

ENVIRONMENT = 'gateway-custody-live'
PHASES = ['prepare', 'commission', 'import-first', 'live', 'cleanup', 'final-proposal']
GITHUB_INPUTS = ['GITHUB_REPOSITORY', 'GITHUB_EVENT_NAME', 'GITHUB_REF', 'GITHUB_RUN_ID',
                 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA', 'GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT']


def provider_keys(family, environment):
    """Reject absent or fake rotation before any infrastructure/provider write."""
    stripe = family == stripe_platform.FAMILY
    require(stripe or family == airtable_record.FAMILY, 'qualification.journey.family')
    names = ['STRIPE_QUALIFICATION_RUNTIME_KEY', 'STRIPE_QUALIFICATION_NEXT_RUNTIME_KEY'] if stripe \
        else ['AIRTABLE_QUALIFICATION_TOKEN', 'AIRTABLE_QUALIFICATION_NEXT_TOKEN']
    result = []
    for name in names + (['STRIPE_QUALIFICATION_SETUP_KEY'] if stripe else []):
        value = environment.get(name)
        prefix = 'sk_test_' if name.endswith('SETUP_KEY') else 'rk_test_' if stripe else 'pat'
        require(type(value) is str and value.startswith(prefix) and 20 <= len(value) <= 2048
                and all(33 <= ord(character) <= 126 for character in value),
                'qualification.journey.provider-key')
        result.append(value.encode())
    require(result[0] != result[1], 'qualification.journey.genuine-rotation-required')
    return result


class Journey:
    def __init__(self, family, root, binary, issuer, python, kit, wheel, node, script, package, environment):
        require(sys.platform == 'linux' and os.getuid() == 0, 'qualification.journey.identity')
        self.run, self.attempt, self.commit = artifact_wait.identity(environment)
        require(environment.get('GITHUB_ACTIONS') == 'true'
                and environment.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'qualification.journey.host')
        self.family, self.root = family, Path(root).absolute()
        self.keys = provider_keys(family, environment)
        require(not self.root.exists() and self.root.resolve() == self.root
                and not self.root.is_relative_to(ROOT), 'qualification.journey.private-directory')
        self.binary, self.issuer, self.python, self.kit, self.wheel, self.node, self.script, self.package = [
            Path(path).absolute() for path in [binary, issuer, python, kit, wheel, node, script, package]]
        self.environment = {name: environment[name] for name in GITHUB_INPUTS}
        # The infrastructure consumes OIDC only; no provider key is put in its
        # environment, any native child or the credential-free author.
        self.identity_environment = {**self.environment, **{name: environment[name] for name in
            ['ACTIONS_ID_TOKEN_REQUEST_URL', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN']}}
        self.root.mkdir(mode=0o700)
        self.work = self.root / 'publication'
        self.work.mkdir(mode=0o700)
        (self.work / 'cases').mkdir(mode=0o700)
        self.mailboxes = self.root / 'mailboxes'
        self.mailboxes.mkdir(mode=0o700)
        # Author/gateway UIDs need traversal of their own private descendants.
        # Publication and mailboxes remain root-only underneath this parent.
        os.chmod(self.root, 0o711)
        self.controller = self.root / 'control'
        self.controller.mkdir(mode=0o700)
        self.endpoint = self.controller / 'operations.sock'
        require(len(str(self.endpoint).encode()) <= 107, 'qualification.journey.socket-bound')
        self.canaries = list(self.keys)
        self.infrastructure = self.author = self.deployment = self.isolation = self.resources = None
        self.operations = self.worker = None
        self.stopping, self.ready = threading.Event(), threading.Event()
        self.worker_failed = False
        self.next_phase, self.failed, self.retired = 0, False, False
        self.deadline = time.monotonic() + 7200
        self.not_after = int(time.time()) + 7200

    def call(self, arguments, *, environment=None, timeout=120, maximum=65536):
        result = subprocess.run(list(map(str, arguments)), stdin=subprocess.DEVNULL, capture_output=True,
            timeout=timeout, cwd=ROOT, env=environment or {'PATH': '/usr/bin:/bin'})
        require(len(result.stdout) <= maximum and len(result.stderr) <= 65536
                and all(canary not in result.stdout + result.stderr for canary in self.canaries),
                'qualification.journey.private-output')
        require(result.returncode == 0, 'qualification.journey.source-command')
        return result.stdout

    def git(self, *arguments):
        return self.call(['/usr/bin/git', '-c', 'safe.directory=' + str(ROOT), *arguments],
                         maximum=2 * 1024 * 1024)

    def check_source(self):
        generate(check=True)
        require(self.git('rev-parse', 'HEAD').decode().strip() == self.commit
                and not self.git('status', '--porcelain').strip(), 'qualification.journey.source-binding')

    def scan(self):
        payload = b'\n'.join(dict.fromkeys(self.canaries)) + b'\n'
        require(len(payload) <= scan_publication.MAX_BYTES, 'qualification.journey.canary-bound')
        write_bytes(self.work / 'canaries', payload, new=not (self.work / 'canaries').exists())
        scan_publication.scan(self.work, self.issuer, keep_canaries=True)

    def start_controller(self):
        def run():
            try:
                controller_socket.serve(self.endpoint, self.operations, self.deadline, self.stopping, self.ready)
            except BaseException:
                self.worker_failed = True
                self.ready.set()
        self.worker = threading.Thread(target=run, name='auths-family-operations', daemon=True)
        self.worker.start()
        require(self.ready.wait(10) and not self.worker_failed and self.worker.is_alive(),
                'qualification.journey.controller-not-ready')

    def stage(self, phase):
        if phase != 'offline':
            require(self.worker is not None and self.worker.is_alive() and not self.worker_failed,
                    'qualification.journey.controller-refused')
            self.infrastructure.check_identity()
            self.operations.begin(phase)
        environment = {'PATH': '/usr/bin:/bin', 'PYTHONNOUSERSITE': '1', **self.environment,
            'AUTHS_GATEWAY': str(self.binary), 'AUTHS_QUALIFICATION': str(self.issuer),
            'AUTHS_QUALIFICATION_CONTROLLER': str(self.endpoint)}
        self.call([self.issuer, 'run-stage', '--phase', phase, '--corpus', self.work / 'corpus.json',
            '--harness', ROOT / 'qualification/families' / self.family / 'harness',
            '--tuple', self.work / 'tuple.json', '--work-dir', self.work], environment=environment, timeout=2400)

    def prepare(self):
        self.check_source()
        for name in ['author_socket.py', 'author_packets.py', 'author_operator.py', 'installed_submit.py', 'application_probe.py']:
            require(read(self.kit / name, 2 * 1024 * 1024) == read(ROOT / 'qualification/reference' / name, 2 * 1024 * 1024),
                    'qualification.journey.consumer-source')
        require(read(self.script, 2 * 1024 * 1024) == read(ROOT / 'qualification/reference/installed_submit.mjs', 2 * 1024 * 1024),
                'qualification.journey.consumer-source')
        self.infrastructure = Infrastructure(self.root / 'infrastructure', self.identity_environment, self.canaries)
        self.infrastructure.start_identity()
        self.infrastructure.synchronize_clock()
        production = self.infrastructure.start_database()
        self.isolation = Isolation()
        self.isolation.__enter__()
        self.resources = StripeResources({'runtime': self.keys[0].decode(), 'setup': self.keys[2].decode()}) \
            if self.family == stripe_platform.FAMILY else AirtableResources(self.keys[0].decode())
        self.journal = self.controller / 'resources.json'
        self.resources.prepare('recipe-qualification/' + self.run + '/' + self.attempt,
                               RESOURCES, self.journal, self.work / 'resources.json')
        prepare_packets(SimpleNamespace(family=self.family, resources=self.work / 'resources.json',
                                       gateway=self.binary, work=self.work))
        self.author = RetainedAuthor(self.python, self.kit, self.work, self.root / 'packet-author')
        carrier = decode(read(self.work / 'public-packets.json', 65536))
        # Original proofs are deliberately five minutes; only a source label
        # can refresh them within the separately bounded two-hour action plan.
        plan = decode(read(self.work / 'packet-plan.json', 65536))
        self.not_after = min(self.not_after, plan['not_after'])
        self.deadline = min(self.deadline, time.monotonic() + self.not_after - time.time())
        require(time.time() < self.not_after, 'qualification.journey.author-expired')
        contract = self.call([self.issuer, 'contract-id', '--contract',
                             ROOT / 'qualification/families' / self.family / 'contract.json']).decode().strip()
        digest(contract)
        tuple_value = child(self.binary, ['qualification-candidate', '--recipe', self.work / 'recipe.json',
            '--profile-lock', self.work / 'profile.lock.json', '--recipe-family', self.family,
            '--provider-contract-id', contract])
        write(self.work / 'tuple.json', tuple_value, new=True)
        self.call([self.python, '-B', self.kit / 'author_operator.py', '--gateway', self.binary, '--work', self.work])
        resources, reviewed = authenticate(self.family, self.work, self.binary, tuple_value)
        operator = decode(read(self.work / 'operator-report.json', 65536))
        require(all(operator['operator_principal'] not in value['actors'] for value in reviewed.values()),
                'qualification.journey.operator-separation')
        write(self.work / 'corpus.json', compile_plan(self.family, resources, reviewed,
                                                   tuple_value['compiled_recipe_sha256']), new=True)
        self.packages(tuple_value)
        self.stage('offline')
        self.offline_evidence()
        write(self.work / 'facts.json', {'commit': self.commit,
            'source_closure_sha256': sha256(self.git('ls-tree', '-r', 'HEAD')),
            'generated_artifacts_sha256': sha256(read(self.binary, 256 * 1024 * 1024)
                                               + read(self.issuer, 256 * 1024 * 1024)),
            'recipe_decision_record_sha256': sha256(read(ROOT / 'qualification/families' / self.family / 'decision-record.md', 65536)),
            'corpus_manifest_sha256': sha256(read(self.work / 'corpus.json', 2 * 1024 * 1024))}, new=True)
        self.deployment = Deployment(self.binary, self.work, self.root / 'deployment', production, self.canaries)
        account = resources['platform'] if self.family == stripe_platform.FAMILY else 'airtable-qualification'
        self.deployment.install(self.keys[0], account)
        for host in [0, 1]:
            for context in [0, 1]:
                self.deployment.start(host, context)
        self.operations = Operations(self.deployment, self.author,
            ReadBack(self.family, resources, self.keys[0].decode()), resources, reviewed)
        self.operations.configure_rotation(self.keys[0], self.keys[1])
        self.operations.configure_consumers(self.python, self.kit)
        self.operations.configure_typescript(self.node, self.script)
        self.start_controller()
        self.scan()

    def packages(self, tuple_value):
        author = decode(read(self.work / 'author-report.json', 65536))
        package = decode(read(self.package / 'package.json', 65536))
        closed(package, ['schema', 'source_commit', 'name', 'version', 'file', 'sha256', 'qualification_issued'])
        require(package['schema'] == 'auths.qualification-installed-package/1'
                and package['source_commit'] == self.commit and package['name'] == '@auths-dev/sdk'
                and package['qualification_issued'] is False
                and type(package['file']) is str and Path(package['file']).name == package['file']
                and package['file'].endswith('.tgz')
                and sha256(read(self.package / package['file'], 64 * 1024 * 1024)) == digest(package['sha256']),
                'qualification.journey.typescript-package')
        write(self.work / 'packages.json', sorted([
            {'name': 'auths', 'version': author['sdk_version'], 'sha256': sha256(read(self.wheel, 64 * 1024 * 1024))},
            {'name': 'auths-gateway', 'version': tuple_value['target']['gateway_version'],
             'sha256': tuple_value['target']['gateway_build_sha256']},
            {'name': package['name'], 'version': package['version'], 'sha256': package['sha256']},
        ], key=lambda package: package['name']), new=True)

    def offline_evidence(self):
        directory = self.work / 'offline'
        directory.mkdir(mode=0o700)
        for member in ['conformance', 'differential']:
            self.call([self.issuer, 'evidence', '--member', member, '--tuple', self.work / 'tuple.json',
                '--commit', self.commit, '--cases', self.work / 'cases' / (member + '.offline.json'),
                '--out', directory / (member + '.json')])

    def commission(self):
        self.deployment.register_commissioning(self.mailboxes / 'commissioning-permit')
        self.stage('commissioning')
        self.scan()
        close_proposal.close(self.family, self.work, ENVIRONMENT, self.run + '-' + self.attempt,
                             'commissioning', self.issuer)

    def import_first(self):
        self.deployment.import_release(self.mailboxes / 'first-release')
        # Each serving process reloads the independently verified installed
        # qualification. No production-policy switch or temporary exception.
        for host in [0, 1]:
            for context in [0, 1]:
                self.deployment.stop(host, context)
                self.deployment.start(host, context)
        self.operations.begin('live')

    def live(self):
        # begin('live') already verified all four ordinary required gates.
        require(self.operations.phase == 'live', 'qualification.journey.first-release-required')
        self.infrastructure.check_identity()
        environment = {'PATH': '/usr/bin:/bin', 'PYTHONNOUSERSITE': '1', **self.environment,
            'AUTHS_GATEWAY': str(self.binary), 'AUTHS_QUALIFICATION': str(self.issuer),
            'AUTHS_QUALIFICATION_CONTROLLER': str(self.endpoint)}
        self.call([self.issuer, 'run-stage', '--phase', 'live', '--corpus', self.work / 'corpus.json',
            '--harness', ROOT / 'qualification/families' / self.family / 'harness',
            '--tuple', self.work / 'tuple.json', '--work-dir', self.work], environment=environment, timeout=2400)
        self.scan()

    def cleanup(self):
        failures = []
        def attempt(action):
            try:
                action()
            except (Refusal, OSError, ValueError, KeyError, subprocess.SubprocessError):
                failures.append(True)
        self.stopping.set()
        if self.worker is not None:
            self.worker.join(timeout=130)
            if self.worker.is_alive():
                failures.append(True)
        if self.deployment is not None:
            attempt(self.deployment.close)
            # Collect while the actual web identity is still renewing. A
            # partial native installation cannot invent a collector result.
            if len(self.deployment.installations) == 4:
                attempt(self.deployment.retire_credentials)
            else:
                def retire_partial():
                    require(not self.deployment.processes, 'qualification.journey.gateway-still-running')
                    self.infrastructure.stop_database()
                    require(self.infrastructure.container is None, 'qualification.journey.database-still-running')
                    existing = self.operations.custody_faults if self.operations is not None else None
                    faults = existing if existing is not None else Faults(self.deployment)
                    faults.retire_partial(self.infrastructure)
                attempt(retire_partial)
        if self.resources is not None and hasattr(self, 'journal') and self.journal.exists():
            attempt(lambda: self.resources.cleanup(self.journal))
        if self.author is not None:
            attempt(self.author.close)
            attempt(self.author.abort)
        if self.isolation is not None:
            attempt(lambda: self.isolation.__exit__(None, None, None))
        if self.infrastructure is not None:
            attempt(self.infrastructure.close)
        self.retired = not failures
        require(self.retired, 'qualification.journey.cleanup-incomplete')

    def final_proposal(self):
        require(self.retired, 'qualification.journey.cleanup-required')
        self.scan()
        close_proposal.close(self.family, self.work, ENVIRONMENT, self.run + '-' + self.attempt,
                             'live', self.issuer)

    def advance(self, phase):
        require(phase in PHASES and not self.failed and self.next_phase < len(PHASES)
                and phase == PHASES[self.next_phase], 'qualification.journey.phase')
        try:
            if phase != 'cleanup':
                require(time.monotonic() < self.deadline and time.time() < self.not_after,
                        'qualification.journey.deadline')
                self.check_source()
            getattr(self, phase.replace('-', '_'))()
            self.next_phase += 1
        except BaseException:
            self.failed = True
            close_proposal.invalidate(self.work)
            raise

    def abort(self):
        self.failed = True
        close_proposal.invalidate(self.work)
        if not self.retired:
            self.cleanup()
