#!/usr/bin/env python3
"""Separate operator: disposable resources, independent trust, gateway installation."""
import argparse
import asyncio
from dataclasses import dataclass
import os
import re
from pathlib import Path
import secrets
import signal
import socketserver
import struct
import threading
import subprocess
import sys
import time
from typing import Optional

from auths.adapters.custody import PublicControlEvidence
from auths.authoring import (GrantEvidence, approval_requests, approve, collect_approvals,
                             open_approval_request, propose_mcp_approval, sign_approval_action)
from auths.testkit import development_ed25519_identity_key
from auths.self_hosted import (ExactMcpTool, StringField, IntegerField, OptionalField,
                              ApprovalRequirement, ApproverAnchor, AssurancePolicy,
                              AssuranceRequirement, Permission, Profile, TrustAnchor,
                              TrustedContextRequest, author_root_grant, compile_trusted_context,
                              load_signer_file)
from demo_common import Refusal, b64, canonical, decode, digest, read, require, unb64, write
from app import Application, LABELS, approval_target

HERE = Path(__file__).resolve().parent
HOME = Path('/run/demo')
PRIVATE = HOME / 'private'
JOURNAL = PRIVATE / 'resources.json'
POOL = PRIVATE / 'resource-pool.json'
APP_UID, APP_GID = 62004, 62005
ENVIRONMENT = {'PATH': '/opt/consumer/bin:/usr/local/bin:/usr/bin:/bin', 'PYTHONNOUSERSITE': '1'}
MANAGERS = ('manager-a', 'manager-b', 'manager-c')
READ_TOOLS = ('auths_gateway_candidate_check_v1', 'auths_gateway_recovery_read_v1')
APPROVALS_REQUIRED = 2
ACTION_VALIDITY_SECONDS = 1800


def input_credentials():
    raw = sys.stdin.buffer.read(8193)
    require(0 < len(raw) <= 8192, 'demo.credential-input-bound')
    values = decode(raw)
    require(type(values) is dict and set(values) == {'token'}, 'demo.development-pat-required')
    value = values['token']
    require(type(value) is str and value.startswith('pat') and 20 <= len(value) <= 2048
            and all(33 <= ord(char) <= 126 for char in value), 'demo.development-pat-required')
    # One owner-provided development PAT is shared by setup and gateway.
    # The app never receives it; this is explicitly not rotation/separation proof.
    return {'setup': value, 'runtime': value}



def cleanup_existing():
    require(os.getuid() == 0 and HOME.is_dir() and not HOME.is_symlink()
            and HOME.stat().st_uid == 0, 'demo.operator-private-session-required')
    require(JOURNAL.is_file(), 'demo.resource-journal-unavailable')
    keys = input_credentials()
    sys.path.insert(0, str(HERE / 'reference'))
    from airtable_resources import Resources
    Resources(keys['setup']).cleanup(JOURNAL)
    print('{"status":"run-owned-records-retired","table_and_base_retained":true}')


def child(command, *, stdin=b'', check=True):
    completed = subprocess.run(list(map(str, command)), input=stdin, capture_output=True,
                               timeout=90, env=ENVIRONMENT)
    if check:
        # Never forward provider/private diagnostic output to the web/app.
        require(completed.returncode == 0, 'demo.operator-command-refused:' + str(command[1]))
    return completed


def gateway(binary, *arguments):
    return child([binary, *arguments]).stdout


async def authority(binary, resources, directory, mode):
    app = directory / 'app'
    private = directory / 'private'
    app.mkdir(mode=0o700)
    require(private.is_dir() and not private.is_symlink() and private.stat().st_uid == 0
            and private.stat().st_mode & 0o777 == 0o700, 'demo.operator-private-directory-required')
    for name, parent in [('root', private), ('reader', private), ('actor', app),
                         *((name, private) for name in MANAGERS)]:
        write(parent / (name + '.seed'), secrets.token_bytes(32), new=True)
        write(parent / (name + '.json'), canonical({'schema': 'auths.approval-signer/1',
              'custody': 'development-ed25519', 'seed_file': name + '.seed'}), new=True)
    root = load_signer_file(private / 'root.json').signer
    actor = load_signer_file(app / 'actor.json').signer
    managers = {name: load_signer_file(private / (name + '.json')).signer for name in MANAGERS}
    review = decode(gateway(binary, 'review', '--recipe', HERE / 'recipe.json',
                            '--profile-lock', HERE / 'profile.lock.json'))
    now, expires = int(time.time()), int(time.time()) + 3600
    audience = 'mcp://airtable-gateway-demo'
    permission = Permission('tools/call', audience + '/tools/set_demo_status_v1')
    permissions = (permission,) + tuple(Permission('tools/call', audience + '/tools/' + tool)
                                        for tool in READ_TOOLS)
    policy = AssurancePolicy('raw-key-baseline', tuple(AssuranceRequirement(*row) for row in [
        ('root', 'every', 'self-certifying-identifier'),
        ('actor', 'every', 'self-certifying-identifier'),
        ('actor', 'every', 'offline-verifiable')]))
    grants = {}
    try:
        grant = await author_root_grant(signer=root, subject=actor.descriptor.principal,
            profile=Profile('auths.mcp', 2), permissions=[permission], audiences=[audience],
            not_before=now - 3600, expires_at=expires, remaining_depth=0,
            assurance_floor='raw-key-baseline', requested_at=now)
        grants['default'] = {'bytes': b64(grant.signed_grant), 'evidence': [
            {'type': item.evidence_type, 'media_type': item.media_type, 'bytes': b64(item.bytes)}
            for item in grant.evidence]}
        anchors = [TrustAnchor('operator-root', root.descriptor.principal, ('raw-key-v1',),
                   (Profile('auths.mcp', 2),), permissions, (audience,), (audience,),
                   now - 3600, expires, 1, 'raw-key-baseline')]
        approver_principals = tuple(managers[name].descriptor.principal for name in MANAGERS)
        options = {'anchors': anchors, 'assurance': policy,
                   'configuration': bytes.fromhex(review['verifier_configuration']),
                   'evidence_types': ('raw-key-v1',), 'critical_extensions': (),
                   'approver_anchors': tuple(ApproverAnchor(principal, ('raw-key-v1',),
                       now - 3600, expires) for principal in approver_principals),
                   'approval_requirements': (ApprovalRequirement(approver_principals,
                       APPROVALS_REQUIRED),)}
        reader = load_signer_file(private / 'reader.json').signer
        try:
            read_grant = await author_root_grant(signer=root, subject=reader.descriptor.principal,
                profile=Profile('auths.mcp', 2), permissions=permissions[1:], audiences=[audience],
                not_before=now - 3600, expires_at=expires, remaining_depth=0,
                assurance_floor='raw-key-baseline', requested_at=now)
            write(private / 'read-grant.json', canonical({'bytes': b64(read_grant.signed_grant),
                'evidence': [{'type': item.evidence_type, 'media_type': item.media_type,
                              'bytes': b64(item.bytes)} for item in read_grant.evidence]}), new=True)
        finally:
            await reader.aclose()
        template = compile_trusted_context(**options)
        challenges = [secrets.token_bytes(32), secrets.token_bytes(32)]
        contexts = [compile_trusted_context(**options,
                    request=TrustedContextRequest(audience, challenge, now)) for challenge in challenges]
        cases = {}
        for index, label in enumerate(LABELS):
            cases[label] = {'arguments': {'operator_namespace': 'airtable-demo',
                'operation_id': label, 'recipe_digest': '0' * 64 if label == 'wrong-recipe' else review['recipe_digest'],
                'record_id': '..' if label == 'path-injection' else 'rec../other-record' if label == 'encoded-segment' else resources['records'][{'typescript-positive': 8, 'crash-before': 3, 'crash-after': 7, 'approval-insufficient': 9}.get(label, index)],
                'replacement': 'Pending' if label == 'pending' else 'Rejected' if label == 'unsupported-value' else 'Approved'},
                'evaluation_time': now - 600 if label == 'expired-action' else now,
                'validity_seconds': 300 if label == 'expired-action' else ACTION_VALIDITY_SECONDS}

        async def approval_bundle(label, *, fresh=False):
            case = cases[label]
            grant = grants['default']
            contract, command = approval_target(label, case['arguments'])
            required = 1 if label == 'approval-insufficient' else APPROVALS_REQUIRED
            proposal = propose_mcp_approval(
                contract=contract, command=command, required=required,
                approvers=approver_principals, actor=actor.descriptor.principal,
                actor_grant=unb64(grant['bytes']),
                challenge=challenges[1 if fresh else 0],
                evaluation_time=case['evaluation_time'],
                validity_seconds=case['validity_seconds'])
            issued = approval_requests(proposal)
            responses, first_review = [], None
            for name in MANAGERS:
                signer = managers[name]
                request = next(item for item in issued
                               if item.approver == signer.descriptor.principal)
                reviewed = open_approval_request(request.text, now=case['evaluation_time'])
                response = await approve(reviewed, signer)
                responses.append(response.text)
                if first_review is None:
                    first_review = {'title': reviewed.title,
                        'fields': list(map(list, reviewed.fields)),
                        'display_digest_hex': reviewed.display_digest_hex,
                        'valid_from': reviewed.valid_from, 'valid_until': reviewed.valid_until,
                        'required': reviewed.required}
            require(first_review is not None, 'demo.approval-review-unavailable')
            return {'required': required, 'responses': responses, 'review': first_review}

        approvals = {label: await approval_bundle(label) for label in LABELS}
        approvals['exact:fresh'] = await approval_bundle('exact', fresh=True)
        plan = {'schema': 'auths.airtable-gateway-demo/1', 'mode': mode,
                'trust': 'separate operator-issued development root and actor; no production trust claim',
                'expires_at': expires, 'recipe_digest': review['recipe_digest'],
                'base': resources['base'], 'table': resources['table'], 'view': resources['view'], 'grants': grants,
                'provider_credential_model': 'one owner-provided development PAT for operator and gateway' if mode == 'live' else 'independent simulation runtime and fixture credentials',
                'template': b64(template), 'contexts': list(map(b64, contexts)),
                'challenges': list(map(b64, challenges)), 'cases': cases,
                'approval': {'required': APPROVALS_REQUIRED, 'approvers': list(MANAGERS),
                    'principals': list(approver_principals), 'actor': actor.descriptor.principal,
                    'mode': 'local native signed-response simulator; simulator state is not authority',
                    'reviews': {label: value['review'] for label, value in approvals.items()
                                if not label.endswith(':fresh')}},
                'approvals': approvals}
        write(app / 'application.json', canonical(plan), new=True)
        for index, context in enumerate(contexts):
            write(private / ('context-' + str(index) + '.cbor'), context, new=True)
        for path in app.iterdir():
            os.chown(path, APP_UID, APP_GID)
        os.chown(app, APP_UID, APP_GID)
        return plan
    finally:
        await root.aclose()
        await actor.aclose()
        for signer in managers.values():
            await signer.aclose()


@dataclass(frozen=True)
class CandidateCheck:
    operation_id: str
    operator_namespace: str
    recipe_digest: str
    candidate_connection: str
    expected_previous: Optional[str]
    read_contract: str
    maximum_response_bytes: int


@dataclass(frozen=True)
class RecoveryRead:
    operation_id: str
    operator_namespace: str
    recipe_digest: str
    source_effect: str
    source_operation: str
    read_contract: str
    maximum_response_bytes: int


def read_contract(call):
    """Closed transport shape only; the native gateway owns every read binding."""
    name = call['name']
    require(name in READ_TOOLS, 'demo.unlisted-read-tool')
    command_type = CandidateCheck if name == READ_TOOLS[0] else RecoveryRead
    fields = {key: StringField(min_length=1, max_length=128)
              for key in command_type.__annotations__}
    fields['maximum_response_bytes'] = IntegerField(1, 1048576)
    if command_type is CandidateCheck:
        fields['expected_previous'] = OptionalField(StringField(min_length=64, max_length=64))
    contract = ExactMcpTool(service=call['service'], name=name,
                            command_type=command_type, fields=fields)
    return contract, contract.validate_arguments(call['arguments'])


def operator_consent(directory, name):
    """Bounded owner-only consent for the already saved exact native review.

    The Docker operator reads the complete literal review and signing request
    and writes one exact token to this private FIFO. The app cannot access it.
    This is development custody, not an authenticated remote approval inbox.
    """
    consent = directory / 'consent'
    os.mkfifo(consent, mode=0o600)
    descriptor = os.open(consent, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        print('Operator review required: read ' + str(directory / 'literal-review.txt')
              + ' and its literal-review.json signing request through the trusted container operator shell; then write "approve '
              + name + '" followed by a newline to ' + str(consent), flush=True)
        deadline, response = time.monotonic() + 600, b''
        while time.monotonic() < deadline:
            require(len(response) < 256, 'demo.operator-review-response-bound')
            try:
                part = os.read(descriptor, 256 - len(response))
            except BlockingIOError:
                part = b''
            response += part
            if b'\n' in response:
                require(response == ('approve ' + name + '\n').encode(),
                        'demo.operator-review-declined')
                return
            time.sleep(0.05)
        raise Refusal('demo.operator-review-expired')
    finally:
        os.close(descriptor)
        consent.unlink(missing_ok=True)


class Operator:
    def __init__(self, mode, owner_ui_port=None):
        require(os.getuid() == 0, 'demo.operator-root-required')
        require(not HOME.exists(), 'demo.fresh-container-required')
        HOME.mkdir(mode=0o755)
        PRIVATE.mkdir(mode=0o700)
        self.mode, self.processes, self.double, self.resources = mode, [], None, None
        self.binary = HERE / 'bin' / ('auths-gateway-simulation' if mode == 'simulation' else 'auths-gateway')
        self.keys, self.sockets = {}, HOME / 'sockets'
        self.sockets.mkdir(mode=0o750)
        os.chown(self.sockets, 0, APP_GID)
        self.port = None
        self.effect_reviewer = development_ed25519_identity_key()
        self.owner_review = None
        if owner_ui_port is not None:
            from owner_review import OwnerReviewServer
            self.owner_review = OwnerReviewServer(PRIVATE, owner_ui_port)

    def start_gateway(self, host):
        socket_path = self.sockets / ('app' + str(host) + '.sock')
        socket_path.unlink(missing_ok=True)
        state = HOME / ('gateway' + str(host))
        (state / 'admin.sock').unlink(missing_ok=True)
        args = [self.binary, 'serve', '--state-dir', state, '--app-socket', socket_path]
        if self.port is not None:
            args.extend(['--loopback-provider', self.port])
        log = open(HOME / 'private' / ('gateway-' + str(host) + '.log'), 'ab')
        process = subprocess.Popen(list(map(str, args)), env=ENVIRONMENT, stdout=log, stderr=log)
        self.processes.append((process, log, host))
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            require(process.poll() is None, 'demo.gateway-start-refused')
            if socket_path.exists():
                os.chown(socket_path, 0, APP_GID)
                os.chmod(socket_path, 0o660)
                return
            time.sleep(0.05)
        raise Refusal('demo.gateway-start-timeout')

    def restart(self, host):
        for process, log, number in list(self.processes):
            if number == host:
                process.terminate()
                process.wait(timeout=10)
                log.close()
                self.processes.remove((process, log, number))
        self.start_gateway(host)

    def prepare(self):
        if self.mode == 'simulation':
            from double import BASE, TABLE, record_ids, serve
            token = 'pat_simulation_' + secrets.token_hex(24)
            self.keys = {'runtime': token}
            self.keys['fixture'] = 'pat_fixture_' + secrets.token_hex(24)
            self.double, self.fixture = serve(digest(token.encode()), HOME / 'provider.jsonl', self.keys['fixture'])
            self.port = self.double.server_address[1]
            resources = {'base': BASE, 'table': TABLE, 'view': None, 'records': record_ids()}
        else:
            self.keys = input_credentials()
            sys.path.insert(0, str(HERE / 'reference'))
            from airtable_resources import Resources
            from airtable_record import BASE, TABLE
            from resource_io import request
            schema = request('https://api.airtable.com', 'GET', '/v0/meta/bases/' + BASE + '/tables', self.keys['setup'])
            tables = [table for table in schema.get('tables', []) if table.get('id') == TABLE]
            require(len(tables) == 1, 'demo.disposable-table-unavailable')
            fields = {field.get('name'): field.get('type') for field in tables[0].get('fields', [])}
            require(all(fields.get(name) in ('singleLineText', 'multilineText')
                        for name in ['Name', 'DemoStatus', 'auths_echo']), 'demo.required-text-fields-unavailable')
            self.resources = Resources(self.keys['setup'])
            session = 'airtable-demo/' + str(int(time.time())) + '/' + str(secrets.randbelow(2**64 - 1) + 1)
            self.resources.prepare(session, 16, JOURNAL, POOL)
            pool = decode(read(POOL))
            resources = {'base': pool['base'], 'table': pool['table'], 'view': next((view.get('id') for view in tables[0].get('views', []) if re.fullmatch(r'viw[A-Za-z0-9]{14}', str(view.get('id')))), None), 'records': [value['id'] for value in pool['records']]}
            # Fresh runtime access checks precede any gateway application effect.
            for record in resources['records']:
                value = request('https://api.airtable.com', 'GET', '/v0/' + BASE + '/' + TABLE + '/' + record,
                                self.keys['runtime'])
                require(value.get('id') == record and value.get('fields', {}).get('DemoStatus') == 'Pending',
                        'demo.runtime-resource-access-refused')
        plan = asyncio.run(authority(self.binary, resources, HOME, self.mode))
        attempts = HOME / 'attempts'
        attempts.mkdir(mode=0o700)
        effect_policy = PRIVATE / 'effect-policy.json'
        write(effect_policy, gateway(self.binary, 'effect-policy', '--partition', 'airtable-demo',
            '--epoch', '1', '--approver-public-key', self.effect_reviewer.public_key.hex()), new=True)
        for host in range(3):
            state = HOME / ('gateway' + str(host))
            args = [self.binary, 'install', '--state-dir', state, '--recipe', HERE / 'recipe.json',
                    '--profile-lock', HERE / 'profile.lock.json', '--trusted-context',
                    PRIVATE / 'context-0.cbor', '--effect-policy', effect_policy,
                    '--approve-digest', plan['recipe_digest'], '--provider', 'airtable',
                    '--alias', 'demo', '--credential-stdin', '--attempt-store', attempts]
            args.extend(['--account-label', resources['base']] if host == 0 else ['--join'])
            child(args, stdin=(self.keys['runtime'] + '\n').encode())
            proposal = state / 'candidate-installation.json'
            if proposal.exists():
                call = PRIVATE / 'candidate-call.json'
                gateway(self.binary, 'effect-candidate-call', '--state-dir', state,
                    '--candidate', proposal, '--operation', 'install-check', '--call-out', call)
                proof, action = asyncio.run(self.read_packet(decode(read(call)), plan))
                approved = self.exact_approval(state, 'install-check', proof, action,
                                                '--candidate', proposal)
                require(approved is not None, 'demo.candidate-effect-approval-unavailable')
                arguments = ['--state-dir', state, '--candidate', proposal, '--proof', approved[0],
                             '--action', approved[1], '--approval', approved[2]]
                local = ['--loopback-provider', self.port] if self.port is not None else []
                gateway(self.binary, 'candidate-acquire', *arguments, *local)
                gateway(self.binary, 'candidate-publish', *arguments)
        # A shared software observer exists only in this labeled development
        # deployment. It is never a production signing-custody claim.
        gateway(self.binary, 'observer-init', '--state-dir', HOME / 'gateway0')
        for host in [1, 2]:
            write(HOME / ('gateway' + str(host)) / 'observer.seed', read(HOME / 'gateway0' / 'observer.seed'), new=True)
        self.observer = decode(gateway(self.binary, 'observer-show', '--state-dir', HOME / 'gateway0'))
        configuration = gateway(self.binary, 'effect-configuration-review',
                                '--state-dir', HOME / 'gateway0')
        write(PRIVATE / 'configuration-review.json', configuration, new=True)
        reviewed = decode(configuration)
        gateway(self.binary, 'effect-configuration-activate', '--state-dir', HOME / 'gateway0',
                '--expected-revision', reviewed['previous_revision_hex'],
                '--expected-candidate', reviewed['candidate_hex'])
        write(HOME / 'private' / 'pins.json', canonical({'trusted_context_sha256':
            digest(read(HOME / 'private' / 'context-0.cbor')), 'observer': self.observer}), new=True)
        for host in range(3):
            self.start_gateway(host)
        self.prepare_exact_approvals(plan)
        self.start_recovery_reviews(plan)
        return plan

    async def read_packet(self, call, plan):
        """Managers simulate separately authorizing a native-authored read call."""
        contract, command = read_contract(call)
        grant = decode(read(PRIVATE / 'read-grant.json'))
        reader = load_signer_file(PRIVATE / 'reader.json').signer
        managers = [load_signer_file(PRIVATE / (name + '.json')).signer for name in MANAGERS]
        try:
            proposal = propose_mcp_approval(contract=contract, command=command,
                required=APPROVALS_REQUIRED, approvers=plan['approval']['principals'],
                actor=reader.descriptor.principal, actor_grant=unb64(grant['bytes']),
                challenge=unb64(plan['challenges'][0]), evaluation_time=int(time.time()),
                validity_seconds=ACTION_VALIDITY_SECONDS)
            responses = []
            for signer in managers[:APPROVALS_REQUIRED]:
                request = next(item for item in approval_requests(proposal)
                               if item.approver == signer.descriptor.principal)
                responses.append((await approve(open_approval_request(request.text,
                    now=int(time.time())), signer)).text)
            signed = await sign_approval_action(proposal, reader, grants=[
                GrantEvidence(unb64(grant['bytes']), tuple(PublicControlEvidence(
                    item['type'], item['media_type'], unb64(item['bytes']))
                    for item in grant['evidence']))])
            return collect_approvals(proposal, responses).assemble(signed), proposal.action
        finally:
            await reader.aclose()
            for signer in managers:
                await signer.aclose()

    def exact_approval(self, state, name, proof, action, *mode, review_only=False, owner_consent=False):
        """Native review plus explicit owner consent, or the labeled simulator."""
        directory = PRIVATE / name
        directory.mkdir(mode=0o700)
        proof_path, action_path = directory / 'proof', directory / 'action'
        request, approval = directory / 'request', directory / 'approval'
        write(proof_path, proof, new=True)
        write(action_path, action, new=True)
        now = int(time.time())
        output = child([self.binary, 'effect-review', '--state-dir', state,
            '--proof', proof_path, '--action', action_path, '--not-before', str(now - 1),
            '--expires-at', str(now + ACTION_VALIDITY_SECONDS), '--request-out', request,
            *mode], check=False)
        if output.returncode != 0:
            return None
        review = decode(output.stdout)
        require(review['schema'] == 'auths.private-effect-signing/2'
                and review['renderer'] == 'auths.literal-complete-review/1'
                and type(review['literal_review']) is str and review['literal_review'],
                'demo.native-effect-review-required')
        write(directory / 'literal-review.json', output.stdout, new=True)
        write(directory / 'literal-review.txt', review['literal_review'].encode('utf-8'), new=True)
        if review_only:
            return proof_path, action_path, None
        if owner_consent:
            require(self.owner_review is not None, 'demo.owner-review-unavailable')
            self.owner_review.request(review)
        elif self.mode == 'live':
            operator_consent(directory, name)
        signature = self.effect_reviewer.sign(bytes.fromhex(review['signing_message_hex']))
        write(approval, gateway(self.binary, 'effect-approval', '--request', request,
                               '--signature-hex', signature.hex()), new=True)
        return proof_path, action_path, approval

    def prepare_exact_approvals(self, plan):
        """Preapprove finite scripted mutations; refusals use an explicitly substituted approval."""
        application = Application(HOME / 'app', [self.sockets / ('app' + str(host) + '.sock')
                                                for host in range(3)])
        values, reviews = {}, {}
        for label in LABELS:
            proof, action, _ = asyncio.run(application.packet(label))
            result = self.exact_approval(HOME / 'gateway0', 'effect-' + label, proof, action,
                                         review_only=self.owner_review is not None)
            if result is not None:
                if result[2] is not None:
                    values[label] = b64(read(result[2]))
                review = decode(read(result[0].parent / 'literal-review.json'))
                reviews[label] = review['literal_review']
        if self.owner_review is None:
            require('exact' in values, 'demo.exact-effect-approval-unavailable')
            for label in LABELS:
                # An approval for another effect is an adversarial substitution,
                # never an application-created authority or a bypass.
                values.setdefault(label, values['exact'])
            values['exact:fresh'] = values['exact']
        else:
            require('exact' in reviews, 'demo.exact-effect-review-unavailable')
        plan['effect_approvals'] = values
        plan['effect_review'] = {'mode': ('authenticated owner review required' if self.owner_review is not None
            else 'scripted operator reviewer; not an independent human trial'
            if self.mode == 'simulation' else 'separate private operator consent; development signing custody'),
                                 'renderer': 'auths.literal-complete-review/1', 'reviews': reviews}
        write(HOME / 'app/application.json', canonical(plan))
        for path in (HOME / 'app').iterdir():
            os.chown(path, APP_UID, APP_GID)

    def prepare_recovery(self, source, sequence, plan):
        """Produce separate read authority; deriving a call never grants entry."""
        operation = 'read-' + source + '-' + str(sequence)
        call = decode(gateway(self.binary, 'effect-recovery-call', '--state-dir', HOME / 'gateway0',
            '--source-operation', source, '--recovery-operation', operation))
        proof, action = asyncio.run(self.read_packet(call, plan))
        approved = self.exact_approval(HOME / 'gateway0', operation, proof, action,
                                        '--recovery-of', source, owner_consent=self.owner_review is not None)
        require(approved is not None, 'demo.recovery-review-refused')
        return {'proof': b64(proof), 'action': b64(action), 'approval': b64(read(approved[2])),
                'literal_review': decode(read(approved[2].parent / 'literal-review.json'))['literal_review']}

    def start_recovery_reviews(self, plan):
        """Finite development reviewer, isolated from the application's UID.

        This is an explicit operator signing channel, not native recovery
        semantics. Live mode requires private operator consent in exact_approval.
        """
        operator = self
        counts = {}

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(660 if operator.mode == 'live' or operator.owner_review is not None else 30)
                def receive(length):
                    output = b''
                    while len(output) < length:
                        block = self.request.recv(length - len(output))
                        require(bool(block), 'demo.review-request-incomplete')
                        output += block
                    return output
                try:
                    length = struct.unpack('>I', receive(4))[0]
                    maximum = 4 * 1024 * 1024 if self.server.mutation_route else 1024
                    require(0 < length <= maximum, 'demo.review-request-bound')
                    request = decode(receive(length))
                    require(type(request) is dict, 'demo.review-request-refused')
                    if self.server.mutation_route:
                        require(set(request) == {'mutation', 'proof', 'action'}, 'demo.review-request-refused')
                        label = request['mutation']
                        require(type(label) is str and label in plan['cases'], 'demo.review-source-refused')
                        proof, action = unb64(request['proof']), unb64(request['action'])
                        if counts.get('mutation:' + label, 0):
                            directory = PRIVATE / ('owner-mutation-' + label)
                            require((directory / 'approval').is_file()
                                    and read(directory / 'proof') == proof and read(directory / 'action') == action,
                                    'demo.review-attempt-limit')
                            # Redeliver only the original signed envelope. This
                            # creates no new consent/signature or native permit.
                            approved = directory / 'proof', directory / 'action', directory / 'approval'
                        else:
                            counts['mutation:' + label] = 1
                            approved = operator.exact_approval(HOME / 'gateway0', 'owner-mutation-' + label,
                                proof, action, owner_consent=True)
                        require(approved is not None, 'demo.owner-review-refused')
                        response = {'proof': b64(proof), 'action': b64(action), 'approval': b64(read(approved[2])),
                            'literal_review': decode(read(approved[2].parent / 'literal-review.json'))['literal_review']}
                        raw = canonical(response)
                        require(len(raw) <= 4 * 1024 * 1024, 'demo.review-response-bound')
                        self.request.sendall(struct.pack('>I', len(raw)) + raw)
                        return
                    require(type(request) is dict and set(request) == {'source'}
                            and type(request['source']) is str
                            and request['source'] in plan['cases'], 'demo.review-source-refused')
                    source = request['source']
                    sequence = counts.get(source, 0) + 1
                    require(sequence <= 4, 'demo.review-attempt-limit')
                    counts[source] = sequence
                    response = operator.prepare_recovery(source, sequence, plan)
                except (Refusal, ValueError, OSError, TimeoutError):
                    response = {'code': 'demo.operator-recovery-review-refused'}
                raw = canonical(response)
                require(len(raw) <= 4 * 1024 * 1024, 'demo.review-response-bound')
                self.request.sendall(struct.pack('>I', len(raw)) + raw)

        self.review_servers = []
        for mutation_route in ([False, True] if self.owner_review is not None else [False]):
            path = self.sockets / ('owner-review.sock' if mutation_route else 'review.sock')
            server = socketserver.UnixStreamServer(str(path), Handler)
            server.mutation_route = mutation_route
            os.chown(path, 0, APP_GID)
            os.chmod(path, 0o660)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.review_servers.append((server, thread))

    def application(self, *arguments):
        return subprocess.run(['/opt/consumer/bin/python', str(HERE / 'app.py'), *arguments],
            env=ENVIRONMENT, capture_output=True, user=APP_UID, group=APP_GID, extra_groups=[], timeout=90)

    def witnesses(self):
        values = []
        for host in range(3):
            result = decode(gateway(self.binary, 'execution-witness', '--state-dir', HOME / ('gateway' + str(host))))
            require(result['ok'] is True, 'demo.execution-witness-refused')
            witness = result['execution_witness']
            require(witness['schema'] == 'auths.gateway-execution-witness/1', 'demo.execution-witness-invalid')
            values.append(witness)
        return values

    def stop(self):
        if self.owner_review is not None:
            self.owner_review.stop()
        for server, thread in getattr(self, 'review_servers', []):
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        for process, log, _ in self.processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            log.close()
        self.processes.clear()
        if self.double:
            self.double.shutdown()
        if self.resources and JOURNAL.exists():
            self.resources.cleanup(JOURNAL)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--live', action='store_true', help='Use the real provider with operator-only stdin credentials')
    parser.add_argument('--port', type=int, default=8081)
    parser.add_argument('--selftest', action='store_true')
    parser.add_argument('--cleanup', action='store_true')
    parser.add_argument('--owner-ui-port', type=int, help='Separate authenticated owner UI for local simulation')
    args = parser.parse_args()
    require(args.owner_ui_port is None or (not args.live and not args.selftest and not args.cleanup
            and 1024 <= args.owner_ui_port <= 65535 and args.owner_ui_port != args.port),
            'demo.owner-ui-simulation-and-separate-port-required')
    if args.cleanup:
        require(args.live and not args.selftest, 'demo.live-cleanup-required')
        cleanup_existing()
        return
    require(not args.selftest or not args.live, 'demo.selftest-simulation-only')
    operator = Operator('live' if args.live else 'simulation', args.owner_ui_port)
    def interrupted(*_):
        raise Refusal('demo.interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        operator.prepare()
        if args.selftest:
            from selftest import run
            run(operator)
        else:
            process = subprocess.Popen(['/opt/consumer/bin/python', str(HERE / 'app.py'),
                       'serve', '--port', str(args.port)], env=ENVIRONMENT,
                       user=APP_UID, group=APP_GID, extra_groups=[])
            operator.processes.append((process, open(os.devnull, 'wb'), -1))
            require(process.wait() == 0, 'demo.application-exited')
    except Refusal as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
    finally:
        operator.stop()


if __name__ == '__main__':
    try:
        main()
    except ValueError as error:
        code = str(error)
        if not re.fullmatch(r'(?:demo|qualification)\.[a-z0-9.-]+(?::[a-z0-9-]+)?', code):
            code = 'demo.operator-input-refused'
        print(code, file=sys.stderr)
        raise SystemExit(1) from None
