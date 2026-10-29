#!/usr/bin/env python3
"""Application: public SDK authoring and proof/action/exact-approval gateway submission."""
import argparse
import asyncio
from dataclasses import asdict, dataclass
import importlib.metadata
import os
from pathlib import Path
import secrets
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from typing import Literal

from auths.adapters.custody import PublicControlEvidence
from auths.authoring import (GrantEvidence, collect_approvals, propose_mcp_approval,
                             sign_approval_action)
from auths.gateway import (GatewayClient, GatewayEndpoint, GatewayProtocolError,
                           GatewaySignedObservation, GatewayPreEntryObservations)
from auths.self_hosted import load_signer_file

from demo_common import Refusal, b64, canonical, decode, read, require, unb64, write
from generated import CONTRACT, SetDemoStatus, FIELDS

HERE = Path(__file__).resolve().parent
LABELS = ('exact', 'pending', 'unsupported-value', 'record-substitution', 'path-injection',
          'wrong-recipe', 'altered-action', 'forged-proof', 'expired-action', 'race',
          'lost-response', 'competing-writer', 'rate-limit', 'provider-error',
          'malformed-response', 'oversized-response', 'encoded-segment', 'typescript-positive',
          'crash-before', 'crash-after', 'approval-insufficient')
EXPERIMENTS = tuple('recover-' + label for label in LABELS) + LABELS + ('replay', 'fresh-replay', 'observe', 'typescript', 'recover-loss', 'recover-competing')
EXPERIMENTS += ('approval-duplicate',)
FAULTS = ('lost-response', 'competing-writer', 'rate-limit', 'provider-error',
          'malformed-response', 'oversized-response')
OPERATOR_CASES = ('crash-before', 'crash-after')


@dataclass(frozen=True)
class UnsupportedStatus:
    """Closed adversarial signing input; the installed profile rejects Rejected."""
    operator_namespace: Literal['airtable-demo']
    operation_id: str
    recipe_digest: str
    record_id: str
    replacement: Literal['Approved', 'Pending', 'Rejected']


def approval_target(label, arguments):
    """Return the exact contract and typed command shown to approvers."""
    contract = CONTRACT
    command_type = SetDemoStatus
    if label == 'unsupported-value':
        from auths.self_hosted import ExactMcpTool, EnumField
        contract = ExactMcpTool(service=CONTRACT.service, name=CONTRACT.name,
            command_type=UnsupportedStatus,
            fields={**FIELDS, 'replacement': EnumField(('Approved', 'Pending', 'Rejected'))})
        command_type = UnsupportedStatus
    elif label == 'path-injection':
        from auths.self_hosted import ExactMcpTool, StringField
        contract = ExactMcpTool(service=CONTRACT.service, name=CONTRACT.name,
            command_type=SetDemoStatus,
            fields={**FIELDS, 'record_id': StringField(min_length=1, max_length=43)})
    return contract, command_type(**arguments)


class Application:
    def __init__(self, directory, sockets):
        self.directory = Path(directory)
        self.plan = decode(read(self.directory / 'application.json'))
        require(self.plan['schema'] == 'auths.airtable-gateway-demo/1', 'demo.invalid-plan')
        require(set(self.plan['cases']) == set(LABELS), 'demo.invalid-cases')
        self.sockets = [Path(path) for path in sockets]
        self.clients = [GatewayClient(GatewayEndpoint(path)) for path in self.sockets]
        require(len(self.clients) == 3, 'demo.race-and-fresh-context-gateways-required')
        self.signer = load_signer_file(self.directory / 'actor.json').signer
        require(not any(('AIRTABLE' in key or key == 'PERSONAL_ACCESS_TOKEN') or 'AWS' in key or key == 'PYTHONPATH' for key in os.environ),
                'demo.app-credential-environment')
        self.lock = threading.Lock()
        self.packets = {}
        self.owner_approvals = {}
        self.records = []
        self.entries = {}
        self.approval_responses = []
        if (self.directory / 'results.json').exists():
            self.records = decode(read(self.directory / 'results.json'))
        if (self.directory / 'audit.json').exists():
            audit = decode(read(self.directory / 'audit.json'))
            self.entries = {item['operation_id']: item for item in audit['entries']}
            self.approval_responses = audit.get('approval_responses', [])
        for label in LABELS:
            path = self.directory / ('packet-' + label + '.json')
            if path.exists():
                value = decode(read(path))
                self.packets[label] = (unb64(value['proof']), unb64(value['action']), value['operation'])

    def summary(self):
        return {'schema': 'auths.airtable-gateway-demo-status/1',
                'mode': self.plan['mode'], 'production_qualified': False,
                'trust': self.plan['trust'], 'recipe_digest': self.plan['recipe_digest'],
                'provider': 'Airtable disposable table' if self.plan['mode'] == 'live' else 'counting Airtable double',
                'base': self.plan['base'], 'table': self.plan['table'], 'view': self.plan['view'], 'expires_at': self.plan['expires_at'],
                'provider_credential_model': self.plan['provider_credential_model'],
                'effect': 'Set DemoStatus and action-derived auths_echo; no compare-and-swap',
                'grant_limits': {'budgets': 'No numeric budget capability in this reviewed profile'},
                'experiments': [value for value in EXPERIMENTS if value not in OPERATOR_CASES],
                'approval': self.plan['approval'], 'effect_review': self.plan['effect_review'],
                'sdk_version': importlib.metadata.version('auths'),
                'proposals': {label: case['arguments'] for label, case in self.plan['cases'].items()},
                'records': self.records[-64:]}

    def proposal(self, label, *, fresh=False):
        case = self.plan['cases'][label]
        grant = self.plan['grants']['default']
        contract, command = approval_target(label, case['arguments'])
        key = label + (':fresh' if fresh else '')
        approval = self.plan['approvals'][key]
        return propose_mcp_approval(
            contract=contract, command=command, required=approval['required'],
            approvers=self.plan['approval']['principals'], actor=self.plan['approval']['actor'],
            actor_grant=unb64(grant['bytes']),
            challenge=unb64(self.plan['challenges'][1 if fresh else 0]),
            evaluation_time=case['evaluation_time'],
            validity_seconds=case['validity_seconds'])

    def approval_duplicate(self):
        proposal = self.proposal('exact')
        response = self.plan['approvals']['exact']['responses'][0]
        collection = collect_approvals(proposal, [response, response])
        refused = [status.code for status in collection.statuses if status.code]
        require(collection.approved == 0 and collection.required == 2
                and refused == ['approval.duplicate-response'],
                'demo.approval-duplicate-not-refused')
        code = refused[0]
        return {'operation_id': 'exact', 'result': {'outcome': 'not-submitted',
                'code': code, 'approved': collection.approved, 'required': collection.required,
                'unattributed': list(collection.unattributed)}, 'language': 'python'}

    async def packet(self, label, *, fresh=False):
        if not fresh and label in self.packets:
            return self.packets[label]
        require(int(time.time()) < self.plan['expires_at'], 'demo.authority-expired')
        case = self.plan['cases'][label]
        grant = self.plan['grants']['default']
        evidence = tuple(PublicControlEvidence(item['type'], item['media_type'], unb64(item['bytes']))
                         for item in grant['evidence'])
        proposal = self.proposal(label, fresh=fresh)
        approval = self.plan['approvals'][label + (':fresh' if fresh else '')]
        collection = collect_approvals(proposal, approval['responses'][:approval['required']])
        signed = await sign_approval_action(
            proposal, self.signer, grants=[GrantEvidence(unb64(grant['bytes']), evidence)])
        proof, action = collection.assemble(signed), proposal.action
        if label in ('altered-action', 'record-substitution'):
            action = self.proposal('pending').action
        if label == 'forged-proof':
            proof = proof[:-1] + bytes([proof[-1] ^ 1])
        packet = (proof, action, case['arguments']['operation_id'])
        if not fresh:
            self.packets[label] = packet
            write(self.directory / ('packet-' + label + '.json'),
                  canonical({'proof': b64(proof), 'action': b64(action), 'operation': packet[2],
                             'approval_requirement': proposal.requirement.requirement_id.hex()}), new=True)
        return packet

    async def exchange(self, packet, host=0, *, typescript=False):
        proof, action, operation = packet
        if self.plan['effect_review']['mode'] == 'authenticated owner review required':
            key = (proof, action)
            if key not in self.owner_approvals:
                reviewed = await self.request_review({'mutation': operation, 'proof': b64(proof), 'action': b64(action)})
                if set(reviewed) == {'code'}:
                    return {'operation_id': operation, 'language': 'python', 'result': {
                        'outcome': 'not-submitted', 'code': 'demo.operator-effect-review-refused'}}
                require(set(reviewed) == {'proof', 'action', 'approval', 'literal_review'}
                        and unb64(reviewed['proof']) == proof and unb64(reviewed['action']) == action,
                        'demo.operator-effect-review-mismatch')
                self.owner_approvals[key] = unb64(reviewed['approval'])
            approval = self.owner_approvals[key]
        else:
            approval = unb64(self.plan['effect_approvals'][operation])
        if typescript:
            completed = await asyncio.create_subprocess_exec(
                '/usr/local/bin/node', str(HERE / 'submit.mjs'),
                '--socket', str(self.sockets[host]),
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env={'PATH': '/usr/local/bin:/usr/bin:/bin'})
            output, _ = await asyncio.wait_for(completed.communicate(
                canonical({'proof_b64': b64(proof), 'action_b64': b64(action),
                           'approval_b64': b64(approval)})), 60)
            require(completed.returncode == 0 and len(output) <= 65536, 'demo.typescript-unavailable')
            result = decode(output)
        else:
            try:
                result = asdict(await self.clients[host].submit(proof=proof, action=action, approval=approval))
            except GatewayProtocolError:
                # The IPC request may have entered. Never retry automatically.
                result = {'outcome': 'transport-unconfirmed', 'code': 'demo.gateway-unavailable'}
        return {'operation_id': operation, 'result': result, 'language': 'typescript' if typescript else 'python'}

    async def remember(self, packet, record):
        proof, action, operation = packet
        # A stored outcome belongs to its original action. Do not attach it to
        # another challenge/action or duplicate an entered outcome in the audit.
        previous = self.entries.get(operation)
        if (previous is None or previous['action_b64'] == b64(action)) and record['result']['outcome'] not in (
                'transport-unconfirmed', 'denied', 'indeterminate', 'not-entered'):
            entry = {'operation_id': operation, 'proof_b64': b64(proof), 'action_b64': b64(action),
                     'outcome_b64': None, 'pre_entry_b64': []}
            try:
                observed = await self.clients[0].observe_outcome(operation)
                if isinstance(observed, GatewaySignedObservation):
                    entry['outcome_b64'] = b64(observed.observation)
                pre = await self.clients[0].observe_pre_entry(operation)
                if isinstance(pre, GatewayPreEntryObservations):
                    entry['pre_entry_b64'] = [b64(item) for item in pre.observations]
            except GatewayProtocolError:
                pass  # Missing signed evidence stays missing; audit must report it.
            self.entries[operation] = entry
            recorded = {(item['operation_id'], item['response']) for item in self.approval_responses}
            for response in self.plan['approvals'].get(operation, {}).get('responses', [])[:2]:
                if (operation, response) not in recorded:
                    self.approval_responses.append({'operation_id': operation, 'response': response})
                    recorded.add((operation, response))

    async def request_review(self, request):
        """Carry closed proposals to the separate operator; never sign consent."""
        def request_review():
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
                channel.settimeout(660 if self.plan['mode'] == 'live' or self.plan['effect_review']['mode'] == 'authenticated owner review required' else 90)
                channel.connect(str(self.sockets[0].parent / ('owner-review.sock' if 'mutation' in request else 'review.sock')))
                payload = canonical(request)
                channel.sendall(struct.pack('>I', len(payload)) + payload)
                def receive(length):
                    output = b''
                    while len(output) < length:
                        block = channel.recv(length - len(output))
                        require(bool(block), 'demo.review-response-incomplete')
                        output += block
                    return output
                length = struct.unpack('>I', receive(4))[0]
                require(0 < length <= 4 * 1024 * 1024, 'demo.review-response-bound')
                return decode(receive(length))
        return await asyncio.to_thread(request_review)

    async def recover(self, source):
        """Request independent operator consent, then submit its native read proof."""
        require(source in self.plan['cases'], 'demo.unknown-recovery-source')
        approved = await self.request_review({'source': source})
        if set(approved) == {'code'}:
            return {'operation_id': source, 'language': 'python', 'result': {
                'outcome': 'not-submitted', 'code': 'demo.operator-recovery-review-refused'}}
        require(set(approved) == {'proof', 'action', 'approval', 'literal_review'},
                'demo.operator-review-unavailable')
        raw = await self.clients[0].recover(source, proof=unb64(approved['proof']),
            action=unb64(approved['action']), approval=unb64(approved['approval']))
        report = decode(raw)
        require(report.get('outcome') in ('recovery-report', 'refused'), 'demo.recovery-refused')
        # The native report is retained unchanged. The UI label does not infer
        # an observation or causation from a provider response.
        return {'operation_id': source, 'language': 'python', 'result': {
            **report, 'literal_review': approved['literal_review']}}

    async def execute(self, experiment):
        require(experiment in EXPERIMENTS, 'demo.unknown-experiment')
        if experiment.startswith('recover-'):
            source = experiment[len('recover-'):]
            source = {'loss': 'lost-response', 'competing': 'competing-writer'}.get(source, source)
            record = await self.recover(source)
            result = {'schema': 'auths.airtable-gateway-demo-result/1',
                'experiment': experiment, 'action': self.plan['cases'][source]['arguments'],
                'records': [record], 'decided_by': ('operator-review'
                    if record['result']['outcome'] == 'not-submitted' else 'gateway'),
                'production_qualified': False,
                'display_signature': 'unsigned', 'recorded_at': int(time.time())}
            require(len(self.records) < 256, 'demo.session-full')
            self.records.append(result)
            write(self.directory / 'results.json', canonical(self.records))
            return result
        if experiment == 'approval-duplicate':
            records = [self.approval_duplicate()]
            result = {'schema': 'auths.airtable-gateway-demo-result/1', 'experiment': experiment,
                      'action': self.plan['cases']['exact']['arguments'], 'records': records,
                      'decided_by': 'native-approval-collection', 'production_qualified': False,
                      'display_signature': 'unsigned', 'recorded_at': int(time.time())}
            require(len(self.records) < 256, 'demo.session-full')
            self.records.append(result)
            write(self.directory / 'results.json', canonical(self.records))
            return result
        if experiment in ('replay', 'fresh-replay', 'observe', 'typescript', 'recover-loss', 'recover-competing'):
            label = 'lost-response' if experiment == 'recover-loss' else 'competing-writer' if experiment == 'recover-competing' else 'exact'
            require(label in self.packets, 'demo.run-original-first')
            packet = await self.packet(label, fresh=experiment == 'fresh-replay')
        else:
            require(self.plan['mode'] == 'simulation' or experiment not in FAULTS + OPERATOR_CASES,
                    'demo.live-fault-not-configured')
            packet = await self.packet(experiment)
        if experiment == 'observe':
            observation = await self.clients[0].observe_outcome(packet[2])
            if isinstance(observation, GatewaySignedObservation):
                result = {'outcome': 'signed-observation', 'observation_b64': b64(observation.observation),
                          'schema': observation.schema, 'observed_at': observation.observed_at}
            else:
                result = asdict(observation)
            records = [{'operation_id': packet[2], 'result': result, 'language': 'python'}]
        elif experiment == 'race':
            records = await asyncio.gather(self.exchange(packet, 0), self.exchange(packet, 1))
        else:
            records = [await self.exchange(packet, 2 if experiment == 'fresh-replay' else 0,
                                           typescript=experiment in ('typescript', 'typescript-positive'))]
        for record in records:
            if experiment != 'observe':
                await self.remember(packet, record)
        result = {'schema': 'auths.airtable-gateway-demo-result/1', 'experiment': experiment,
                  'action': self.plan['cases'][label if experiment not in LABELS else experiment]['arguments'],
                  'records': records, 'decided_by': 'gateway', 'production_qualified': False,
                  'display_signature': 'unsigned', 'recorded_at': int(time.time())}
        require(len(self.records) < 256, 'demo.session-full')
        self.records.append(result)
        write(self.directory / 'results.json', canonical(self.records))
        write(self.directory / 'audit.json', canonical(self.audit()))
        return result

    def audit(self):
        return {'schema': 'auths.gateway-audit-bundle/2',
                'recipe_b64': b64(read(HERE / 'recipe.json')),
                'profile_lock_b64': b64(read(HERE / 'profile.lock.json')),
                'trusted_context_b64': self.plan['contexts'][0],
                'entries': list(self.entries.values()),
                'approval_responses': self.approval_responses}


def serve(application, port):
    token = secrets.token_urlsafe(32)
    capacity = threading.BoundedSemaphore(8)
    allowed_hosts = {f'localhost:{port}', f'127.0.0.1:{port}'}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, value, content_type='application/json'):
            data = value if isinstance(value, bytes) else canonical(value)
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.headers.get('Host') not in allowed_hosts:
                return self.reply(403, {'code': 'demo.invalid-host'})
            routes = {'/': ('index.html', 'text/html'), '/app.js': ('app.js', 'text/javascript'),
                      '/styles.css': ('styles.css', 'text/css'), '/receipt': ('receipt.html', 'text/html')}
            path = urlsplit(self.path).path
            if path in routes:
                file, media = routes[path]
                return self.reply(200, read(HERE / 'web' / file), media)
            with application.lock:
                if path == '/api/status':
                    return self.reply(200, {**application.summary(), 'submission_token': token})
                if path == '/api/audit':
                    return self.reply(200, application.audit())
            return self.reply(404, {'code': 'demo.not-found'})

        def do_POST(self):
            host = self.headers.get('Host')
            if (host not in allowed_hosts or self.headers.get('Origin') != 'http://' + host
                    or self.headers.get('X-Demo-Token') != token or self.path != '/api/experiment'):
                return self.reply(403, {'code': 'demo.origin-or-session-refused'})
            if not capacity.acquire(blocking=False):
                return self.reply(503, {'code': 'demo.busy'})
            try:
                self.connection.settimeout(5)
                length = int(self.headers.get('Content-Length', '0'))
                require(0 < length <= 1024, 'demo.request-bound')
                value = decode(self.rfile.read(length))
                require(type(value) is dict and set(value) == {'experiment'}, 'demo.invalid-request')
                require(value['experiment'] not in OPERATOR_CASES, 'demo.operator-case-required')
                # This lock only orders app history. The race itself executes
                # simultaneously on two independent gateway processes.
                with application.lock:
                    result = asyncio.run(application.execute(value['experiment']))
                self.reply(200, result)
            except (Refusal, ValueError, TimeoutError):
                self.reply(400, {'code': 'demo.request-refused'})
            except Exception:
                self.reply(503, {'code': 'demo.experiment-unavailable', 'retry_write': False})
            finally:
                capacity.release()

    server = ThreadingHTTPServer(('0.0.0.0', port), Handler)
    server.daemon_threads = True
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--application', type=Path, default=Path('/run/demo/app'))
    parser.add_argument('--socket', action='append', default=[])
    parser.add_argument('--port', type=int, default=8081)
    parser.add_argument('command', choices=['serve', 'status', 'submit', 'export'])
    parser.add_argument('--experiment', choices=EXPERIMENTS, default='exact')
    args = parser.parse_args()
    application = Application(args.application, args.socket or ['/run/demo/sockets/app0.sock',
                              '/run/demo/sockets/app1.sock', '/run/demo/sockets/app2.sock'])
    if args.command == 'serve':
        serve(application, args.port)
    elif args.command == 'status':
        print(canonical(application.summary()).decode())
    elif args.command == 'export':
        print(canonical(decode(read(args.application / 'audit.json'))).decode())
    else:
        print(canonical(asyncio.run(application.execute(args.experiment))).decode())


if __name__ == '__main__':
    main()
