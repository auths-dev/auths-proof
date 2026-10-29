"""Installed local managed journey composition; native Rust owns all decisions.

The operator supplies a finite, separately consented native proposal. The agent
uses installed SDK acquisition/history and the native authenticated recipient.
No plaintext or ACK evidence is returned through the demo's public HTTP UI.
"""
import asyncio
from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
import time

from auths.self_hosted import ExactMcpTool, IntegerField, ObjectField, StringField
from demo_common import b64, canonical, decode, read, require, unb64, write

CONTENT_TOOL = 'auths_gateway_content_read_v1'
DISCLOSURE_TOOL = 'auths_gateway_disclosure_v1'
CONTENT_TOOLS = (CONTENT_TOOL, DISCLOSURE_TOOL)
EXPERIMENTS = ('managed-acquire', 'managed-acquire-typescript', 'managed-disclose',
              'managed-content-history', 'managed-release-history')
SOURCE = 'managed-read-python'
RELEASE = 'managed-disclosure'


@dataclass(frozen=True)
class Resource:
    record_id: str


@dataclass(frozen=True)
class ContentRead:
    operation_id: str
    operator_namespace: str
    recipe_digest: str
    content_contract: str
    resource_arguments: Resource
    maximum_response_bytes: int


@dataclass(frozen=True)
class Disclosure:
    operation_id: str
    operator_namespace: str
    recipe_digest: str
    disclosure_contract: str
    source_effect: str
    source_operation: str
    recipient: str
    channel: str
    delivery_instance: str
    maximum_disclosure_bytes: int


def contract(call):
    """Public SDK authoring shape for the unchanged native-authored tool call."""
    require(call['name'] in CONTENT_TOOLS, 'demo.unlisted-content-tool')
    kind = ContentRead if call['name'] == CONTENT_TOOL else Disclosure
    fields = {name: StringField(min_length=1, max_length=512)
              for name in kind.__annotations__}
    if kind is ContentRead:
        fields['resource_arguments'] = ObjectField(Resource, {'record_id': StringField(17, 43)})
        fields['maximum_response_bytes'] = IntegerField(1, 65536)
    else:
        fields['maximum_disclosure_bytes'] = IntegerField(0, 65536)
    tool = ExactMcpTool(service=call['service'], name=call['name'],
                        command_type=kind, fields=fields)
    return tool, tool.validate_arguments(call['arguments'])


def prepare(operator, kind, plan, gateway):
    """One finite operator proposal, exact native review and explicit consent."""
    require(operator.owner_review is not None and kind in EXPERIMENTS[:3],
            'demo.managed-owner-review-required')
    private = operator.managed_private
    state = operator.managed_state
    operation = RELEASE if kind == 'managed-disclose' else (
        SOURCE if kind == 'managed-acquire' else 'managed-read-typescript')
    call_file = private / (operation + '.call')
    if kind == 'managed-disclose':
        target = private / 'managed-target.json'
        gateway(operator.binary, 'effect-disclosure-call', '--state-dir', state,
                '--target', target, '--operation', operation, '--call-out', call_file)
        mode = ('--disclosure', target)
    else:
        arguments = private / (operation + '.resource')
        write(arguments, canonical({'record_id': plan['cases']['exact']['arguments']['record_id']}), new=True)
        gateway(operator.binary, 'effect-content-call', '--state-dir', state,
                '--resource-arguments', arguments, '--operation', operation, '--call-out', call_file)
        mode = ('--content',)
    call = decode(read(call_file))
    proof, action = asyncio.run(operator.read_packet(call, plan, content=True))
    approved = operator.exact_approval(state, operation, proof, action, *mode, owner_consent=True)
    require(approved is not None, 'demo.managed-review-refused')
    directory = approved[2].parent
    response = {'proof': b64(proof), 'action': b64(action), 'approval': b64(read(approved[2])),
                'binding': b64(read(directory / 'binding')),
                'literal_review': decode(read(directory / 'literal-review.json'))['literal_review']}
    if kind == 'managed-disclose':
        response['target'] = decode(read(private / 'managed-target.json'))
        response['expected_bytes'] = call['arguments']['maximum_disclosure_bytes']
    return response


def view(packet, literal=None):
    """Display only the native stage; this neither grants nor refines facts."""
    require(type(packet) is dict, 'demo.native-content-result-required')
    if packet.get('outcome') == 'history':
        stage = packet['history']['snapshot']['stage']
    else:
        stage = packet.get('outcome', 'unconfirmed')
    return {'outcome': stage, 'native': packet, **({'literal_review': literal} if literal else {})}


async def execute(application, experiment):
    require(application.plan.get('managed_content') is True and experiment in EXPERIMENTS,
            'demo.managed-owner-review-required')
    directory = application.directory / 'managed-content'
    directory.mkdir(mode=0o700, exist_ok=True)
    require(directory.stat().st_uid == os.getuid() and directory.stat().st_mode & 0o077 == 0
            and not directory.is_symlink(), 'demo.managed-private-recipient-required')
    history_only = experiment in EXPERIMENTS[3:]
    operation = ('managed-read-typescript' if experiment == 'managed-acquire-typescript'
                 else RELEASE if experiment in ('managed-disclose', 'managed-release-history') else SOURCE)
    language = 'typescript' if experiment == 'managed-acquire-typescript' else 'python'
    literal = None
    if history_only:
        packet = decode(await application.clients[0].content_history(operation))
    else:
        cache = directory / (experiment + '.packet')
        if cache.exists():
            approved = decode(read(cache))
        else:
            approved = await application.request_review({'content': experiment})
            if set(approved) == {'code'}:
                return {'operation_id': operation, 'language': language,
                        'result': {'outcome': 'not-submitted', 'code': approved['code']}}
            require(set(approved) == ({'proof', 'action', 'approval', 'binding', 'literal_review'} |
                    ({'target', 'expected_bytes'} if experiment == 'managed-disclose' else set())),
                    'demo.managed-review-unavailable')
            write(cache, canonical(approved), new=True)
        literal = approved['literal_review']
        if experiment == 'managed-disclose':
            packet = await asyncio.to_thread(receive, application, directory, approved)
        else:
            arguments = {name: unb64(approved[name]) for name in ('proof', 'action', 'approval')}
            if language == 'typescript':
                def acquire():
                    result = subprocess.run(['node', str(Path(__file__).resolve().parent / 'submit.mjs'),
                        '--socket', str(application.sockets[0]), '--content'], input=canonical({
                            name + '_b64': approved[name] for name in arguments}),
                        capture_output=True, timeout=90)
                    require(result.returncode == 0, 'demo.typescript-content-unconfirmed')
                    return decode(result.stdout)
                packet = await asyncio.to_thread(acquire)
            else:
                packet = decode(await application.clients[0].acquire_content(**arguments))
    return {'operation_id': operation, 'language': language, 'result': view(packet, literal)}


def receive(application, directory, approved):
    """Use the native recipient for identity, channel, exact bytes and ACK.

    Each invocation uses fresh output paths; retained history cannot recreate
    delivery. A lost CLI reply is unconfirmed and never triggers another call.
    """
    target = directory / 'target.json'
    if not target.exists():
        write(target, canonical(approved['target']), new=True)
        for name in ('proof', 'action', 'approval', 'binding'):
            write(directory / name, unb64(approved[name]), new=True)
    prefix = str(time.monotonic_ns())
    command = [str(Path(__file__).resolve().parent / 'bin' / 'auths-gateway-simulation'),
        'disclosure-receive', '--app-socket', str(application.sockets[0]),
        '--target', str(target), '--expected-binding', str(directory / 'binding'),
        '--expected-bytes', str(approved['expected_bytes']),
        '--content-out', str(directory / (prefix + '.content')),
        '--acknowledgement-out', str(directory / (prefix + '.ack')), '--recipient-seed-stdin']
    for name in ('proof', 'action', 'approval'):
        command.extend(['--' + name, str(directory / name)])
    result = subprocess.run(command, input=read(application.directory / 'recipient.seed', 32),
                            capture_output=True, timeout=90)
    require(result.returncode == 0, 'demo.recipient-unconfirmed-no-redelivery')
    status = decode(result.stdout)
    require(status.get('outcome') in ('recipient-ack-sent', 'history', 'refused'),
            'demo.native-recipient-result-required')
    if status['outcome'] != 'recipient-ack-sent':
        return status
    # The recipient's ACK-send claim is not the gateway's persisted ACK fact.
    async def recorded():
        for _ in range(30):
            packet = decode(await application.clients[0].content_history(RELEASE))
            if packet.get('outcome') != 'history' or packet['history']['snapshot']['stage'] == 'acknowledged':
                return packet
            await asyncio.sleep(.1)
        return packet
    return asyncio.run(recorded())
