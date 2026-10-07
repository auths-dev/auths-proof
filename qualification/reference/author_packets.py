#!/usr/bin/env python3
"""Author public qualification packets with an installed SDK and no credential.

Run with an empty environment outside the checkout. Native SDK primitives own
every grant, context, signature, challenge and canonical protocol commitment.
No private signing key is written, exported or reused across author runs.
"""

import argparse
import importlib.metadata
import os
from pathlib import Path
import select
import sys
import sysconfig
import time

from common import Refusal, canonical, closed, integer, require, sha256
from expand import decode, read
from packet_plan import REFERENCES, validate
from resource_io import finish, write, write_bytes


def installed_native():
    # Environment is a positive allowlist, so an unanticipated credential name
    # cannot silently reach this process. Callers must construct its environment.
    require(set(os.environ) <= {'PATH', 'PYTHONNOUSERSITE', 'LC_CTYPE', 'LANG'},
            'qualification.packets.consumer-environment')
    try:
        import auths
        from auths import _native as native
    except ImportError:
        raise Refusal('qualification.packets.sdk-unavailable') from None
    package = Path(auths.__file__).resolve()
    installed_roots = [Path(sysconfig.get_path(name)).resolve() for name in ['purelib', 'platlib']]
    require(any(package.is_relative_to(root) for root in installed_roots)
            and 'site-packages' in package.parts, 'qualification.packets.repository-import')
    require(Path(native.__file__).resolve().parent == package.parent,
            'qualification.packets.native-package')
    return native, importlib.metadata.version('auths')


def create_session(plan_path):
    plan = validate(decode(read(plan_path, 65536)))
    now = int(time.time())
    require(plan['evaluated_at'] <= now <= plan['evaluated_at'] + 60,
            'qualification.packets.stale-plan')
    native, version = installed_native()
    reference = REFERENCES[plan['family']]
    current, end = plan['evaluated_at'], plan['not_after']
    audience = 'mcp://' + reference.SERVICE
    resource = audience + '/tools/' + reference.TOOL
    key = native.DevelopmentEd25519Key.generate()
    actor = native.Principal(key.principal)
    extension = plan['extension']
    extensions = [] if extension is None else [(extension['extension_id'], bytes.fromhex(extension['extension_body_hex']))]
    request = native.GrantRequest(actor, 'auths.mcp', 2, [('tools/call', resource)],
        current - 60, end, [audience], None, None, 0, None, 'raw-key-baseline', extensions)
    unsigned = native.root_grant(actor, request)
    signing = native.prepare_signing(unsigned, key.principal_method, key.verification_method, key.suite)
    grant = signing.complete(key.sign(signing.signing_preimage))
    challenge = native.generate_challenge_v1()
    anchor = native.TrustAnchor(actor.value, actor, [key.principal_method], [('auths.mcp', 2)],
        [('tools/call', resource)], [audience], [audience], current - 60, end,
        None, 1, 'raw-key-baseline', None)
    assurance = native.AssurancePolicy('raw-key-baseline', [
        ('root', 'every', 'self-certifying-identifier', None),
        ('actor', 'every', 'self-certifying-identifier', None),
        ('actor', 'every', 'offline-verifiable', None)])
    template = native.compile_trusted_context(bytes.fromhex(plan['configuration']), None, 1, 1, 1,
        [anchor], assurance, None, None, 'none-v1', [key.evidence_type],
        [] if extension is None else [extension['extension_id']])
    context = template.bind_request(audience, challenge, current)
    evidence = (key.evidence_type, key.media_type, key.evidence)
    # The closure alone retains this native key. A refresh accepts a known
    # label, never caller-supplied arguments, a new grant, actor or challenge.
    retained_context, last_time = None, current
    def emit(work, label=None):
        nonlocal retained_context, last_time
        current = int(time.time())
        require(last_time <= current < end, 'qualification.packets.session-expired')
        last_time = current
        validity = min(300, end - current)
        selected = [packet for packet in plan['packets'] if label is None or packet['label'] == label]
        require(bool(selected), 'qualification.packets.unknown-label')
        packets = []
        for packet in selected:
            label, arguments = packet['label'], packet['arguments']
            call = native.mcp_call(reference.SERVICE, reference.TOOL, canonical(arguments))
            prepared = native.prepare_mcp_call_action(call, actor, grant, challenge, current, validity)
            signing = native.prepare_signing(prepared.unsigned, key.principal_method, key.verification_method, key.suite)
            signed_action = signing.complete(key.sign(signing.signing_preimage))
            proof, action, trust = native.assemble_mcp_proof(prepared, signed_action, [grant],
                                                          [[evidence]], [evidence], context)
            # Assembly binds its returned context to the fresh envelope time.
            # Keep one exact installation context: native normalization changes
            # only the request evaluation input. The gateway always supplies
            # its own synchronized current time when verifying this proof.
            trust = bytes(native.inspect_trusted_context(native.parse_trusted_context(trust)
                .bind_request(audience, challenge, plan['evaluated_at'])))
            require(retained_context is None or retained_context == trust,
                    'qualification.packets.context-binding')
            retained_context = bytes(trust)
            write_bytes(work / (label + '.proof'), bytes(proof), new=True)
            write_bytes(work / (label + '.action'), bytes(action), new=True)
            packets.append({'label': label, 'proof': label + '.proof', 'action': label + '.action',
                            'arguments': arguments})
        write_bytes(work / 'context.cbor', retained_context, new=True)
        write(work / 'public-packets.json', {'schema': 'auths.qualification-public-packets/2',
            'protected_run': plan['protected_run'], 'evaluated_at': current, 'not_after': current + validity,
            'trusted_context': 'context.cbor', 'packets': packets}, new=True)
        write(work / 'author-report.json', {'schema': 'auths.qualification-packet-author/1',
            'family': plan['family'], 'protected_run': plan['protected_run'], 'sdk_version': version,
            'packet_count': len(packets), 'trusted_context_sha256': sha256(retained_context),
            'private_key_exported': False, 'provider_token_received': False,
            'repository_imported': False, 'qualification_issued': False}, new=True)
    return emit, end


def command(raw, generation):
    require(0 < len(raw) <= 512 and raw.endswith(b'\n'), 'qualification.packets.command-bound')
    value = decode(raw)
    require(type(value) is dict, 'qualification.packets.command-bound')
    if value.get('command') == 'close':
        closed(value, ['command'])
        return None
    closed(value, ['command', 'label', 'generation'])
    require(value['command'] == 'refresh' and type(value['label']) is str,
            'qualification.packets.command-bound')
    require(integer(value['generation'], 1, 1024) == generation + 1,
            'qualification.packets.generation')
    return value


def author(plan_path, work, serve=False):
    emit, end = create_session(plan_path)
    emit(work)
    if not serve:
        return
    print('{"schema":"auths.qualification-author-session/1","state":"ready"}', flush=True)
    generation = 0
    # Bounded pipe reads use os.read rather than buffered readline: select
    # must not miss an already-buffered second command. Partial frames have
    # the same finite grant deadline and cannot extend the process lifetime.
    pending = b''
    while True:
        remaining = end - time.time()
        require(remaining > 0, 'qualification.packets.session-expired')
        ready, _, _ = select.select([sys.stdin.fileno()], [], [], remaining)
        require(bool(ready), 'qualification.packets.session-expired')
        chunk = os.read(sys.stdin.fileno(), 513)
        if not chunk:
            require(not pending, 'qualification.packets.command-bound')
            return
        pending += chunk
        require(len(pending) <= 512, 'qualification.packets.command-bound')
        if b'\n' not in pending:
            continue
        require(pending.count(b'\n') == 1 and pending.endswith(b'\n'),
                'qualification.packets.command-bound')
        value = command(pending, generation)
        pending = b''
        if value is None:
            return
        generation = value['generation']
        destination = work / ('refresh-' + str(generation).zfill(4))
        destination.mkdir(mode=0o700)
        emit(destination, value['label'])
        print(canonical({'schema': 'auths.qualification-author-session/1',
            'state': 'refreshed', 'generation': generation, 'label': value['label']}).decode(), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=lambda value: Path(value).absolute(), required=True)
    parser.add_argument('--work', type=lambda value: Path(value).absolute(), required=True)
    parser.add_argument('--serve', action='store_true')
    args = parser.parse_args()
    finish(lambda: author(args.plan, args.work, args.serve))


if __name__ == '__main__':
    main()
