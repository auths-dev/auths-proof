#!/usr/bin/env python3
"""Protected, source-owned commissioning signer entry point.

The signer job builds its reviewer and issuer from this exact main checkout.
Downloaded candidate bytes are hashed, never executed here. Public inputs
select neither tools nor the reviewed contract, recipe, oracle or lease cap.
The root key and release signer are not inputs to this command.
"""

import argparse
import base64
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'reference'))
import expand
from common import digest, require
from resource_io import finish, write_bytes
import artifact_wait

ROOT = Path(__file__).resolve().parents[2]


def call(arguments):
    result = subprocess.run(list(map(str, arguments)), stdin=subprocess.DEVNULL,
        capture_output=True, timeout=120, cwd=ROOT, env={'PATH': '/usr/bin:/bin'})
    require(result.returncode == 0 and len(result.stdout) <= 65536 and len(result.stderr) <= 65536,
            'qualification.commission.source-command')
    return result.stdout


def source_contract(family, inputs, issuer):
    require(family in expand.REFERENCES, 'qualification.commission.family')
    from generate_families import generate
    generate(check=True)
    contract = ROOT / 'qualification/families' / family / 'contract.json'
    # Hash the reviewed source contract through the native format, never use
    # an artifact-supplied contract ID as its own expected value.
    expected = digest(call([issuer, 'contract-id', '--contract', contract]).decode('ascii').strip())
    actual = expand.decode(expand.read(inputs / 'tuple.json', 65536))
    require(actual['recipe_family'] == family and actual['provider_contract_id'] == expected,
            'qualification.commission.contract-binding')
    return actual


def signing_seed(value):
    require(type(value) is str and re.fullmatch(r'[A-Za-z0-9_-]{43}', value) is not None,
            'qualification.commission.key-format')
    raw = base64.urlsafe_b64decode(value + '=')
    require(len(raw) == 32 and base64.urlsafe_b64encode(raw).rstrip(b'=').decode() == value,
            'qualification.commission.key-format')
    return value.encode('ascii')


def issue(family, inputs, candidate, output):
    run, attempt, commit = artifact_wait.identity(os.environ)
    require(call(['/usr/bin/git', 'rev-parse', 'HEAD']).decode().strip() == commit
            and not call(['/usr/bin/git', 'status', '--porcelain']).strip(),
            'qualification.commission.source-binding')
    require(not output.exists() and not output.is_symlink(), 'qualification.commission.output-exists')
    issuer, reviewer = [ROOT / 'target/release' / name for name in ['auths-qualification', 'auths-gateway']]
    source_contract(family, inputs, issuer)
    protected_run = 'recipe-qualification/' + run + '/' + attempt
    packets = inputs / 'packets/public-packets.json'
    plan = expand.decode(expand.read(packets, 65536))
    now = int(time.time())
    # Delayed approval cannot extend the original installed-author session.
    require(type(plan.get('evaluated_at')) is int
            and now - 7200 < plan['evaluated_at'] <= now + 60,
            'qualification.commission.author-expired')
    not_after = min(now + 7200, plan['evaluated_at'] + 7200)
    require(now < not_after, 'qualification.commission.author-expired')
    output.mkdir(mode=0o700)
    completed = False
    try:
        with tempfile.TemporaryDirectory(prefix='auths-source-commission-') as private:
            private = Path(private)
            expansion = private / 'reference'
            expand.expand(SimpleNamespace(source_commit=commit, protected_run=protected_run,
                tuple=inputs / 'tuple.json', candidate=candidate, reviewer=reviewer,
                recipe=inputs / 'recipe.json', profile_lock=inputs / 'profile.lock.json',
                resources=inputs / 'resources.json', packets=packets,
                conformance=inputs / 'offline/conformance.json',
                differential=inputs / 'offline/differential.json', out_dir=expansion))
            # Read the key only after source identity, contract and independent
            # full-pool reconstruction passed. Children inherit no key env.
            seed = signing_seed(os.environ.get('QUALIFICATION_COMMISSIONING_SIGNER_KEY'))
            key = private / 'commissioner.key'
            canaries = private / 'canaries'
            write_bytes(key, seed, new=True)
            write_bytes(canaries, seed + b'\n', new=True)
            certificate = ROOT / 'qualification/trust/commissioning-signer-certificate.json'
            call([issuer, 'commissioning-sign', '--binding', expansion / 'binding.json',
                '--conformance', inputs / 'offline/conformance.json',
                '--differential', inputs / 'offline/differential.json', '--signer-key', key,
                '--certificate', certificate, '--issued-at', str(now),
                '--not-before', str(now), '--not-after', str(not_after),
                '--out', output / 'commissioning-permit.json'])
            for name, source in [('signer-certificate.json', certificate),
                                 ('revocation-list.json', ROOT / 'qualification/trust/revocation-list.json')]:
                write_bytes(output / name, expand.read(source, 65536), new=True)
            scan = [issuer, 'stage-redaction', '--canaries', canaries]
            for name in ['commissioning-permit.json', 'signer-certificate.json', 'revocation-list.json']:
                scan += ['--source', 'evidence=' + str(output / name)]
            call([*scan, '--out', private / 'signer-publication-scan.json'])
            require(int(time.time()) < not_after, 'qualification.commission.author-expired')
            completed = True
    finally:
        if not completed:
            shutil.rmtree(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family', choices=sorted(expand.REFERENCES), required=True)
    for name in ['inputs', 'candidate', 'out']:
        parser.add_argument('--' + name, type=lambda value: Path(value).absolute(), required=True)
    args = parser.parse_args()
    finish(lambda: issue(args.family, args.inputs, args.candidate, args.out))


if __name__ == '__main__':
    main()
