#!/usr/bin/env python3
"""Actual installed Python client with public proof/action and no credential."""

import argparse
import asyncio
from dataclasses import asdict
from pathlib import Path
import importlib.metadata

from author_packets import installed_native
from common import canonical, require, sha256
from expand import read
from resource_io import finish


def submit(endpoint, proof, action):
    installed_native()
    from auths.gateway import GatewayClient, GatewayEndpoint
    result = asyncio.run(GatewayClient(GatewayEndpoint(endpoint)).submit(
        proof=read(proof, 4 * 1024 * 1024), action=read(action, 65536)))
    payload = canonical(asdict(result))
    require(len(payload) <= 65536, 'qualification.consumer.output-bound')
    print(payload.decode())


def inspect():
    native, version = installed_native()
    import auths
    distribution = importlib.metadata.distribution('auths')
    require(Path(distribution.locate_file('auths/__init__.py')).resolve() == Path(auths.__file__).resolve(),
            'qualification.consumer.distribution-binding')
    print(canonical({'schema': 'auths.qualification-consumer-provenance/1', 'language': 'python',
        'package_name': 'auths', 'version': version, 'installation': 'site-packages',
        'module_sha256': sha256(read(Path(native.__file__), 64 * 1024 * 1024)),
        'repository_imported': False, 'provider_token_received': False}).decode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest='operation', required=True)
    subparsers.add_parser('inspect')
    submission = subparsers.add_parser('submit')
    for name in ['endpoint', 'proof', 'action']:
        submission.add_argument('--' + name, type=lambda value: Path(value).absolute(), required=True)
    args = parser.parse_args()
    finish(lambda: inspect() if args.operation == 'inspect' else submit(args.endpoint, args.proof, args.action))


if __name__ == '__main__':
    main()
