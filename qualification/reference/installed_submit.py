#!/usr/bin/env python3
"""Actual installed Python client with public proof/action and no credential."""

import argparse
import asyncio
from dataclasses import asdict
from pathlib import Path

from author_packets import installed_native
from common import canonical, require
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['endpoint', 'proof', 'action']:
        parser.add_argument('--' + name, type=lambda value: Path(value).absolute(), required=True)
    args = parser.parse_args()
    finish(lambda: submit(args.endpoint, args.proof, args.action))


if __name__ == '__main__':
    main()
