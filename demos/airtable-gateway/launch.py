#!/usr/bin/env python3
"""Launch this installed demo; credentials travel only over operator stdin."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys

PLATFORM = 'airtable'
PORT = 8081
ENV_FIELDS = {'token': 'PERSONAL_ACCESS_TOKEN'}


def credentials(filename):
    descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size > 16384:
            raise ValueError('demo.operator-env-file-refused')
        # Keep the owner-provided credential file private without copying it.
        if stat.S_IMODE(info.st_mode) & 0o077:
            os.fchmod(stream.fileno(), 0o600)
        raw = stream.read(16385).decode('utf-8')
    selected = {}
    for line in raw.splitlines():
        match = re.fullmatch(r'\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*', line)
        if not match or match[1] not in ENV_FIELDS.values():
            continue
        if match[1] in selected:
            raise ValueError('demo.duplicate-credential-field')
        values = shlex.split(match[2], comments=True)
        if len(values) != 1:
            raise ValueError('demo.credential-field-refused')
        selected[match[1]] = values[0]
    if set(selected) != set(ENV_FIELDS.values()):
        raise ValueError('demo.operator-env-fields-missing')
    return json.dumps({field: selected[name] for field, name in ENV_FIELDS.items()}).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live', action='store_true', help='Use the actual provider; default is simulation')
    parser.add_argument('--env-file', type=Path, help='Private operator credential file; never mounted into the app')
    parser.add_argument('--image', default='auths-' + PLATFORM + '-gateway-demo')
    parser.add_argument('--name', default='auths-' + PLATFORM + '-gateway-demo')
    parser.add_argument('--port', type=int, default=PORT)
    parser.add_argument('--cleanup', action='store_true')
    args = parser.parse_args()
    if (args.live != (args.env_file is not None) or args.cleanup and not args.live
            or not 1024 <= args.port <= 65535 or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', args.name)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}', args.image)):
        parser.error('live requires an operator env file; cleanup requires live; name/image/port must be bounded')
    docker = shutil.which('docker')
    if docker is None:
        raise ValueError('demo.docker-unavailable')
    if os.environ.get('DOCKER_HOST') and not os.environ['DOCKER_HOST'].startswith('unix://'):
        raise ValueError('demo.local-docker-required')
    context = subprocess.run([docker, 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'],
                             capture_output=True, timeout=10)
    if context.returncode != 0 or not context.stdout.strip().startswith(b'unix://'):
        raise ValueError('demo.local-docker-required')
    command = [docker, 'run', '--platform', 'linux/amd64', '--rm', '--init', '-i', '--name', args.name]
    if args.live:
        command.extend(['-v', args.name + '-journal:/run'])
    if not args.cleanup:
        command.extend(['-p', f'127.0.0.1:{args.port}:{args.port}'])
    command.extend([args.image, '--port', str(args.port)])
    if args.live:
        command.append('--live')
    if args.cleanup:
        command.append('--cleanup')
    payload = credentials(args.env_file) if args.live else b''
    print(('LIVE PROVIDER · DEVELOPMENT CUSTODY' if args.live else 'SIMULATION')
          + (' · CLEANUP' if args.cleanup else ' · http://localhost:' + str(args.port)), flush=True)
    # No shell, credential arguments, environment export or app mount.
    raise SystemExit(subprocess.run(command, input=payload).returncode)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, UnicodeError, subprocess.TimeoutExpired):
        print('demo.launch-refused: check the private env file and local Docker', file=sys.stderr)
        raise SystemExit(1) from None
