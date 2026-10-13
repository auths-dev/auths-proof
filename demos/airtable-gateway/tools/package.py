#!/usr/bin/env python3
"""Construct the source-free demo handoff; never copy private runtime state."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile


def main():
    parser = argparse.ArgumentParser()
    for name in ['gateway', 'simulation-gateway', 'wheel', 'npm', 'compiled-client', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    if len(args.commit) != 40 or any(c not in '0123456789abcdef' for c in args.commit):
        parser.error('a full source commit is required')
    source = Path(__file__).resolve().parents[1]
    repository = source.parents[1]
    files = {}
    for name in ['app.py', 'operate.py', 'demo_common.py', 'double.py', 'selftest.py', 'generated.py',
                 'profile.toml', 'profile.lock.json', 'recipe.json', 'vectors.json',
                 'Dockerfile', 'README.md', 'package.json', 'contract.json', 'launch.py']:
        files[name] = ((source / name).read_bytes(), 0o644)
    for path in sorted((source / 'web').iterdir()):
        files['web/' + path.name] = (path.read_bytes(), 0o644)
    for path in sorted((source / 'tests').iterdir()):
        if path.is_file():
            files['tests/' + path.name] = (path.read_bytes(), 0o644)
    # Release-only reviewed fixture preparation. These never enter app/runtime.
    for name in ['common.py', 'resource_io.py', 'fresh_evidence.py', 'airtable_record.py',
                 'airtable_resources.py']:
        files['reference/' + name] = ((repository / 'qualification/reference' / name).read_bytes(), 0o644)
    files['bin/auths-gateway'] = (args.gateway.read_bytes(), 0o755)
    files['bin/auths-gateway-simulation'] = (args.simulation_gateway.read_bytes(), 0o755)
    files['submit.mjs'] = (args.compiled_client.read_bytes(), 0o644)
    for path in [args.wheel, args.npm]:
        files['artifacts/' + path.name] = (path.read_bytes(), 0o644)
    manifest = {'schema': 'auths.airtable-gateway-demo-package/1', 'source_commit': args.commit,
                'production_qualification': False, 'platform': 'linux-x86_64',
                'simulation_binary': 'bin/auths-gateway-simulation',
                'shipping_binary': 'bin/auths-gateway',
                'files': [{'path': name, 'sha256': hashlib.sha256(data).hexdigest()}
                          for name, (data, _) in sorted(files.items())]}
    files['manifest.json'] = ((json.dumps(manifest, sort_keys=True) + '\n').encode(), 0o644)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('wb') as destination:
        with gzip.GzipFile(filename='', fileobj=destination, mode='wb', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                for name, (data, mode) in sorted(files.items()):
                    entry = tarfile.TarInfo('airtable-gateway-demo/' + name)
                    entry.size, entry.mode, entry.mtime = len(data), mode, 0
                    archive.addfile(entry, io.BytesIO(data))
    checksum = hashlib.sha256(args.output.read_bytes()).hexdigest()
    args.output.with_suffix(args.output.suffix + '.sha256').write_text(checksum + '  ' + args.output.name + '\n')
    print(json.dumps({'archive': args.output.name, 'sha256': checksum, 'files': len(files)}))


if __name__ == '__main__':
    main()
