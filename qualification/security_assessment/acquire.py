#!/usr/bin/env python3
"""Acquire only the pinned AP075 source-free laboratory inputs; never execute them."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import zipfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_name(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or '\\' in name:
        raise ValueError('unsafe archive path')
    return path


def acquire(manifest, destination):
    destination.mkdir(parents=True, exist_ok=True)
    records = []
    for item in manifest['artifacts']:
        output = destination / item['key']
        output.mkdir(exist_ok=True)
        archive = output / 'artifact.zip'
        if not archive.exists():
            result = subprocess.run(['gh', 'api', 'repos/auths-dev/auths-proof/actions/artifacts/'
                                     + str(item['id']) + '/zip'], check=True, capture_output=True)
            archive.write_bytes(result.stdout)
        raw = archive.read_bytes()
        if digest(raw) != item['sha256']:
            raise ValueError('GitHub artifact digest mismatch: ' + item['key'])
        members = zipfile.ZipFile(io.BytesIO(raw))
        names = members.namelist()
        if len(names) != len(set(names)):
            raise ValueError('duplicate ZIP entry')
        for name in names:
            safe_name(name)
        packages = [name for name in names if name.endswith('.tgz')]
        if len(packages) != 1:
            raise ValueError('one package required')
        package = members.read(packages[0])
        checksum = members.read(packages[0] + '.sha256').decode().split()[0]
        if digest(package) != checksum:
            raise ValueError('package checksum mismatch')
        tree = tarfile.open(fileobj=io.BytesIO(package), mode='r:gz')
        entries = tree.getmembers()
        if len(entries) != len({entry.name for entry in entries}):
            raise ValueError('duplicate tar entry')
        files = {}
        for entry in entries:
            path = safe_name(entry.name)
            if not path.parts or path.parts[0] != item['root'] or not entry.isfile():
                raise ValueError('unexpected tar root/type')
            if entry.size > 128 * 1024 * 1024:
                raise ValueError('package member too large')
            stream = tree.extractfile(entry)
            if stream is None:
                raise ValueError('missing regular file')
            files[str(path.relative_to(item['root']))] = (stream.read(), entry.mode)
        metadata = json.loads(files['manifest.json'][0])
        if (metadata['schema'] != item['manifest_schema']
                or metadata['source_commit'] != manifest['target_revision']
                or metadata['production_qualification'] is not False):
            raise ValueError('package source/schema/claim mismatch')
        expected = {row['path']: row['sha256'] for row in metadata['files']}
        if len(expected) != len(metadata['files']) or set(expected) != set(files) - {'manifest.json'}:
            raise ValueError('incomplete/duplicate payload manifest')
        for name, expected_hash in expected.items():
            safe_name(name)
            if digest(files[name][0]) != expected_hash:
                raise ValueError('payload digest mismatch')
        unpacked = output / item['root']
        unpacked.mkdir(exist_ok=True)
        for name, (data, mode) in files.items():
            path = unpacked / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
                raise ValueError('symlink in extraction destination')
            path.write_bytes(data)
            path.chmod(mode & 0o777)
        records.append({'key': item['key'], 'artifact_id': item['id'], 'run_id': item['run_id'],
                        'archive_sha256': digest(raw), 'package_sha256': digest(package),
                        'source_commit': metadata['source_commit'], 'verified_files': len(expected),
                        'path': str(unpacked.resolve()), 'executed': False,
                        'origin_trust': 'pinned GitHub Actions producer, not a signed release'})
    return {'schema': 'auths.security-assessment-acquisition/1', 'artifacts': records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    report = acquire(json.loads(args.manifest.read_text()), args.destination)
    (args.destination / 'acquisition.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
