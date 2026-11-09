#!/usr/bin/env python3
"""AP075 corruption controls for pinned package acquisition; no mutant is executed."""
import argparse
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import zipfile

from acquire import acquire


def packed_zip(parts):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in parts:
            archive.writestr(name, content)
    return output.getvalue()


def mutate_package(raw, root, operation):
    source = tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz')
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as target:
        for member in source.getmembers():
            content = source.extractfile(member).read()
            if operation == 'wrong-source' and member.name == root + '/manifest.json':
                value = json.loads(content)
                value['source_commit'] = '0' * 40
                content = json.dumps(value).encode()
            if operation == 'omitted-inventory' and member.name == root + '/manifest.json':
                value = json.loads(content)
                value['files'].pop()
                content = json.dumps(value).encode()
            if operation == 'payload-hash' and member.name == root + '/bin/auths-gateway':
                content = bytes([content[0] ^ 1]) + content[1:]
            item = copy.copy(member)
            item.size = len(content)
            target.addfile(item, io.BytesIO(content))
        if operation == 'tar-link':
            item = tarfile.TarInfo(root + '/unexpected-link')
            item.type = tarfile.SYMTYPE
            item.linkname = '../../outside'
            target.addfile(item)
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    pin = next(x for x in manifest['artifacts'] if x['key'] == 'stripe-package')
    original = (args.inputs / pin['key'] / 'artifact.zip').read_bytes()
    assert hashlib.sha256(original).hexdigest() == pin['sha256']
    archive = zipfile.ZipFile(io.BytesIO(original))
    package_name = next(name for name in archive.namelist() if name.endswith('.tgz'))
    package = archive.read(package_name)
    rows = []
    variants = ['intact-control', 'outer-hash', 'duplicate-zip', 'zip-traversal', 'tar-link',
                'wrong-source', 'payload-hash', 'omitted-inventory', 'destination-link']
    for variant in variants:
        altered = copy.deepcopy(manifest)
        altered['artifacts'] = [copy.deepcopy(pin)]
        if variant in ['tar-link', 'wrong-source', 'payload-hash', 'omitted-inventory']:
            body = mutate_package(package, pin['root'], variant)
            raw = packed_zip([(package_name, body), (package_name + '.sha256',
                             hashlib.sha256(body).hexdigest().encode() + b'  ' + package_name.encode() + b'\n')])
        elif variant == 'duplicate-zip':
            raw = packed_zip([(name, archive.read(name)) for name in archive.namelist()]
                             + [(package_name, package)])
        elif variant == 'zip-traversal':
            raw = packed_zip([('../escape.tgz', package)])
        elif variant == 'outer-hash':
            raw = original[:-1] + bytes([original[-1] ^ 1])
        else:
            raw = original
        # Nested corruption controls deliberately authenticate the outer test
        # fixture, to exercise inner validation separately. They do not claim an
        # attacker can change the real trusted expected-hash manifest.
        if variant != 'outer-hash':
            altered['artifacts'][0]['sha256'] = hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory(prefix='ap075-corruption-') as temporary:
            # macOS exposes /var through /private/var. The legitimate lab root
            # is canonical; links introduced inside extraction remain forbidden.
            root = Path(temporary).resolve()
            entry = root / pin['key']
            entry.mkdir()
            (entry / 'artifact.zip').write_bytes(raw)
            if variant == 'destination-link':
                dest = entry / pin['root']
                dest.mkdir()
                inside = root / 'owned-link-target'
                inside.mkdir()
                (dest / 'bin').symlink_to(inside, target_is_directory=True)
            try:
                result = acquire(altered, root)
                accepted, reason = True, 'verified payloads: ' + str(result['artifacts'][0]['verified_files'])
            except ValueError as error:
                accepted, reason = False, str(error)
            expected = variant == 'intact-control'
            rows.append({'id': variant, 'status': 'pass' if accepted == expected else 'finding',
                         'expected_accept': expected, 'actual_accept': accepted, 'reason': reason,
                         'mutant_executed': False})
    report = {'schema': 'auths.security-assessment-artifact-controls/1',
              'target_revision': manifest['target_revision'], 'cases': rows,
              'scope': 'corruption/traversal/source/payload controls; GitHub producer remains trusted'}
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'cases': len(rows), 'findings': sum(x['status'] != 'pass' for x in rows)}))
    if any(x['status'] != 'pass' for x in rows):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
