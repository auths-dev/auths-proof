#!/usr/bin/env python3
"""Exercise the public Python instructions with installed packages in a fresh directory."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

PAGES = {
    '01-authenticate-identity': '01_AUTHENTICATE_IDENTITY.md',
    '02-verify-authority': '02_VERIFY_AUTHORITY.md',
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[3]
    manifest = json.loads((repository / 'bindings/recipes/manifest.json').read_bytes())
    reports = []
    with tempfile.TemporaryDirectory(prefix='auths-public-recipes-') as temporary:
        work = Path(temporary)
        environment = {'PATH': os.defpath, 'PYTHONNOUSERSITE': '1'}
        package = json.loads(subprocess.check_output([
            sys.executable, '-c',
            'import auths, importlib.metadata, json, sys; '
            'print(json.dumps({"version": importlib.metadata.version("auths"), '
            '"file": auths.__file__, "prefix": sys.prefix}))',
        ], cwd=work, env=environment, timeout=30))
        if not Path(package['file']).resolve().is_relative_to(Path(package['prefix']).resolve()):
            raise SystemExit('recipes.package-is-not-installed')
        for recipe in manifest['recipes']:
            page = repository / 'docs/product/recipes' / PAGES[recipe['id']]
            source = page.read_text()
            blocks = re.findall(r'```python\n(.*?)\n```', source, re.S)
            if not blocks:
                raise SystemExit('recipes.python-example-missing')
            started = time.monotonic()
            for index, block in enumerate(blocks):
                program = work / (recipe['id'] + '-' + str(index) + '.py')
                program.write_text(block + '\n')
                child_environment = dict(environment)
                if recipe['id'] == '02-verify-authority' and index == len(blocks) - 1:
                    child_environment['AUTHS_RECIPE_FIXTURE'] = str(work / 'auths-demo-evidence')
                result = subprocess.run([sys.executable, str(program)], cwd=work,
                    env=child_environment, capture_output=True, text=True, timeout=60)
                if result.returncode:
                    raise SystemExit('recipes.public-example-failed:' + recipe['id'] + '\n' + result.stderr[-4096:])
            observation = json.loads(result.stdout.splitlines()[-1])
            if observation.get('outcome') != recipe['expected'] or observation.get('changedRejected') is not True:
                raise SystemExit('recipes.public-example-result-mismatch:' + recipe['id'])
            reports.append({'recipe': recipe['id'], 'result': observation,
                'seconds': round(time.monotonic() - started, 3),
                'page_sha256': hashlib.sha256(page.read_bytes()).hexdigest()})
    report = {'schema': 'auths.public-python-recipe-rehearsal/1', 'sdk': package,
        'repository_sdk_import': False, 'provider_credentials': False, 'recipes': reports}
    encoded = json.dumps(report, indent=2) + '\n'
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(encoded)
    print(encoded, end='')


if __name__ == '__main__':
    main()
