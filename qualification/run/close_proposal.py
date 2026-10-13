#!/usr/bin/env python3
"""Close and scan a proposal while the operator still holds the real canaries.

The first assembly introduces new retained files. Rescan those files, rebuild
with that complete redaction report, then scan the actual final bytes again.
The report must remain unchanged; expanding or changing the output categories
during the second assembly refuses publication. No authority is issued here.
"""

import argparse
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

import scan_publication as publication


def invalidate(work):
    for name in ['proposal', 'evidence']:
        path = work / name
        if path.is_symlink():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)
    cases = work / 'cases'
    if cases.is_dir() and not cases.is_symlink():
        (cases / 'redaction.scan.json').unlink(missing_ok=True)


def assemble(family, work, environment, run, stage, tool):
    # Only this checkout's assembler executes. No artifact supplies a program,
    # callback, argument list, signer key or provider credential to it.
    script = Path(__file__).resolve().with_name('assemble.sh')
    result = subprocess.run(
        ['bash', str(script), family, str(work), environment, run, stage],
        capture_output=True, timeout=120,
        env={'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
             'AUTHS_QUALIFICATION': str(tool), 'GIT_CONFIG_COUNT': '1',
             'GIT_CONFIG_KEY_0': 'safe.directory', 'GIT_CONFIG_VALUE_0': str(script.parents[2])},
        cwd=script.parents[2])
    publication.require(result.returncode == 0
                        and len(result.stdout) <= publication.MAX_BYTES
                        and len(result.stderr) <= publication.MAX_BYTES)


def close(family, work, environment, run, stage, tool):
    publication.require(stage in ['commissioning', 'live']
                        and re.fullmatch(r'[a-z][a-z0-9-]{0,63}', family) is not None)
    work = Path(work).absolute()
    info = os.lstat(work)
    publication.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                        and stat.S_IMODE(info.st_mode) == 0o700)
    complete = False
    try:
        publication.scan(work, tool, keep_canaries=True)
        assemble(family, work, environment, run, stage, tool)
        publication.scan(work, tool, keep_canaries=True)
        report = publication.contents(work / 'cases/redaction.scan.json')
        assemble(family, work, environment, run, stage, tool)
        publication.scan(work, tool, keep_canaries=True)
        publication.require(publication.contents(work / 'cases/redaction.scan.json') == report)
        publication.require((work / 'proposal').is_dir()
                            and not (work / 'proposal').is_symlink())
        if stage == 'live':
            (work / 'canaries').unlink()
        complete = True
    finally:
        if not complete:
            invalidate(work)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family', required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--environment', required=True)
    parser.add_argument('--run', required=True)
    parser.add_argument('--stage', choices=['commissioning', 'live'], default='live')
    parser.add_argument('--tool', type=Path, required=True)
    args = parser.parse_args()
    try:
        close(args.family, args.work, args.environment, args.run, args.stage, args.tool)
    except (ValueError, OSError, subprocess.SubprocessError):
        print('qualification.proposal.not-closed', file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
