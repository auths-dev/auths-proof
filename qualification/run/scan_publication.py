#!/usr/bin/env python3
"""Scan every retained public file, including newly added phase evidence.

The one private canary file is excluded and never published. Executables and
other private inputs belong outside this publication tree. Symbolic/hard links,
special files, oversized sources and concurrent changes refuse publication.
"""

import argparse
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys

MAX_FILES = 256
MAX_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
KINDS = {'log', 'trace', 'metric', 'support-bundle'}


class Refusal(ValueError):
    pass


def require(value):
    if not value:
        raise Refusal('qualification.publication.refused')


def contents(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= MAX_BYTES)
        payload = stream.read(MAX_BYTES + 1)
    require(len(payload) <= MAX_BYTES)
    return payload


def sources(work):
    require(stat.S_ISDIR(os.lstat(work).st_mode))
    work = work.resolve()
    result, total = [], 0
    for parent, directories, files in os.walk(work, followlinks=False):
        for name in directories:
            require(stat.S_ISDIR(os.lstat(Path(parent) / name).st_mode))
        for name in files:
            path = Path(parent) / name
            info = os.lstat(path)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
            relative = path.relative_to(work)
            if relative == Path('canaries'):
                require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) & 0o077 == 0)
                continue
            require(relative != Path('cases/redaction.scan.json'))
            payload = contents(path)
            total += len(payload)
            require(total <= MAX_TOTAL_BYTES and len(result) < MAX_FILES)
            kind = relative.parts[1] if len(relative.parts) >= 3 and relative.parts[0] == 'scan' \
                and relative.parts[1] in KINDS else 'evidence'
            result.append((relative.as_posix(), kind, hashlib.sha256(payload).hexdigest()))
    require(result)
    return sorted(result)


def scan(work, tool, keep_canaries=False):
    require(stat.S_ISDIR(os.lstat(work).st_mode))
    work = work.resolve()
    require(stat.S_ISDIR(os.lstat(work / 'cases').st_mode))
    report = work / 'cases/redaction.scan.json'
    report.unlink(missing_ok=True)
    before = sources(work)
    arguments = [str(tool), 'stage-redaction', '--canaries', str(work / 'canaries')]
    for name, kind, _digest in before:
        arguments += ['--source', kind + '=' + str(work / name)]
    arguments += ['--out', str(report)]
    try:
        result = subprocess.run(arguments, capture_output=True, timeout=120,
                                cwd='/', env={'PATH': '/usr/bin:/bin'})
    except subprocess.SubprocessError:
        report.unlink(missing_ok=True)
        raise
    # Native diagnostics may contain input paths. They never enter job logs.
    if result.returncode != 0:
        report.unlink(missing_ok=True)
        raise Refusal('qualification.publication.refused')
    require(len(result.stdout) <= MAX_BYTES and len(result.stderr) <= MAX_BYTES)
    # Recheck the complete tree, including unanticipated added files. A report
    # is the only output allowed between the pre-scan and post-scan inventories.
    report_bytes = contents(report)
    report.unlink()
    try:
        require(sources(work) == before)
        descriptor = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(report_bytes)
            stream.flush()
            os.fsync(stream.fileno())
    except (ValueError, OSError):
        report.unlink(missing_ok=True)
        raise
    if not keep_canaries:
        (work / 'canaries').unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=lambda value: Path(value).absolute(), required=True)
    parser.add_argument('--tool', type=lambda value: Path(value).absolute(), required=True)
    parser.add_argument('--keep-canaries', action='store_true')
    args = parser.parse_args()
    try:
        scan(args.work, args.tool, args.keep_canaries)
    except (ValueError, OSError, subprocess.SubprocessError):
        print('qualification.publication.refused', file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
