#!/usr/bin/env python3
"""Wait for one public artifact from this exact protected qualification run.

No uploaded program is executed. Run/source/attempt identities and GitHub's
archive digest are checked before bounded public files are extracted. Native
permit/record verification is still mandatory: transport identity is not
qualification authority. The only credential passed to gh is its Actions token.
"""

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'reference'))
from common import Refusal, require
from expand import decode
from resource_io import finish, write_bytes

REPOSITORY = 'auths-dev/auths-proof'
REPOSITORY_ID = 1310728509
WORKFLOW = '.github/workflows/recipe-qualification.yml'
KINDS = ['commissioning-inputs', 'commissioning-permit', 'first-proposal', 'first-release', 'final-proposal']
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_FILES = 256
MAX_FILE = 2 * 1024 * 1024
POLL_SECONDS = 600


def identity(environment):
    require(environment.get('GITHUB_REPOSITORY') == REPOSITORY
            and environment.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and environment.get('GITHUB_REF') == 'refs/heads/main',
            'qualification.artifact.protected-run')
    run, attempt, commit = [environment.get(name, '') for name in
                            ['GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA']]
    require(re.fullmatch(r'[1-9][0-9]{0,19}', run) and re.fullmatch(r'[1-9][0-9]{0,9}', attempt)
            and re.fullmatch(r'[0-9a-f]{40}', commit), 'qualification.artifact.run-identity')
    return run, attempt, commit


def api(path, destination=None):
    # Never inherit provider keys, signer keys, proxy settings, alternate API
    # hosts or GitHub configuration. gh handles the authenticated archive
    # redirect; its token is for GitHub, not a provider or signing input.
    token = os.environ.get('GH_TOKEN', '')
    require(bool(token), 'qualification.artifact.token-missing')
    environment = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'GH_TOKEN': token,
                   'GH_PROMPT_DISABLED': '1', 'GH_CONFIG_DIR': '/nonexistent-auths-gh-config'}
    arguments = ['gh', 'api', '--hostname', 'github.com', '-H', 'X-GitHub-Api-Version: 2022-11-28',
                 'repos/' + REPOSITORY + '/' + path]
    result = subprocess.run(arguments, env=environment, cwd='/', stdin=subprocess.DEVNULL,
                            stdout=destination if destination is not None else subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=60)
    require(result.returncode == 0, 'qualification.artifact.transport-refused')
    if destination is None:
        require(0 < len(result.stdout) <= 256 * 1024, 'qualification.artifact.metadata-bound')
        return decode(result.stdout)


def check_run(value, run, attempt, commit):
    require(value.get('id') == int(run) and value.get('run_attempt') == int(attempt)
            and value.get('head_sha') == commit and value.get('head_branch') == 'main'
            and value.get('event') == 'workflow_dispatch' and value.get('path') == WORKFLOW
            and value.get('repository', {}).get('id') == REPOSITORY_ID
            and value.get('head_repository', {}).get('id') == REPOSITORY_ID,
            'qualification.artifact.run-binding')


def select_artifact(value, name, run, commit):
    require(type(value) is dict and type(value.get('total_count')) is int
            and 0 <= value['total_count'] <= 100 and type(value.get('artifacts')) is list
            and len(value['artifacts']) == value['total_count'], 'qualification.artifact.metadata-bound')
    selected = [artifact for artifact in value['artifacts'] if artifact.get('name') == name]
    require(len(selected) <= 1, 'qualification.artifact.duplicate-name')
    if not selected:
        return None
    artifact = selected[0]
    source = artifact.get('workflow_run', {})
    require(type(artifact.get('id')) is int and artifact['id'] > 0
            and artifact.get('expired') is False
            and type(artifact.get('size_in_bytes')) is int and 0 < artifact['size_in_bytes'] <= MAX_ARCHIVE
            and type(artifact.get('digest')) is str
            and re.fullmatch(r'sha256:[0-9a-f]{64}', artifact['digest'])
            and source.get('id') == int(run) and source.get('head_sha') == commit
            and source.get('head_branch') == 'main'
            and source.get('repository_id') == REPOSITORY_ID
            and source.get('head_repository_id') == REPOSITORY_ID,
            'qualification.artifact.source-binding')
    return artifact


def members(archive):
    entries = archive.infolist()
    require(0 < len(entries) <= MAX_FILES * 2, 'qualification.artifact.archive-bound')
    files, names, total = [], set(), 0
    for entry in entries:
        name = entry.filename
        path = PurePosixPath(name)
        require(not path.is_absolute() and 1 <= len(path.parts) <= 4
                and all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}', part) for part in path.parts)
                and '\\' not in name and name == str(path) + ('/' if entry.is_dir() else '')
                and str(path) not in names and not entry.flag_bits & 1,
                'qualification.artifact.archive-path')
        names.add(str(path))
        mode = entry.external_attr >> 16
        kind = stat.S_IFMT(mode)
        require(kind in [0, stat.S_IFDIR if entry.is_dir() else stat.S_IFREG],
                'qualification.artifact.archive-kind')
        if entry.is_dir():
            require(entry.file_size == 0, 'qualification.artifact.archive-bound')
            continue
        require(path.suffix in ['.json', '.cbor', '.proof', '.action']
                and 0 < entry.file_size <= MAX_FILE, 'qualification.artifact.public-file')
        total += entry.file_size
        require(total <= MAX_ARCHIVE and len(files) < MAX_FILES, 'qualification.artifact.archive-bound')
        files.append((entry, path))
    require(bool(files), 'qualification.artifact.archive-bound')
    file_names = {str(path) for _, path in files}
    require(all(str(parent) not in file_names for _, path in files
                for parent in path.parents if str(parent) != '.'), 'qualification.artifact.archive-path')
    return files


def unpack(path, artifact, destination):
    info = os.lstat(path)
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_ARCHIVE,
            'qualification.artifact.archive-bound')
    with path.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    require(artifact['digest'] == 'sha256:' + actual, 'qualification.artifact.archive-digest')
    require(not destination.exists(), 'qualification.artifact.output-exists')
    parent = os.lstat(destination.parent)
    require(stat.S_ISDIR(parent.st_mode) and stat.S_IMODE(parent.st_mode) == 0o700
            and parent.st_uid == os.getuid(), 'qualification.artifact.private-output')
    complete = False
    try:
        with zipfile.ZipFile(path) as archive:
            files = members(archive)
            destination.mkdir(mode=0o700)
            for entry, relative in files:
                output = destination / str(relative)
                output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with archive.open(entry) as stream:
                    payload = stream.read(MAX_FILE + 1)
                require(len(payload) == entry.file_size, 'qualification.artifact.archive-bound')
                write_bytes(output, payload, new=True)
            complete = True
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError):
        raise Refusal('qualification.artifact.archive-refused') from None
    finally:
        # A partial extraction, including a CRC/format/write failure, never
        # becomes input to the native authority verifier.
        if not complete and destination.exists():
            shutil.rmtree(destination)


def wait(args):
    run, attempt, commit = identity(os.environ)
    require(args.kind in KINDS and re.fullmatch(r'[a-z][a-z0-9-]{0,63}', args.family),
            'qualification.artifact.name')
    name = 'qualification-' + args.kind + '-' + args.family + '-' + run + '-' + attempt
    now = int(time.time())
    require(now < args.not_after <= now + 7200, 'qualification.artifact.deadline')
    deadline = time.monotonic() + args.not_after - now
    last_clock = time.time()
    check_run(api('actions/runs/' + run), run, attempt, commit)
    while True:
        now = time.time()
        require(now >= last_clock and now < args.not_after and time.monotonic() < deadline,
                'qualification.artifact.deadline')
        last_clock = now
        artifact = select_artifact(api('actions/runs/' + run + '/artifacts?per_page=100'), name, run, commit)
        if artifact is not None:
            # The current attempt must still be the one being operated on;
            # rerunning a workflow cannot import the earlier attempt's mailbox.
            check_run(api('actions/runs/' + run), run, attempt, commit)
            with tempfile.TemporaryDirectory(prefix='auths-qualification-artifact-') as temporary:
                path = Path(temporary) / 'public.zip'
                with path.open('xb') as output:
                    os.chmod(path, 0o600)
                    api('actions/artifacts/' + str(artifact['id']) + '/zip', output)
                require(last_clock <= time.time() < args.not_after and time.monotonic() < deadline,
                        'qualification.artifact.deadline')
                unpack(path, artifact, args.out)
            return
        time.sleep(min(POLL_SECONDS, max(0, deadline - time.monotonic())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind', choices=KINDS, required=True)
    parser.add_argument('--family', required=True)
    parser.add_argument('--not-after', type=int, required=True)
    parser.add_argument('--out', type=lambda value: Path(value).absolute(), required=True)
    args = parser.parse_args()
    finish(lambda: wait(args))


if __name__ == '__main__':
    main()
