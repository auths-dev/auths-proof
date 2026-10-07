"""Private local I/O for disposable resource preparation; never shipping code."""

import json
import os
from pathlib import Path
import re
import stat
import sys
import urllib.error
import urllib.request

from common import Refusal, canonical, closed, require
from fresh_evidence import decode


def run_id(value):
    require(type(value) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,63}/[0-9]{1,20}/[0-9]{1,20}', value),
            'qualification.resources.run-binding')
    return value


def credentials(fields):
    raw = sys.stdin.buffer.read(8193)
    require(0 < len(raw) <= 8192, 'qualification.resources.credential-bound')
    try:
        value = decode(raw)
        closed(value, fields)
        for name, prefix in fields.items():
            key = value[name]
            require(type(key) is str and key.startswith(prefix) and 20 <= len(key) <= 2048
                    and all(33 <= ord(character) <= 126 for character in key),
                    'qualification.resources.credential-kind')
        return value
    finally:
        raw = b''


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Refusal('qualification.resources.redirect-refused')


def request(origin, method, path, key, body=None, headers=None):
    require(path.startswith('/') and not path.startswith('//') and '\r' not in path and '\n' not in path,
            'qualification.resources.path-bound')
    values = {'Authorization': 'Bearer ' + key, 'Accept': 'application/json'}
    values.update(headers or {})
    outbound = urllib.request.Request(origin + path, method=method, data=body, headers=values)
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect).open(outbound, timeout=25) as response:
            require(200 <= response.status <= 299, 'qualification.resources.http-refused')
            raw = response.read(65537)
            return decode(raw)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
        # Provider errors can contain submitted credentials or resource data.
        # They never become stdout, exception text or a saved report.
        raise Refusal('qualification.resources.provider-unavailable') from None


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 65536,
                'qualification.resources.ledger-bound')
        return decode(stream.read(65537))


def write(path, value, *, new=False):
    path = Path(path)
    parent = path.parent
    info = os.lstat(parent)
    require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
            and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
            'qualification.resources.private-output')
    payload = canonical(value)
    require(len(payload) <= 65536, 'qualification.resources.ledger-bound')
    if new:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    else:
        # A ledger is replaced atomically, never followed through a symlink.
        existing = os.lstat(path)
        require(stat.S_ISREG(existing.st_mode) and existing.st_nlink == 1
                and existing.st_uid == os.getuid(), 'qualification.resources.ledger-bound')
        temporary = path.with_name(path.name + '.next-' + os.urandom(8).hex())
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def finish(command):
    try:
        command()
    except (Refusal, ValueError, OSError):
        print('qualification.resources.refused', file=sys.stderr)
        raise SystemExit(1) from None
