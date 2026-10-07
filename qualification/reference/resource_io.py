"""Private local I/O for disposable resource preparation; never shipping code."""

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

from common import Refusal, canonical, closed, require
from fresh_evidence import decode

# Source-owned fixture/read traffic shares Airtable's base limit with the
# unmodified gateway. Leave a whole window between source calls/case starts;
# never retry a provider write or change a gateway result after a 429.
AIRTABLE_INTERVAL = 1.1
_airtable_lock = threading.Lock()
_airtable_next = 0.0


def pace_airtable():
    global _airtable_next
    with _airtable_lock:
        delay = _airtable_next - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        _airtable_next = time.monotonic() + AIRTABLE_INTERVAL


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


def exchange(origin, method, path, key, body=None, headers=None):
    require(path.startswith('/') and not path.startswith('//') and '\r' not in path and '\n' not in path,
            'qualification.resources.path-bound')
    if origin == 'https://api.airtable.com':
        pace_airtable()
    values = {'Authorization': 'Bearer ' + key, 'Accept': 'application/json'}
    values.update(headers or {})
    outbound = urllib.request.Request(origin + path, method=method, data=body, headers=values)
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect).open(outbound, timeout=25) as response:
            raw = response.read(65537)
            require(0 < len(raw) <= 65536, 'qualification.resources.response-bound')
            return response.status, raw
    except urllib.error.HTTPError as response:
        # Error bytes are private inputs too. No exception/provider detail is
        # printed; a reviewed denied-read probe may inspect only its status.
        with response:
            raw = response.read(65537)
            require(len(raw) <= 65536, 'qualification.resources.response-bound')
            return response.code, raw
    except (urllib.error.URLError, TimeoutError, OSError):
        # Provider errors can contain submitted credentials or resource data.
        # They never become stdout, exception text or a saved report.
        raise Refusal('qualification.resources.provider-unavailable') from None


def request(origin, method, path, key, body=None, headers=None):
    status, raw = exchange(origin, method, path, key, body, headers)
    require(200 <= status <= 299, 'qualification.resources.http-refused')
    return decode(raw)


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 65536,
                'qualification.resources.ledger-bound')
        return decode(stream.read(65537))


def write(path, value, *, new=False):
    payload = canonical(value)
    require(len(payload) <= 65536, 'qualification.resources.ledger-bound')
    write_bytes(path, payload, new=new)


def write_bytes(path, payload, *, new=False):
    """Durably write bounded public protocol bytes in an owner-private parent."""
    require(type(payload) is bytes and 0 < len(payload) <= 4 * 1024 * 1024,
            'qualification.resources.ledger-bound')
    path = Path(path)
    parent = path.parent
    info = os.lstat(parent)
    require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
            and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
            'qualification.resources.private-output')
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
    except Refusal as error:
        code = str(error)
        if not re.fullmatch(r'qualification\.[a-z0-9.-]{1,128}', code):
            code = 'qualification.resources.refused'
        print(code, file=sys.stderr)
        raise SystemExit(1) from None
    except (ValueError, OSError, KeyError, TypeError, ImportError, OverflowError,
            RecursionError, subprocess.SubprocessError):
        print('qualification.resources.refused', file=sys.stderr)
        raise SystemExit(1) from None
