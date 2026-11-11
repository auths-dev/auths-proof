"""Bounded demo files and transport-independent public records, never authority."""
import base64
import hashlib
import json
import os
from pathlib import Path
import selectors
import time

MAX_FILE = 4 * 1024 * 1024


def application_socket_paths(home):
    """One protected socket parent per independently serving gateway."""
    root = Path(home) / 'sockets'
    return tuple(root / ('gateway' + str(host)) / 'app.sock' for host in range(3))


def create_socket_directories(home, application_gid):
    """Gateway UID owns each parent; the application group may traverse only."""
    root = Path(home) / 'sockets'
    paths = application_socket_paths(home)
    for directory in (root, *(path.parent for path in paths)):
        directory.mkdir(mode=0o750)
        os.chown(directory, os.getuid(), application_gid)
        os.chmod(directory, 0o750)
    return paths


def wait_gateway_ready(process, log, *, timeout=20):
    """Wait for this process's bounded native readiness event, not a pathname."""
    require(process.stdout is not None, 'demo.gateway-start-refused')
    deadline = time.monotonic() + timeout
    output = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while len(output) <= 65536:
            remaining = deadline - time.monotonic()
            require(remaining > 0 and selector.select(remaining), 'demo.gateway-start-timeout')
            chunk = os.read(process.stdout.fileno(), min(4096, 65537 - len(output)))
            require(bool(chunk), 'demo.gateway-start-refused')
            log.write(chunk)
            log.flush()
            output.extend(chunk)
            if b'\n' in output:
                line = output.split(b'\n', 1)[0]
                require(len(output) <= 65536 and line.startswith(b'app socket ready')
                        and process.poll() is None, 'demo.gateway-start-refused')
                return
    raise Refusal('demo.gateway-start-refused')


def review_socket_path(request, *, recovery, owner):
    """Select an explicitly configured operator channel, never an app parent."""
    return Path(owner if 'mutation' in request else recovery)


class Refusal(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise Refusal(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def unb64(value):
    require(type(value) is str and len(value) <= MAX_FILE * 2, 'demo.invalid-encoding')
    try:
        data = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    except ValueError:
        raise Refusal('demo.invalid-encoding') from None
    require(b64(data) == value, 'demo.invalid-encoding')
    return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path, maximum=MAX_FILE):
    path = Path(path)
    require(not path.is_symlink() and path.is_file() and path.stat().st_size <= maximum,
            'demo.file-unavailable')
    return path.read_bytes()


def decode(data):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, 'demo.duplicate-field')
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: require(False, 'demo.invalid-json'))
    except (ValueError, UnicodeError, RecursionError):
        raise Refusal('demo.invalid-json') from None


def write(path, data, *, new=False, mode=0o600):
    path = Path(path)
    require(not path.is_symlink(), 'demo.invalid-file')
    if new:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    else:
        temporary = path.with_name(path.name + '.pending')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
