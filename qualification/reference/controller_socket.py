"""Private root-to-root operation transport for the reviewed stage harness.

Only case coordinates cross this socket. A caller supplies no packet, secret,
command, expected verdict or output path. The owner retains actual measured
state across stage-runner processes and refuses unknown/unimplemented steps.
"""

import os
from pathlib import Path
import re
import socket
import stat
import struct
import time

from common import canonical, closed, Refusal, require
from expand import decode

REQUEST = 'auths.qualification-controller-step/1'
REPLY = 'auths.qualification-controller-reply/1'
MAX_REPLY = 65536


def endpoint(path, *, existing):
    path = Path(path).absolute()
    require(os.getuid() == 0 and hasattr(socket, 'SO_PEERCRED')
            and len(str(path).encode()) <= 107 and path.resolve() == path,
            'qualification.controller.identity')
    parent = os.lstat(path.parent)
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0
            and stat.S_IMODE(parent.st_mode) == 0o700,
            'qualification.controller.private-directory')
    if existing:
        info = os.lstat(path)
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0
                and stat.S_IMODE(info.st_mode) == 0o600, 'qualification.controller.socket')
    else:
        require(not path.exists() and not path.is_symlink(), 'qualification.controller.socket')
    return path


def peer(connection):
    _pid, uid, _gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    require(uid == 0, 'qualification.controller.peer')


def receive(connection, maximum):
    result = b''
    while not result.endswith(b'\n'):
        chunk = connection.recv(min(4096, maximum + 1 - len(result)))
        require(chunk and len(result) + len(chunk) <= maximum, 'qualification.controller.message-bound')
        result += chunk
    require(result.count(b'\n') == 1, 'qualification.controller.message-bound')
    value = decode(result)
    require(result == canonical(value) + b'\n', 'qualification.controller.message-canonical')
    return value


def checked_request(value, family):
    closed(value, ['schema', 'family', 'case', 'index', 'operation'])
    require(value['schema'] == REQUEST and value['family'] == family
            and type(value['case']) is str and re.fullmatch(r'(commissioning|live)-[a-z0-9-]{1,64}', value['case'])
            and type(value['index']) is int and 0 <= value['index'] < 16
            and value['operation'] in ['submit', 'probe', 'replay', 'race', 'restart', 'crash',
                'rotate', 'read-back', 'drop-response', 'delay-visibility', 'installed-consumer'],
            'qualification.controller.coordinates')
    return value


def call(path, family, case, index, operation):
    path = endpoint(path, existing=True)
    request = checked_request({'schema': REQUEST, 'family': family, 'case': case,
                               'index': index, 'operation': operation}, family)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(120)
        connection.connect(str(path))
        peer(connection)
        connection.sendall(canonical(request) + b'\n')
        reply = receive(connection, MAX_REPLY)
    if type(reply) is dict and set(reply) == {'schema', 'code'}:
        require(reply['schema'] == REPLY and type(reply['code']) is str
                and re.fullmatch(r'qualification\.[a-z0-9.-]{1,128}', reply['code']),
                'qualification.controller.reply')
        raise Refusal(reply['code'])
    closed(reply, ['schema', 'observation'])
    require(reply['schema'] == REPLY and type(reply['observation']) is dict,
            'qualification.controller.reply')
    return reply['observation']


def serve(path, operations, deadline, stopping):
    path = endpoint(path, existing=False)
    require(type(deadline) in [int, float] and time.monotonic() < deadline <= time.monotonic() + 7200,
            'qualification.controller.deadline')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        os.chmod(path, 0o600)
        inode = os.lstat(path).st_ino
        server.listen(1)
        server.settimeout(0.25)
        try:
            while not stopping.is_set() and time.monotonic() < deadline:
                try:
                    connection, _ = server.accept()
                except socket.timeout:
                    continue
                with connection:
                    connection.settimeout(120)
                    try:
                        peer(connection)
                        value = checked_request(receive(connection, 4096), operations.family)
                        observation = operations.step(value['case'], value['index'], value['operation'])
                        reply = {'schema': REPLY, 'observation': observation}
                    except (Refusal, OSError, ValueError, KeyError, TypeError, TimeoutError) as error:
                        code = str(error) if isinstance(error, Refusal) else 'qualification.controller.operation-refused'
                        if re.fullmatch(r'qualification\.[a-z0-9.-]{1,128}', code) is None:
                            code = 'qualification.controller.operation-refused'
                        reply = {'schema': REPLY, 'code': code}
                    payload = canonical(reply) + b'\n'
                    require(len(payload) <= MAX_REPLY, 'qualification.controller.message-bound')
                    try:
                        connection.sendall(payload)
                    except OSError:
                        # A lost report cannot undo an entered native attempt;
                        # its case coordinates remain consumed by Operations.
                        pass
        finally:
            if path.exists() and os.lstat(path).st_ino == inode:
                path.unlink()
