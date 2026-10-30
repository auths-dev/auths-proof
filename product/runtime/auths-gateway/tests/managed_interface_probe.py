"""Untrusted client test: framing and OS probes only, no authorization evaluator."""
import base64
import json
import os
import socket
import struct
import subprocess
import sys


def exact(stream, count):
    value = bytearray()
    while len(value) < count:
        chunk = stream.recv(count - len(value))
        if not chunk:
            raise EOFError("closed native channel")
        value.extend(chunk)
    return bytes(value)


def receive(stream):
    length = struct.unpack('!I', exact(stream, 4))[0]
    assert 0 < length <= 8 * 1024 * 1024, 'unbounded native reply'
    return exact(stream, length)


def send(stream, value):
    stream.sendall(struct.pack('!I', len(value)) + value)


data = json.load(sys.stdin)
distinct = data['distinct_uid']
assert (os.geteuid() != data['gateway_uid']) == distinct, 'wrong test UID'
if distinct:
    assert os.geteuid() == 65534, 'wrong untrusted UID'
    for filename in data['private_paths']:
        try:
            with open(filename, 'rb') as private:
                private.read(1)
        except PermissionError:
            pass
        else:
            raise AssertionError('managed private file was readable')
    for filename in ('environ', 'mem'):
        try:
            with open(f"/proc/{data['gateway_pid']}/{filename}", 'rb') as private:
                private.read(1)
        except PermissionError:
            pass
        else:
            raise AssertionError('gateway process memory was readable')
    try:
        os.chmod(data['state'], 0o777)
    except PermissionError:
        pass
    else:
        raise AssertionError('application changed private state permissions')
    try:
        os.setuid(data['gateway_uid'])
    except PermissionError:
        pass
    else:
        raise AssertionError('application acquired gateway UID')

cases = []
for case in data['cases']:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(5)
        stream.connect(data['socket'])
        if case.get('advertised_length'):
            stream.sendall(struct.pack('!I', case['advertised_length']))
        elif case.get('raw_http'):
            stream.sendall(b'GET /credentials HTTP/1.1\r\n\r\n')
        else:
            send(stream, case['frame'].encode('utf-8'))
        reply = receive(stream)
        result = json.loads(reply)
        after = []
        if result.get('outcome') == 'ready':
            try:
                challenge = receive(stream)
                after.append(base64.b64encode(challenge).decode('ascii'))
                send(stream, b'{}')  # deliberately no recipient key possession
                try:
                    after.append(base64.b64encode(receive(stream)).decode('ascii'))
                except (EOFError, ConnectionResetError):
                    pass
            except (EOFError, ConnectionResetError):
                pass
            assert len(after) <= (0 if distinct else 1), 'unexpected bytes after failed recipient authentication'
        cases.append({'case': case['case'], 'response': result, 'after_ready_b64': after})

admin = []
if distinct:
    for frame in data['admin_frames']:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(5)
            stream.connect(data['admin_socket'])  # intentionally permissive inode
            try:
                send(stream, frame.encode('utf-8'))
                assert not stream.recv(1), 'operator bytes reached the wrong UID'
            except (BrokenPipeError, ConnectionResetError):
                pass
        admin.append(json.loads(frame)['command'])

cli = []
for name in data['cli_commands']:
    arguments = [data['binary'], 'help'] if name == 'help' else [data['binary'], name, '--help']
    result = subprocess.run(arguments, capture_output=True, timeout=10)
    assert result.returncode == 0, 'native help entry inaccessible'
    cli.append({'command': name, 'help_accessible': True})

private_cli = []
if distinct:
    for arguments in (
        ['serve', '--state-dir', data['state'], '--app-socket', data['socket'] + '.alternate'],
        ['status', '--state-dir', data['state'], '--admin-socket', data['admin_socket']],
        ['execution-witness', '--state-dir', data['state'], '--admin-socket', data['admin_socket']],
        ['readiness-probe', '--state-dir', data['state']],
        ['audit-export', '--state-dir', data['state'], '--admin-socket', data['admin_socket'], '--operation-id', 'forbidden', '--out', data['state'] + '/forbidden-audit.json'],
    ):
        result = subprocess.run([data['binary']] + arguments, capture_output=True, timeout=10)
        assert result.returncode != 0, 'application used a private native CLI route'
        private_cli.append({'command': arguments[0], 'refused': True,
                            'stdout_b64': base64.b64encode(result.stdout).decode('ascii'),
                            'stderr_b64': base64.b64encode(result.stderr).decode('ascii')})

direct = []
for credential in (None, 'pat_public_content_journey_fixture'):
    with socket.create_connection(('127.0.0.1', data['provider_port']), timeout=5) as stream:
        headers = '' if credential is None else f'Authorization: Bearer {credential}\r\n'
        stream.sendall(('PATCH /v0/appTEST0000000001/tblTEST0000000001/recTEST0000000001 HTTP/1.1\r\n'
                        'Host: localhost\r\n' + headers + 'Content-Length: 0\r\nConnection: close\r\n\r\n').encode('ascii'))
        response = bytearray()
        while chunk := stream.recv(4096):
            response.extend(chunk)
        assert bytes(response).startswith(b'HTTP/1.1 401 '), 'direct provider call acquired managed credentials'
        direct.append({'credential': 'absent' if credential is None else 'public-fixture-guess', 'status': 401})

json.dump({'distinct_uid': distinct, 'cases': cases, 'admin_commands_closed': admin,
           'cli': cli, 'private_cli': private_cli, 'direct_provider': direct,
           'private_files_inaccessible': len(data['private_paths']) if distinct else None}, sys.stdout)
