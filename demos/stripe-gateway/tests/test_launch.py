"""Private env input stays on operator stdin; live never means a URL toggle."""
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('demo_launch', Path(__file__).resolve().parents[1] / 'launch.py')
launch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launch)
common_spec = importlib.util.spec_from_file_location(
    'demo_socket_layout', Path(__file__).resolve().parents[1] / 'demo_common.py')
common = importlib.util.module_from_spec(common_spec)
common_spec.loader.exec_module(common)


class LaunchTests(unittest.TestCase):
    def test_readiness_is_a_native_process_event_and_is_retained_in_the_log(self):
        command = [sys.executable, '-c',
                   'import sys; print("app socket ready; fixture", flush=True); sys.stdin.buffer.read(1)']
        with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL) as process:
            try:
                log = io.BytesIO()
                common.wait_gateway_ready(process, log, timeout=5)
                self.assertEqual(log.getvalue(), b'app socket ready; fixture\n')
                self.assertIsNone(process.poll())
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)

    def test_existing_socket_paths_are_not_readiness_or_cleanup_authority(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            app = Path(directory) / 'app.sock'
            admin = Path(directory) / 'admin.sock'
            with socket.socket(socket.AF_UNIX) as live:
                live.bind(str(app))
                live.listen(1)
                with socket.socket(socket.AF_UNIX) as stale:
                    stale.bind(str(admin))
                identities = [(path.stat().st_dev, path.stat().st_ino) for path in (app, admin)]
                with subprocess.Popen([sys.executable, '-c', 'pass'], stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL) as process:
                    with self.assertRaisesRegex(common.Refusal, 'demo.gateway-start-refused'):
                        common.wait_gateway_ready(process, io.BytesIO(), timeout=5)
                    process.wait(timeout=5)
                self.assertEqual(identities, [(path.stat().st_dev, path.stat().st_ino)
                                             for path in (app, admin)])
                with socket.socket(socket.AF_UNIX) as client:
                    client.settimeout(1)
                    client.connect(str(app))
                    accepted, _ = live.accept()
                    accepted.close()

    def test_partial_readiness_line_has_a_bounded_deadline(self):
        read_end, write_end = os.pipe()
        try:
            os.write(write_end, b'app socket ready; unterminated')
            with os.fdopen(read_end, 'rb') as stdout:
                process = SimpleNamespace(stdout=stdout, poll=lambda: None)
                with self.assertRaisesRegex(common.Refusal, 'demo.gateway-start-timeout'):
                    common.wait_gateway_ready(process, io.BytesIO(), timeout=0.05)
        finally:
            os.close(write_end)

    def test_each_gateway_has_a_protected_application_socket_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = common.create_socket_directories(directory, os.getgid())
            self.assertEqual(paths, common.application_socket_paths(directory))
            self.assertEqual(len({path.parent for path in paths}), 3)
            for host, path in enumerate(paths):
                self.assertEqual(path, Path(directory) / 'sockets' / ('gateway' + str(host)) / 'app.sock')
                for parent in (path.parent, path.parent.parent):
                    info = parent.stat()
                    self.assertEqual(info.st_uid, os.getuid())
                    self.assertEqual(info.st_gid, os.getgid())
                    self.assertEqual(stat.S_IMODE(info.st_mode), 0o750)
            recovery = Path(directory) / 'sockets' / 'review.sock'
            self.assertNotIn(recovery.parent, {path.parent for path in paths})

    def env(self, directory):
        path = Path(directory) / '.env'
        values = {name: 'simulation-value-' + str(index) for index, name in enumerate(launch.ENV_FIELDS.values())}
        path.write_text('IGNORED_VAR=unrelated\n' + '\n'.join(name + "='" + value + "' # private" for name, value in values.items()))
        os.chmod(path, 0o644)
        return path, values

    def test_live_secrets_are_only_stdin_not_arguments_or_mounts(self):
        with tempfile.TemporaryDirectory() as directory:
            path, values = self.env(directory)
            calls = []
            def run(command, **kwargs):
                calls.append((command, kwargs))
                return SimpleNamespace(returncode=0, stdout=b'unix:///local/docker.sock')
            with patch.object(launch.sys, 'argv', ['launch.py', '--live', '--env-file', str(path)]), \
                 patch.object(launch.shutil, 'which', return_value='/docker'), \
                 patch.object(launch.subprocess, 'run', side_effect=run), \
                 patch.object(launch.sys, 'stdout', io.StringIO()), \
                 patch.dict(launch.os.environ, {}, clear=True):
                with self.assertRaises(SystemExit) as exited:
                    launch.main()
                self.assertEqual(exited.exception.code, 0)
            command, options = calls[-1]
            self.assertIn('--live', command)
            self.assertNotIn(str(path), command)
            self.assertEqual(json.loads(options['input']), {field: values[name] for field, name in launch.ENV_FIELDS.items()})
            for secret in values.values():
                self.assertNotIn(secret, ' '.join(command))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_duplicate_and_symlink_inputs_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _ = self.env(directory)
            alias = Path(directory) / 'alias'
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                launch.credentials(alias)
            with path.open('a') as output:
                output.write('\n' + next(iter(launch.ENV_FIELDS.values())) + '=duplicate')
            with self.assertRaises(ValueError):
                launch.credentials(path)

    def test_remote_docker_refuses_before_credentials_are_read(self):
        with patch.object(launch.sys, 'argv', ['launch.py', '--live', '--env-file', '/private/env']), \
             patch.object(launch.shutil, 'which', return_value='/docker'), \
             patch.dict(launch.os.environ, {'DOCKER_HOST': 'tcp://remote.invalid:2375'}, clear=True), \
             patch.object(launch, 'credentials') as reader:
            with self.assertRaises(ValueError):
                launch.main()
            reader.assert_not_called()


if __name__ == '__main__':
    unittest.main()
