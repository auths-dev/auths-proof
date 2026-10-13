"""Private env input stays on operator stdin; live never means a URL toggle."""
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('demo_launch', Path(__file__).resolve().parents[1] / 'launch.py')
launch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launch)


class LaunchTests(unittest.TestCase):
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
