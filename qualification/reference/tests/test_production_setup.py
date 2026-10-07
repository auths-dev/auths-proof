"""Private process boundaries, without credentials or provider evidence."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import Refusal
import production_setup as setup


class Production(unittest.TestCase):
    def deployment(self):
        value = object.__new__(setup.Deployment)
        value.database = {'AUTHS_POSTGRES_URL': 'synthetic-only sslmode=require',
            'AUTHS_POSTGRES_CA_PEM': '/synthetic-only-ca', 'AUTHS_POSTGRES_SERVER_NAME': 'localhost'}
        value.operator_token = Path('/synthetic-only-operator-token')
        value.runtime_token = Path('/synthetic-only-runtime-token')
        return value

    def test_runtime_cannot_inherit_writer_identity_or_ambient_credentials(self):
        value = self.deployment()
        environment = value.environment()
        self.assertEqual(environment['AWS_ROLE_ARN'], setup.RUNTIME_ROLE)
        self.assertEqual(environment['AWS_WEB_IDENTITY_TOKEN_FILE'], str(value.runtime_token))
        self.assertEqual(set(environment), {'PATH', 'AWS_ROLE_ARN', 'AWS_WEB_IDENTITY_TOKEN_FILE', *setup.DATABASE_ENV})
        operator = value.environment(administrative=True)
        self.assertEqual(operator['AWS_ROLE_ARN'], setup.OPERATOR_ROLE)
        self.assertEqual(operator['AUTHS_GATEWAY_RUNTIME_ROLE_ARN'], setup.RUNTIME_ROLE)
        self.assertEqual(operator['AUTHS_GATEWAY_RUNTIME_TOKEN_FILE'], str(value.runtime_token))
        self.assertNotEqual(operator['AWS_ROLE_ARN'], operator['AUTHS_GATEWAY_RUNTIME_ROLE_ARN'])

    def test_native_refusal_never_exports_an_external_detail_or_secret(self):
        refused = subprocess.CompletedProcess([], 1, b'',
            b'gateway.install.credential-store-unavailable private-external-detail')
        with self.assertRaisesRegex(Refusal, '^qualification.production.gateway.install.credential-store-unavailable$'):
            setup.native_output(refused, [b'synthetic-only-sensitive-value'])
        leaked = subprocess.CompletedProcess([], 0, b'{"secret":"synthetic-only-sensitive-value"}', b'')
        with self.assertRaisesRegex(Refusal, 'secret-exposed'):
            setup.native_output(leaked, [b'synthetic-only-sensitive-value'])
        with self.assertRaisesRegex(Refusal, 'output-bound'):
            setup.native_output(subprocess.CompletedProcess([], 0, b'x' * 65537, b''), [])

    def test_private_identity_inputs_refuse_links_wrong_owner_and_readable_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'token'
            path.write_bytes(b'synthetic-only-token')
            path.chmod(0o600)
            self.assertEqual(setup.private_file(path, os.getuid()), path)
            linked = path.with_name('linked')
            linked.symlink_to(path)
            with self.assertRaises(Refusal): setup.private_file(linked, os.getuid())
            hardlinked = path.with_name('hardlinked')
            os.link(path, hardlinked)
            with self.assertRaises(Refusal): setup.private_file(path, os.getuid())
            hardlinked.unlink()
            with self.assertRaises(Refusal): setup.private_file(path, os.getuid() + 1)
            path.chmod(0o644)
            with self.assertRaises(Refusal): setup.private_file(path, os.getuid())


if __name__ == '__main__':
    unittest.main()
