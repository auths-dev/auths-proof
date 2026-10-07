"""Actual file-open and bounded socket refusals, without provider traffic."""

import errno
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import application_probe as application
from common import Refusal


class Application(unittest.TestCase):
    def test_readable_missing_or_non_permission_errors_cannot_be_reported_as_isolation(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(application.os, 'getuid', return_value=application.APPLICATION_UID), \
                patch.dict(os.environ, {'PATH': '/usr/bin:/bin'}, clear=True):
            path = Path(directory) / 'synthetic-only-private-file'
            path.write_bytes(b'synthetic-only-not-a-secret')
            with self.assertRaisesRegex(Refusal, 'private-file-accessible'):
                application.probe('files', [str(path)])
            path.unlink()
            with self.assertRaisesRegex(Refusal, 'file-refusal-unmeasured'):
                application.probe('files', [str(path)])
            with patch.object(application.os, 'open', side_effect=OSError(errno.EACCES, 'synthetic-only')):
                report = application.probe('files', [str(path)])
            self.assertEqual(report['attempted'], report['refused'])
            self.assertEqual(report['provider_requests'], 0)

    def test_successful_or_unmeasured_connection_cannot_be_reported_as_egress_refusal(self):
        connection = MagicMock()
        factory = MagicMock()
        factory.__enter__.return_value = connection
        with patch.object(application.os, 'getuid', return_value=application.APPLICATION_UID), \
                patch.dict(os.environ, {'PATH': '/usr/bin:/bin'}, clear=True), \
                patch.object(application.socket, 'socket', return_value=factory):
            with self.assertRaisesRegex(Refusal, 'provider-reachable'):
                application.probe('egress', ['8.8.8.8'])
            connection.connect.side_effect = TimeoutError('synthetic-only')
            with self.assertRaisesRegex(Refusal, 'egress-refusal-unmeasured'):
                application.probe('egress', ['8.8.8.8'])
            connection.connect.side_effect = PermissionError(errno.EACCES, 'synthetic-only')
            report = application.probe('egress', ['8.8.8.8', '2606:4700:4700::1111'])
            self.assertEqual(report['attempted'], 2)
            self.assertEqual(report['refused'], 2)
            self.assertEqual(report['provider_requests'], 0)
            with self.assertRaises(Refusal): application.probe('egress', ['127.0.0.1'])

    def test_an_ambient_provider_credential_refuses_before_the_probe(self):
        with patch.object(application.os, 'getuid', return_value=application.APPLICATION_UID), \
                patch.dict(os.environ, {'AUTHS_QUALIFICATION_PROVIDER_CREDENTIAL': 'synthetic-only'}, clear=True), \
                patch.object(application.os, 'open') as opened:
            with self.assertRaises(Refusal): application.probe('files', ['/unreviewed'])
            opened.assert_not_called()


if __name__ == '__main__':
    unittest.main()
