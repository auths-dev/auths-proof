"""Hosted identity and owned cleanup boundaries; no real token or provider."""

import base64
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import Refusal
import production_environment as infrastructure


class Environment(unittest.TestCase):
    environment = {'GITHUB_REPOSITORY': 'auths-dev/auths-proof',
        'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/main',
        'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_SHA': '1' * 40}

    def claims(self):
        return {'iss': 'https://token.actions.githubusercontent.com', 'aud': 'sts.amazonaws.com',
            'sub': infrastructure.SUBJECT, 'repository_id': '1310728509',
            'repository_owner_id': '260513770', 'repository': 'auths-dev/auths-proof',
            'event_name': 'workflow_dispatch', 'ref': 'refs/heads/main', 'sha': '1' * 40,
            'run_id': '123', 'run_attempt': '2', 'iat': 1000, 'exp': 1300}

    @staticmethod
    def token(claims):
        encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
        return 'synthetic-only-header.' + encoded + '.synthetic-only-signature'

    def test_identity_preconditions_bind_the_actual_run_and_freshness(self):
        with patch.object(infrastructure.time, 'time', return_value=1000):
            raw = self.token(self.claims())
            self.assertEqual(infrastructure.checked_token(raw, self.environment), raw.encode())
            mutations = {'iss': 'https://example.invalid', 'aud': 'unreviewed', 'sub': 'unreviewed',
                'repository_id': '1', 'repository_owner_id': '1', 'repository': 'unreviewed',
                'event_name': 'pull_request', 'ref': 'refs/heads/unreviewed', 'sha': '2' * 40,
                'run_id': '124', 'run_attempt': '1', 'iat': True, 'exp': True}
            for name, value in mutations.items():
                with self.subTest(name=name), self.assertRaises(Refusal):
                    infrastructure.checked_token(self.token(dict(self.claims(), **{name: value})), self.environment)
            for times in [(879, 1300), (1031, 1300), (1000, 1060), (1000, 1901)]:
                with self.assertRaises(Refusal):
                    infrastructure.checked_token(self.token(dict(self.claims(), iat=times[0], exp=times[1])), self.environment)
            with self.assertRaises(Refusal):
                infrastructure.checked_token(self.token([]), self.environment)

    def test_request_destination_cannot_be_selected_by_credentials_or_redirects(self):
        url = 'https://pipelines.actions.githubusercontent.com/identity?api-version=2.0'
        self.assertEqual(infrastructure.token_url(url), url + '&audience=sts.amazonaws.com')
        for value in ['http://pipelines.actions.githubusercontent.com/identity',
                      'https://actions.githubusercontent.com.example.invalid/identity',
                      'https://user@pipelines.actions.githubusercontent.com/identity',
                      url + '#fragment', url + '&audience=unreviewed',
                      'https://pipelines.actions.githubusercontent.com:bad/identity',
                      'https://pipelines.actions.githubusercontent.com:443/identity']:
            with self.subTest(value=value), self.assertRaises(Refusal):
                infrastructure.token_url(value)

    def test_cleanup_continues_after_owned_database_failure_and_retains_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = object.__new__(infrastructure.Infrastructure)
            value.stopping, value.refresher = threading.Event(), None
            value.container, value.request_token = 'auths-qualification-synthetic-only', 'synthetic-only-token'
            value.tokens, value.clock_configuration = root, root / 'clock.conf'
            for name in ['operator.jwt', 'runtime.jwt', 'clock.conf']:
                (root / name).write_bytes(b'synthetic-only-private-input')
            calls = []
            def refused(arguments, **kwargs):
                calls.append(arguments)
                raise Refusal('qualification.infrastructure.command-refused')
            with patch.object(infrastructure, 'command', refused), self.assertRaisesRegex(Refusal, 'cleanup-incomplete'):
                value.close()
            self.assertEqual(len(calls), 1)
            self.assertIn('name=^/auths-qualification-synthetic-only$', calls[0])
            self.assertEqual(list(root.iterdir()), [])
            self.assertIsNone(value.request_token)
            self.assertEqual(value.container, 'auths-qualification-synthetic-only')

    def test_failed_container_start_can_retire_when_its_exact_name_is_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            value = object.__new__(infrastructure.Infrastructure)
            value.stopping, value.refresher = threading.Event(), None
            value.tokens, value.container = Path(directory), 'auths-qualification-synthetic-only'
            value.request_token = 'synthetic-only-token'
            with patch.object(infrastructure, 'command', return_value=b'') as command:
                value.close()
            self.assertEqual(command.call_count, 1)
            self.assertIsNone(value.container)


if __name__ == '__main__':
    unittest.main()
