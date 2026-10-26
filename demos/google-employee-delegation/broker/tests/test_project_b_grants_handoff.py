"""The Project B two-grant probe is a pinned provider-state prerequisite."""

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from employee_read_demo.demo_co_contract import ContractRejected
from employee_read_demo.project_b_grants_handoff import (
    ProjectBGrantPins, validate_project_b_grants,
)


class ProjectBGrantsHandoffTests(unittest.TestCase):
    def test_exact_two_grant_result_and_tamper_refusals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'generation-0016'
            root.mkdir(mode=0o700)
            path = root / 'google-project-b-jules-grants.json'
            observation = {
                'schema_version': 'demo-co/google-project-b-jules-grants/v1',
                'attribution': 'provider_state_only',
                'company': 'test-company', 'instance': 'test-instance',
                'definition_hash': 'a' * 64,
                'observed_at': '1970-01-01T00:29:59Z',
                'resource_id': 'doc-project-b-plan',
                'document_id': 'project-b-doc', 'drive_id': 'project-drive',
                'jules_subject': 'jules-subject',
                'admin_owned_document_observed': True,
                'admin_export_matches_fixture': True,
                'read_grant_kind': 'google-person-jules-drive-readonly',
                'read_grant_http_status': 200,
                'read_grant_export_matches_fixture': True,
                'read_grant_denial_leaked_fixture': False,
                'write_grant_kind': 'google-write-person-jules-drive-file',
                'write_grant_http_status': 403,
                'write_grant_export_matches_fixture': False,
                'write_grant_denial_leaked_fixture': False,
            }

            def save() -> str:
                raw = json.dumps(observation, sort_keys=True).encode()
                path.write_bytes(raw)
                os.chmod(path, 0o600)
                return hashlib.sha256(raw).hexdigest()

            def pins(digest: str) -> ProjectBGrantPins:
                return ProjectBGrantPins(
                    'test-company', 'test-instance', 'a' * 64,
                    'jules-subject', 'project-b-doc', 'project-drive', digest,
                )

            original = save()
            result = validate_project_b_grants(path, pins(original), now=1800)
            self.assertEqual((result.read_grant_status, result.write_grant_status),
                             (200, 403))
            observation['write_grant_http_status'] = 200
            changed = save()
            with self.assertRaisesRegex(ContractRejected, 'digest'):
                validate_project_b_grants(path, pins(original), now=1800)
            with self.assertRaisesRegex(ContractRejected, 'differs'):
                validate_project_b_grants(path, pins(changed), now=1800)
            observation['write_grant_http_status'] = 403
            observation['read_grant_export_matches_fixture'] = False
            changed = save()
            with self.assertRaisesRegex(ContractRejected, 'differs'):
                validate_project_b_grants(path, pins(changed), now=1800)
            observation['read_grant_export_matches_fixture'] = True
            self.assertEqual(save(), original)
            with self.assertRaisesRegex(ContractRejected, 'stale'):
                validate_project_b_grants(path, pins(original), now=5400)
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(ContractRejected, 'unavailable'):
                validate_project_b_grants(path, pins(original), now=1800)


if __name__ == '__main__':
    unittest.main()
