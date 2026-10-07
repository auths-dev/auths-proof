"""Artifact transport cannot choose code, another run or unbounded input."""

import copy
import hashlib
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'run'))
import artifact_wait
from common import Refusal


class ArtifactWait(unittest.TestCase):
    def artifact(self):
        return {'id': 12, 'name': 'qualification-first-release-airtable-record-update-v1-123-1',
            'expired': False, 'size_in_bytes': 1024, 'digest': 'sha256:' + '1' * 64,
            'workflow_run': {'id': 123, 'head_sha': '2' * 40, 'head_branch': 'main',
                'repository_id': artifact_wait.REPOSITORY_ID,
                'head_repository_id': artifact_wait.REPOSITORY_ID}}

    def test_an_artifact_binds_exact_name_run_source_and_repository(self):
        artifact = self.artifact()
        def select(value):
            return artifact_wait.select_artifact({'total_count': 1, 'artifacts': [value]},
                                                  artifact['name'], '123', '2' * 40)
        self.assertEqual(select(artifact), artifact)
        for change in [lambda a: a.update(expired=True), lambda a: a.update(id=True),
                       lambda a: a.update(digest='1' * 64),
                       lambda a: a.update(size_in_bytes=artifact_wait.MAX_ARCHIVE + 1),
                       lambda a: a['workflow_run'].update(id=124),
                       lambda a: a['workflow_run'].update(head_sha='3' * 40),
                       lambda a: a['workflow_run'].update(head_branch='codex/unreviewed'),
                       lambda a: a['workflow_run'].update(head_repository_id=42)]:
            changed = copy.deepcopy(artifact)
            change(changed)
            with self.assertRaises(Refusal): select(changed)
        self.assertIsNone(select(dict(artifact, name='another-attempt')))
        with self.assertRaises(Refusal):
            artifact_wait.select_artifact({'total_count': 2, 'artifacts': [artifact, artifact]},
                                         artifact['name'], '123', '2' * 40)

    def test_only_main_dispatch_of_the_exact_attempt_and_workflow_is_allowed(self):
        environment = {'GITHUB_REPOSITORY': artifact_wait.REPOSITORY, 'GITHUB_EVENT_NAME': 'workflow_dispatch',
            'GITHUB_REF': 'refs/heads/main', 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1',
            'GITHUB_SHA': '2' * 40}
        self.assertEqual(artifact_wait.identity(environment), ('123', '1', '2' * 40))
        for name, value in [('GITHUB_REPOSITORY', 'fork/unreviewed'), ('GITHUB_EVENT_NAME', 'pull_request'),
                            ('GITHUB_REF', 'refs/pull/206/merge'), ('GITHUB_RUN_ATTEMPT', '01')]:
            with self.assertRaises(Refusal): artifact_wait.identity(dict(environment, **{name: value}))
        run = {'id': 123, 'run_attempt': 1, 'head_sha': '2' * 40, 'head_branch': 'main',
            'event': 'workflow_dispatch', 'path': artifact_wait.WORKFLOW,
            'repository': {'id': artifact_wait.REPOSITORY_ID},
            'head_repository': {'id': artifact_wait.REPOSITORY_ID}}
        artifact_wait.check_run(run, '123', '1', '2' * 40)
        for name, value in [('run_attempt', 2), ('path', '.github/workflows/unreviewed.yml'),
                            ('event', 'pull_request')]:
            with self.assertRaises(Refusal): artifact_wait.check_run(dict(run, **{name: value}), '123', '1', '2' * 40)

    def archive(self, entries):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            for name, value in entries:
                archive.writestr(name, value)
        return output.getvalue()

    def test_archive_paths_links_executables_duplicates_and_decompression_are_refused(self):
        link = zipfile.ZipInfo('linked.json')
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        invalid = [[('../record.json', b'{}')], [('/record.json', b'{}')],
            [('a//record.json', b'{}')], [('record.json', b'{}'), ('record.json', b'{}')],
            [('a.json', b'{}'), ('a.json/record.json', b'{}')], [(link, b'root.key')],
            [('harness.py', b'pass')], [('hidden/.key.json', b'{}')], [('empty.json', b'')],
            [('huge.json', b'x' * (artifact_wait.MAX_FILE + 1))], [('dir///', b'')]]
        for entries in invalid:
            with zipfile.ZipFile(io.BytesIO(self.archive(entries))) as archive:
                with self.assertRaises(Refusal): artifact_wait.members(archive)

    def test_digest_checked_extraction_publishes_only_private_public_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            work.chmod(0o700)
            path = work / 'public.zip'
            payload = self.archive([('record.json', b'{"source":"reviewed"}'),
                                    ('evidence/conformance.json', b'{}')])
            path.write_bytes(payload)
            artifact = {'digest': 'sha256:' + hashlib.sha256(payload).hexdigest()}
            with self.assertRaises(Refusal): artifact_wait.unpack(path, {'digest': 'sha256:' + '0' * 64}, work / 'bad')
            self.assertFalse((work / 'bad').exists())
            artifact_wait.unpack(path, artifact, work / 'accepted')
            for file in ['record.json', 'evidence/conformance.json']:
                self.assertEqual(stat.S_IMODE(os.lstat(work / 'accepted' / file).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.lstat(work / 'accepted/evidence').st_mode), 0o700)


if __name__ == '__main__':
    unittest.main()
