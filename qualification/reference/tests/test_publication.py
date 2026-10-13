"""Publication-tree confinement; native leak decisions run in the Rust pipeline."""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

path = Path(__file__).resolve().parents[2] / 'run/scan_publication.py'
spec = importlib.util.spec_from_file_location('scan_publication', path)
publication = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publication)


class Publication(unittest.TestCase):
    def workspace(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        work = Path(temporary.name).resolve()
        (work / 'cases').mkdir()
        (work / 'canaries').write_bytes(b'synthetic-private-scan-canary\n')
        (work / 'canaries').chmod(0o600)
        (work / 'commissioning-effects.json').write_bytes(b'closed synthetic facts')
        return work

    def test_unlisted_phase_files_and_all_output_kinds_enter_the_scan(self):
        work = self.workspace()
        for kind in ['log', 'trace', 'metric', 'support-bundle']:
            directory = work / 'scan' / kind
            directory.mkdir(parents=True)
            (directory / 'retained-output').write_bytes(b'closed synthetic state')
        (work / 'unexpected-output').write_bytes(b'closed synthetic public data')
        values = publication.sources(work)
        self.assertEqual(len(values), 6)
        self.assertEqual({kind for _, kind, _ in values},
                         {'log', 'trace', 'metric', 'support-bundle', 'evidence'})
        self.assertIn('commissioning-effects.json', {name for name, _, _ in values})
        self.assertIn('unexpected-output', {name for name, _, _ in values})
        self.assertNotIn('canaries', {name for name, _, _ in values})

    def test_links_special_files_and_public_canaries_refuse(self):
        for mode in ['file-link', 'directory-link', 'hard-link', 'fifo', 'public-canary']:
            work = self.workspace()
            if mode == 'file-link':
                (work / 'linked-output').symlink_to(work / 'canaries')
            elif mode == 'directory-link':
                (work / 'linked-directory').symlink_to(work / 'cases', target_is_directory=True)
            elif mode == 'hard-link':
                os.link(work / 'canaries', work / 'linked-output')
            elif mode == 'fifo':
                os.mkfifo(work / 'fifo')
            else:
                (work / 'canaries').chmod(0o644)
            with self.assertRaises(publication.Refusal, msg=mode): publication.sources(work)

    def test_no_executable_or_oversized_source_is_silently_excluded(self):
        work = self.workspace()
        binary = work / 'bin/auths-gateway'
        binary.parent.mkdir()
        with binary.open('wb') as stream:
            stream.truncate(publication.MAX_BYTES + 1)
        with self.assertRaises(publication.Refusal): publication.sources(work)


if __name__ == '__main__':
    unittest.main()
