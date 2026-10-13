"""Control-plane closure tests; synthetic assembly is not provider evidence."""

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'run'))
import close_proposal
import scan_publication as publication


class Closure(unittest.TestCase):
    def work(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        work = Path(temporary.name)
        os.chmod(work, 0o700)
        (work / 'cases').mkdir()
        (work / 'canaries').write_bytes(b'synthetic-private-scan-canary\n')
        (work / 'canaries').chmod(0o600)
        (work / 'facts.json').write_bytes(b'{}')
        return work

    def synthetic_scan(self, work, _tool, keep_canaries):
        self.assertTrue(keep_canaries)
        report = work / 'cases/redaction.scan.json'
        report.unlink(missing_ok=True)
        entries = publication.sources(work)
        # Mirrors the native scanner's source-kind/ordinal report identities.
        report.write_bytes(json.dumps([(i, kind) for i, (_, kind, _) in enumerate(entries)]).encode())
        self.scanned.append({name: publication.contents(work / name) for name, _, _ in entries})

    def synthetic_assemble(self, _family, work, _environment, _run, _stage, _tool):
        self.builds += 1
        proposal = work / 'proposal'
        proposal.mkdir(exist_ok=True)
        # Each assembly changes the bytes, while the complete set of output
        # categories stays fixed. The last scan must see the rebuilt bytes.
        (proposal / 'record.json').write_bytes(json.dumps({'assembly': self.builds}).encode())
        (proposal / 'redaction.json').write_bytes(publication.contents(work / 'cases/redaction.scan.json'))

    def run_close(self, work, stage='live', assembly=None, scan=None):
        self.builds, self.scanned = 0, []
        with patch.object(close_proposal, 'assemble', assembly or self.synthetic_assemble), \
                patch.object(publication, 'scan', scan or self.synthetic_scan):
            close_proposal.close('synthetic-family', work, 'synthetic-environment',
                                 'synthetic-run', stage, Path('/synthetic-native-issuer'))

    def test_final_bytes_and_complete_report_are_scanned_before_canary_removal(self):
        work = self.work()
        self.run_close(work)
        self.assertEqual(self.builds, 2)
        self.assertEqual(len(self.scanned), 3)
        self.assertNotIn('proposal/record.json', self.scanned[0])
        self.assertEqual(self.scanned[-1]['proposal/record.json'], b'{"assembly": 2}')
        self.assertEqual((work / 'proposal/redaction.json').read_bytes(),
                         (work / 'cases/redaction.scan.json').read_bytes())
        self.assertFalse((work / 'canaries').exists())

    def test_commissioning_keeps_canaries_for_the_subsequent_ordinary_live_phase(self):
        work = self.work()
        self.run_close(work, stage='commissioning')
        self.assertTrue((work / 'canaries').exists())
        self.assertTrue((work / 'proposal/record.json').exists())

    def test_second_assembly_cannot_grow_the_publication_tree_and_leave_a_proposal(self):
        work = self.work()
        def expand(*arguments):
            self.synthetic_assemble(*arguments)
            if self.builds == 2:
                (work / 'unexpected.json').write_bytes(b'{}')
        with self.assertRaises(publication.Refusal): self.run_close(work, assembly=expand)
        self.assertFalse((work / 'proposal').exists())
        self.assertFalse((work / 'cases/redaction.scan.json').exists())
        self.assertTrue((work / 'canaries').exists())

    def test_assembly_or_final_scan_failure_invalidates_all_proposal_outputs(self):
        for failure in ['assembly', 'scan']:
            work = self.work()
            def assemble(*args):
                self.synthetic_assemble(*args)
                if failure == 'assembly': raise publication.Refusal('synthetic-refusal')
            def scan(*args, **kwargs):
                self.synthetic_scan(*args, **kwargs)
                if failure == 'scan' and self.builds == 2:
                    raise publication.Refusal('synthetic-refusal')
            with self.assertRaises(publication.Refusal):
                self.run_close(work, assembly=assemble, scan=scan)
            self.assertFalse((work / 'proposal').exists())
            self.assertFalse((work / 'evidence').exists())
            self.assertFalse((work / 'cases/redaction.scan.json').exists())
            self.assertTrue((work / 'canaries').exists())


if __name__ == '__main__':
    unittest.main()
