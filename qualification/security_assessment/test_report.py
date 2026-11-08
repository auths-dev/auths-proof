"""Retained evidence controls; no claim about product-security properties."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from report import verify_bundle


class RetainedReportControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ap075-report-control-')
        self.root = Path(self.temporary.name)
        source = Path(__file__).resolve().parents[2] / 'docs/reviews/0075-security-boundary-assessment'
        for name in ['evidence-manifest.json', 'test-plan.json', 'claim-ledger.json', 'case-results.jsonl']:
            shutil.copyfile(source / name, self.root / name)
        shutil.copytree(source / 'evidence', self.root / 'evidence')

    def tearDown(self):
        self.temporary.cleanup()

    def test_intact_report(self):
        self.assertEqual(verify_bundle(self.root)['case_records'], 535)

    def test_missing_or_duplicate_result(self):
        path = self.root / 'case-results.jsonl'
        rows = path.read_text().splitlines()
        for mutated in [rows[1:], rows + rows[:1]]:
            path.write_text('\n'.join(mutated) + '\n')
            with self.assertRaises(ValueError):
                verify_bundle(self.root)

    def test_changed_retained_bytes(self):
        path = self.root / 'evidence/installed-stripe-boundary.json'
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaises(ValueError):
            verify_bundle(self.root)

    def test_missing_family_and_wrong_claim_source(self):
        path = self.root / 'test-plan.json'
        original = path.read_text()
        value = json.loads(original)
        value['cases'].pop()
        path.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            verify_bundle(self.root)
        path.write_text(original)
        path = self.root / 'claim-ledger.json'
        value = json.loads(path.read_text())
        value['target_revision'] = 'unrelated-source'
        path.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            verify_bundle(self.root)


if __name__ == '__main__':
    unittest.main()
