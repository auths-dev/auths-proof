"""Regression for actual hosted owner-journey counter initialization failure."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from double import Fixture


class ProviderLedger(unittest.TestCase):
    def test_owned_counter_log_exists_before_any_provider_request(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / 'provider.jsonl'
            fixture = Fixture(ledger, 'public-fixture-control')
            self.assertEqual(ledger.read_bytes(), b'')
            self.assertEqual(ledger.stat().st_mode & 0o777, 0o600)
            fixture.append({'kind': 'read', 'status': 200})
            retained = ledger.read_bytes()
            self.assertTrue(retained.endswith(b'\n'))
            with self.assertRaises(FileExistsError):
                Fixture(ledger, 'public-fixture-control')
            self.assertEqual(ledger.read_bytes(), retained, 'startup overwrote counter evidence')


if __name__ == '__main__':
    unittest.main()
