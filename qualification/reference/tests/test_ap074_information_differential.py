"""Synthetic log-parser controls; these do not establish native execution."""

from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ap074_information_differential as differential
from common import Refusal


class NativeEvidenceInventory(unittest.TestCase):
    def test_evidence_requires_each_actual_selector_and_one_pass_without_ignored_tests(self):
        selectors = []
        for adapter in ['file', 'postgres']:
            for module, suffix, _stem, _schema in differential.SUITES.values():
                function = ('native_file_' if adapter == 'file' else 'postgres_native_') + suffix + '_fixture_is_current'
                selectors.append(module + '::' + function)
        records = [f'test {selector} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'
                   for selector in selectors]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic.log'
            path.write_text(''.join(records))
            self.assertEqual(set(differential.native_evidence(path)), {'file', 'postgres'})
            altered = [records[1:], records + [records[0]],
                [records[0].replace('1 passed', '0 passed'), *records[1:]],
                [records[0].replace('0 ignored', '1 ignored'), *records[1:]],
                [records[0].replace('... ok', '... ignored'), *records[1:]]]
            for index, rows in enumerate(altered):
                with self.subTest(alteration=index):
                    path.write_text(''.join(rows))
                    with self.assertRaises(Refusal):
                        differential.native_evidence(path)


if __name__ == '__main__':
    unittest.main()
