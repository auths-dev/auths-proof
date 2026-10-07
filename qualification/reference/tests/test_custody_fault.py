"""Bounded custody fixture obligations; no AWS or provider calls."""

from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import custody_fault as custody
from common import Refusal
from expand import decode

CONNECTION = 'conn_AAAAAAAAAAAAAAAAAAAAAA'
FIRST = b'qualification-fixture-first-credential'
SECOND = b'qualification-fixture-second-credential'


class Reference(unittest.TestCase):
    def test_every_coordinate_is_bound_and_noncanonical_connection_is_refused(self):
        first = custody.reference('test-namespace', CONNECTION, 1, FIRST)
        self.assertTrue(first[0].startswith('auths-gateway/'))
        self.assertEqual([len(value) for value in first], [78, 64, 64])
        self.assertNotEqual(first, custody.reference('other-namespace', CONNECTION, 1, FIRST))
        self.assertNotEqual(first, custody.reference('test-namespace', CONNECTION, 2, FIRST))
        changed = custody.reference('test-namespace', CONNECTION, 1, SECOND)
        self.assertEqual(first[0], changed[0])
        self.assertNotEqual(first[1:], changed[1:])
        for connection in [CONNECTION + '=', CONNECTION[:-1] + 'B', '../../secret', 'conn_' + 'a' * 32]:
            with self.assertRaises(Refusal): custody.reference('test-namespace', connection, 1, FIRST)
        for generation in [True, 0, -1, 1 << 64]:
            with self.assertRaises(Refusal): custody.reference('test-namespace', CONNECTION, generation, FIRST)


class Restoration(unittest.TestCase):
    def fixture(self, root):
        value = object.__new__(custody.Faults)
        value.root, value.generation = root, 0
        value.deployment = SimpleNamespace(canaries=[FIRST, SECOND], namespace='test-namespace')
        value.current = lambda credential: (CONNECTION, 1, *custody.reference('test-namespace', CONNECTION, 1, credential))
        return value

    def test_wrong_bytes_use_the_original_version_then_always_restore_exact_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            value = self.fixture(Path(temporary))
            events = []
            value.delete = lambda name: events.append(('delete', name))
            value.create = lambda name, version, payload: events.append(('create', name, version, payload.read_bytes()))
            with self.assertRaisesRegex(Refusal, 'qualification.fixture.submission-failed'):
                with value.drift('commitment', FIRST, SECOND):
                    events.append(('submit',))
                    raise Refusal('qualification.fixture.submission-failed')
            self.assertEqual([event[0] for event in events], ['delete', 'create', 'submit', 'delete', 'create'])
            self.assertEqual(events[1][1:3], events[4][1:3])
            self.assertNotEqual(events[1][3], FIRST)
            self.assertEqual(events[4][3], FIRST)
            self.assertFalse((value.root / '1/original').exists())
            self.assertTrue(decode((value.root / '1/obligation.json').read_bytes())['restored'])

    def test_same_bytes_use_a_distinct_real_version_and_original_version_is_restored(self):
        with tempfile.TemporaryDirectory() as temporary:
            value = self.fixture(Path(temporary))
            events = []
            value.delete = lambda name: None
            value.create = lambda name, version, payload: events.append((name, version, payload.read_bytes()))
            with value.drift('version', FIRST, SECOND): pass
            self.assertEqual(events[0][0], events[1][0])
            self.assertNotEqual(events[0][1], events[1][1])
            self.assertEqual(events[0][2], events[1][2])

    def test_ambiguous_delete_still_requires_restoration_and_failure_keeps_obligation(self):
        with tempfile.TemporaryDirectory() as temporary:
            value = self.fixture(Path(temporary))
            with patch.object(value, 'delete', side_effect=[Refusal('qualification.custody.aws-refused'), None]), \
                 patch.object(value, 'create', side_effect=Refusal('qualification.custody.restore-required')):
                with self.assertRaisesRegex(Refusal, 'restore-required'):
                    with value.drift('commitment', FIRST, SECOND): self.fail('delete was refused')
            self.assertEqual((value.root / '1/original').read_bytes(), FIRST)
            self.assertFalse(decode((value.root / '1/obligation.json').read_bytes())['restored'])

    def test_absent_exact_owned_name_is_idempotent_but_other_failures_are_not(self):
        value = object.__new__(custody.Faults)
        with patch.object(value, 'api', return_value={'missing': True}): value.delete('owned-fixture-name')
        for response in [None, {'Name': 'another-fixture-name'}]:
            with patch.object(value, 'api', return_value=response):
                with self.assertRaises(Refusal): value.delete('owned-fixture-name')


if __name__ == '__main__':
    unittest.main()
