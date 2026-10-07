"""Session refusal and cleanup ordering; these tests issue no authority."""

from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import Refusal
import journey_session as session
import production_journey as production


class Session(unittest.TestCase):
    def test_rpc_can_select_a_known_phase_but_no_inputs_or_execution_program(self):
        request = {'schema': session.REQUEST, 'family': 'airtable-record-update-v1', 'command': 'prepare'}
        self.assertEqual(session.checked_command(request, request['family']), 'prepare')
        for changed in [dict(request, command='sign'), dict(request, command='__init__'),
                        dict(request, expected={'outcome': 'observed'}), dict(request, key='synthetic-only'),
                        dict(request, root='/unreviewed'), dict(request, command_line=['unreviewed']),
                        dict(request, family='unreviewed')]:
            with self.assertRaises(Refusal): session.checked_command(changed, request['family'])

    def test_genuine_rotation_preflight_refuses_before_a_provider_can_be_configured(self):
        names = ['STRIPE_QUALIFICATION_RUNTIME_KEY', 'STRIPE_QUALIFICATION_NEXT_RUNTIME_KEY',
                 'STRIPE_QUALIFICATION_SETUP_KEY']
        environment = dict(zip(names, ['rk_test_SYNTHETIC_ONLY_FIRST',
            'rk_test_SYNTHETIC_ONLY_SECOND', 'sk_test_SYNTHETIC_ONLY_SETUP']))
        self.assertEqual(len(production.provider_keys('stripe-platform-refund-v1', environment)), 3)
        for changed in [{}, dict(environment, STRIPE_QUALIFICATION_NEXT_RUNTIME_KEY=environment[names[0]]),
                        dict(environment, STRIPE_QUALIFICATION_RUNTIME_KEY=environment[names[2]]),
                        dict(environment, STRIPE_QUALIFICATION_RUNTIME_KEY='rk_live_SYNTHETIC_ONLY')]:
            with self.assertRaises(Refusal): production.provider_keys('stripe-platform-refund-v1', changed)

    def journey(self, root):
        value = object.__new__(production.Journey)
        value.next_phase, value.failed, value.retired = 0, False, False
        value.work, value.controller = root / 'publication', root / 'control'
        value.work.mkdir()
        value.controller.mkdir()
        (value.work / 'cases').mkdir()
        value.deadline, value.not_after = time.monotonic() + 60, int(time.time()) + 60
        value.check_source = lambda: None
        return value

    def test_failed_setup_invalidates_proposal_and_cannot_advance_or_be_replayed(self):
        with tempfile.TemporaryDirectory() as directory:
            value = self.journey(Path(directory))
            (value.work / 'proposal').mkdir()
            (value.work / 'proposal/record.json').write_bytes(b'synthetic-only-record')
            (value.work / 'canaries').write_bytes(b'synthetic-only-canary')
            calls = []
            def prepare():
                calls.append('actual-source-prepare')
                raise Refusal('qualification.resources.provider-unavailable')
            value.prepare = prepare
            with self.assertRaises(Refusal): value.advance('commission')
            self.assertEqual(calls, [])
            with self.assertRaises(Refusal): value.advance('prepare')
            self.assertTrue(value.failed)
            self.assertFalse((value.work / 'proposal').exists())
            self.assertTrue((value.work / 'canaries').exists(), 'real scan canaries must survive failure cleanup')
            for phase in ['prepare', 'commission', 'live', 'final-proposal']:
                with self.assertRaises(Refusal): value.advance(phase)
            self.assertEqual(calls, ['actual-source-prepare'])

    def test_all_cleanup_is_attempted_with_credential_collection_before_identity_retirement(self):
        with tempfile.TemporaryDirectory() as directory:
            value = self.journey(Path(directory))
            value.stopping, value.worker = threading.Event(), None
            calls = []
            class Deployment:
                installations = [(0, 0), (1, 0), (0, 1), (1, 1)]
                def state(self, host): return Path(directory)
                def close(self): calls.append('stop-gateways')
                def retire_credentials(self):
                    calls.append('collect-credentials')
                    raise Refusal('qualification.production.credential-cleanup-incomplete')
            class Resources:
                def cleanup(self, journal):
                    calls.append('retire-owned-provider-resources')
                    raise Refusal('qualification.resources.provider-unavailable')
            class Author:
                def close(self): calls.append('close-author')
                def abort(self): calls.append('abort-own-author')
            class Isolation:
                def __exit__(self, *_args): calls.append('remove-own-rules')
            class Infrastructure:
                def close(self): calls.append('retire-identity-and-database')
            (Path(directory) / 'installation.json').write_bytes(b'synthetic-only-installation')
            value.journal = value.controller / 'resources.json'
            value.journal.write_bytes(b'synthetic-only-journal')
            value.deployment, value.resources = Deployment(), Resources()
            value.author, value.isolation, value.infrastructure = Author(), Isolation(), Infrastructure()
            with self.assertRaisesRegex(Refusal, 'cleanup-incomplete'): value.cleanup()
            self.assertEqual(calls, ['stop-gateways', 'collect-credentials', 'retire-owned-provider-resources',
                'close-author', 'abort-own-author', 'remove-own-rules', 'retire-identity-and-database'])
            self.assertFalse(value.retired)
            with self.assertRaisesRegex(Refusal, 'cleanup-required'): value.final_proposal()

    def test_partial_install_removes_its_database_before_exact_journal_retirement(self):
        with tempfile.TemporaryDirectory() as directory:
            value = self.journey(Path(directory))
            value.stopping, value.worker = threading.Event(), None
            value.operations = value.resources = value.author = value.isolation = None
            calls = []
            class Deployment:
                installations, processes = [], {}
                def close(self): calls.append('stop-own-gateways')
                def retire_credentials(self): raise AssertionError('partial state cannot claim native collection')
            class Infrastructure:
                container = 'owned-fixture-container'
                def stop_database(self):
                    calls.append('remove-owned-database')
                    self.container = None
                def close(self): calls.append('retire-identity')
            class Faults:
                def __init__(self, deployment): self.deployment = deployment
                def retire_partial(self, infrastructure):
                    if infrastructure.container is not None or self.deployment.processes:
                        raise Refusal('qualification.custody.partial-not-stopped')
                    calls.append('delete-exact-journal-names')
            value.deployment, value.infrastructure = Deployment(), Infrastructure()
            with patch.object(production, 'Faults', Faults): value.cleanup()
            self.assertEqual(calls, ['stop-own-gateways', 'remove-owned-database',
                                    'delete-exact-journal-names', 'retire-identity'])
            self.assertTrue(value.retired)


if __name__ == '__main__':
    unittest.main()
