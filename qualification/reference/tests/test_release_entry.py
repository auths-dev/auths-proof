"""Signer boundary tests; no credentials, signatures or provider traffic."""

import copy
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'run'))
import sign_release as release
from common import canonical, Refusal


class Coverage(unittest.TestCase):
    def test_proposal_cannot_change_omit_repeat_or_import_another_phase_case(self):
        corpus = {'cases': [
            {'id': 'offline-source', 'phase': 'offline', 'scenario': 'clean-source', 'capabilities': []},
            {'id': 'commissioning-live', 'phase': 'commissioning', 'scenario': 'declared-capability',
             'capabilities': ['observation', 'budget']},
            {'id': 'live-live', 'phase': 'live', 'scenario': 'declared-capability', 'capabilities': ['observation']}]}
        reports = [dict(id=case['id'], scenario=case['scenario'], capabilities=sorted(case['capabilities']),
                        unauthorized_provider_entries=0) for case in corpus['cases'][:2]]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'evidence').mkdir()
            def save(values):
                (root / 'evidence/00.json').write_bytes(canonical({'cases': values}))
            save(reports)
            release.coverage(root, corpus, 'commissioning')
            changed = copy.deepcopy(reports)
            changed[1]['scenario'] = 'proof-replay'
            changed_caps = copy.deepcopy(reports)
            changed_caps[1]['capabilities'] = []
            entered = copy.deepcopy(reports)
            entered[1]['unauthorized_provider_entries'] = 1
            for values in [reports[:1], reports + reports[:1], changed, changed_caps, entered,
                           reports + [dict(id='live-live', scenario='declared-capability',
                                           capabilities=['observation'], unauthorized_provider_entries=0)]]:
                save(values)
                with self.assertRaises(Refusal): release.coverage(root, corpus, 'commissioning')


class SigningBoundary(unittest.TestCase):
    def test_failed_independent_reconstruction_never_reads_the_key_or_signs(self):
        identity = {'GITHUB_REPOSITORY': 'auths-dev/auths-proof', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                    'GITHUB_REF': 'refs/heads/main', 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1',
                    'GITHUB_SHA': '1' * 40}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = SimpleNamespace(family=['stripe-platform-refund-v1'], stage='commissioning',
                inputs=root / 'inputs', candidate=root / 'candidate', wheel=root / 'sdk.whl',
                typescript=root / 'typescript', proposal=root / 'proposals', out=root / 'out')
            with patch.dict(release.os.environ, identity, clear=True), \
                 patch.object(release.commission, 'call', side_effect=[('1' * 40 + '\n').encode(), b'']) as native, \
                 patch.object(release, 'verify_proposal', side_effect=Refusal('qualification.sign.record-source-binding')), \
                 patch.object(release.commission, 'signing_seed') as seed:
                with self.assertRaises(Refusal): release.sign(args)
                seed.assert_not_called()
                self.assertEqual(native.call_count, 2)
                self.assertFalse(args.out.exists())

    def test_all_families_pass_before_the_key_is_read(self):
        identity = {'GITHUB_REPOSITORY': 'auths-dev/auths-proof', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                    'GITHUB_REF': 'refs/heads/main', 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1',
                    'GITHUB_SHA': '1' * 40}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = SimpleNamespace(family=['airtable-record-update-v1', 'stripe-platform-refund-v1'], stage='live',
                inputs=root / 'inputs', candidate=root / 'candidate', wheel=root / 'sdk.whl',
                typescript=root / 'typescript', proposal=root / 'proposals', out=root / 'out')
            with patch.dict(release.os.environ, identity, clear=True), \
                 patch.object(release.commission, 'call', side_effect=[('1' * 40 + '\n').encode(), b'']), \
                 patch.object(release, 'verify_proposal', side_effect=[(Path('/source/issuer'), {}),
                      Refusal('qualification.sign.corpus-coverage')]) as verify, \
                 patch.object(release.commission, 'signing_seed') as seed:
                with self.assertRaises(Refusal): release.sign(args)
                self.assertEqual(verify.call_count, 2)
                seed.assert_not_called()
                self.assertFalse(args.out.exists())


if __name__ == '__main__':
    unittest.main()
