from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from importlib.resources import files
from jsonschema import Draft202012Validator

from employee_read_demo.demo_co_contract import ContractRejected
from employee_read_demo.edit_rerun_handoff import (
    EditRerunPins, OPTION_A, OPTION_B, validate_edit_rerun,
    validate_edit_rerun_observation,
)
from employee_read_demo.write_handoff import WriteHandoffPins


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class EditRerunHandoffTests(unittest.TestCase):
    def test_complete_before_and_both_after_states_are_precommitted(self) -> None:
        now = int(datetime(2026, 10, 25, 20, 13, tzinfo=timezone.utc).timestamp())
        marker = 'AP071-RERUN-' + '1' * 24
        raw_before = b'\xef\xbb\xbf' + marker.encode()
        raw_a = b'\xef\xbb\xbf' + OPTION_A.encode()
        raw_b = b'\xef\xbb\xbf' + OPTION_B.encode()
        producer = WriteHandoffPins('atlas-studio', 'live-test-atlas', 'a' * 64,
                                    'customer-1', 'jules-subject',
                                    'jules@example.test', 'b' * 64)
        source = {'folder_id': 'project-a-folder', 'drive_id': 'drive-1',
                  'document_id': 'old-working-doc'}
        baseline = {
            'schema_version': 'demo-co/google-edit-rerun-baseline/v1',
            'status': 'ready', 'attribution': 'provider_state_only',
            'company': producer.company, 'instance': producer.instance,
            'definition_hash': producer.definition_hash,
            'customer_id': producer.customer_id,
            'jules_subject': producer.jules_subject,
            'observed_at': '2026-10-25T20:10:27Z',
            'source_write_verification_sha256': producer.evidence_sha256,
            'source_working_observation_sha256': 'c' * 64,
            'source_v2_baseline_sha256': 'd' * 64,
            'source_v2_final_sha256': 'e' * 64,
            'folder_id': source['folder_id'], 'drive_id': source['drive_id'],
            'document_id': 'new-rerun-doc',
            'document_title': 'Demo Co AP-071 Project A Clean Edit Rerun',
            'tab_id': 't.0', 'jules_revision_id': 'revision-1',
            'marker': marker, 'baseline_exactly_one_marker': True,
            'baseline_raw_sha256': digest(raw_before),
            'baseline_raw_byte_count': len(raw_before),
            'approved_option_a_sha256': digest(OPTION_A.encode()),
            'approved_option_a_byte_count': len(OPTION_A.encode()),
            'expected_after_raw_sha256': digest(raw_a),
            'expected_after_raw_byte_count': len(raw_a),
            'expected_after_rule': 'replace_single_marker_in_exact_raw_export/v1',
            'jules_can_edit': True, 'direct_child_count': 5,
            'canonical_project_a_unchanged': True,
            'canonical_project_b_unchanged': True,
            'jules_probe_unchanged': True,
            'preserved_child_unchanged': True,
            'second_child_unchanged': True,
            'working_document_unchanged': True,
        }
        choices = {
            'schema_version': 'demo-co/google-edit-rerun-choices/v1',
            'status': 'ready',
            'attribution': 'precommitted_provider_expectation',
            'company': producer.company, 'instance': producer.instance,
            'definition_hash': producer.definition_hash,
            'observed_at': '2026-10-25T20:12:01Z',
            'baseline_generation': 13,
            'baseline_raw_sha256': digest(raw_before),
            'baseline_raw_byte_count': len(raw_before),
            'document_id': baseline['document_id'], 'marker': marker,
            'direct_child_count': 5,
            'replacement_rule': baseline['expected_after_rule'],
        }
        for letter, replacement, raw in (('a', OPTION_A, raw_a),
                                         ('b', OPTION_B, raw_b)):
            choices[f'option_{letter}_text_byte_count'] = len(replacement.encode())
            choices[f'option_{letter}_text_sha256'] = digest(replacement.encode())
            choices[f'option_{letter}_expected_raw_byte_count'] = len(raw)
            choices[f'option_{letter}_expected_raw_sha256'] = digest(raw)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before_dir = root / 'generation-0013'
            choices_dir = root / 'generation-0014'
            before_dir.mkdir(mode=0o700)
            choices_dir.mkdir(mode=0o700)
            before_path = before_dir / 'google-edit-rerun-baseline.json'
            choices_path = choices_dir / 'google-edit-rerun-choices.json'

            def save(path: Path, value: dict) -> str:
                path.write_text(json.dumps(value, sort_keys=True))
                os.chmod(path, 0o600)
                return digest(path.read_bytes())

            baseline_sha = save(before_path, baseline)
            schema = json.loads(files('employee_read_demo').joinpath(
                'schemas', 'google-edit-rerun-baseline-v1.schema.json').read_text())
            self.assertEqual([str(error) for error in
                              Draft202012Validator(schema).iter_errors(baseline)], [])
            choices['baseline_sha256'] = baseline_sha
            choices_sha = save(choices_path, choices)
            pins = EditRerunPins(producer, 'c' * 64, baseline_sha, choices_sha)
            target = validate_edit_rerun(before_path, choices_path, pins,
                                         source_evidence=source, now=now)
            self.assertEqual(target.document_id, 'new-rerun-doc')
            self.assertEqual([choice['replacement'] for choice in
                              target.allowed_arguments()], [OPTION_A, OPTION_B])
            choices['option_b_expected_raw_sha256'] = 'f' * 64
            save(choices_path, choices)
            with self.assertRaisesRegex(ContractRejected, 'digest'):
                validate_edit_rerun(before_path, choices_path, pins,
                                    source_evidence=source, now=now)
            tampered_pins = EditRerunPins(
                producer, 'c' * 64, baseline_sha, digest(choices_path.read_bytes()))
            with self.assertRaisesRegex(ContractRejected, 'choice commitment'):
                validate_edit_rerun(before_path, choices_path, tampered_pins,
                                    source_evidence=source, now=now)

            choices['option_b_expected_raw_sha256'] = digest(raw_b)
            self.assertEqual(save(choices_path, choices), choices_sha)
            observation_dir = root / 'generation-0015'
            observation_dir.mkdir(mode=0o700)
            observation_path = observation_dir / 'google-edit-rerun-observation.json'
            observation = {
                'schema_version': 'demo-co/google-edit-rerun-observation/v1',
                'status': 'ready', 'attribution': 'provider_state_only',
                'company': producer.company, 'instance': producer.instance,
                'definition_hash': producer.definition_hash,
                'observed_at': '2026-10-25T20:13:00Z',
                'baseline_generation': 13, 'baseline_sha256': baseline_sha,
                'choices_generation': 14, 'choices_sha256': choices_sha,
                'selected_choice': 'A', 'document_id': target.document_id,
                'admin_tab_id': target.tab_id,
                'admin_revision_id': 'admin-revision-after',
                'observed_raw_sha256': digest(raw_a),
                'observed_raw_byte_count': len(raw_a),
                'expected_raw_sha256': digest(raw_a),
                'expected_raw_byte_count': len(raw_a),
                'exact_expected_content': True, 'original_marker_count': 0,
                'direct_child_count': 5,
                'canonical_project_a_unchanged': True,
                'canonical_project_b_unchanged': True,
                'jules_probe_unchanged': True,
                'preserved_child_unchanged': True,
                'second_child_unchanged': True,
                'working_document_unchanged': True,
            }
            observation_sha = save(observation_path, observation)
            accepted = validate_edit_rerun_observation(
                observation_path, observation_sha256=observation_sha,
                baseline_path=before_path, choices_path=choices_path,
                pins=pins, target=target, selected_choice='A',
                task_not_before=now - 60, now=now,
            )
            self.assertEqual(accepted.raw_sha256, digest(raw_a))
            with self.assertRaisesRegex(ContractRejected, 'target or identity'):
                validate_edit_rerun_observation(
                    observation_path, observation_sha256=observation_sha,
                    baseline_path=before_path, choices_path=choices_path,
                    pins=pins, target=target, selected_choice='B',
                    task_not_before=now - 60, now=now,
                )
            observation['observed_raw_sha256'] = digest(raw_b)
            bad_sha = save(observation_path, observation)
            with self.assertRaisesRegex(ContractRejected, 'complete after-state'):
                validate_edit_rerun_observation(
                    observation_path, observation_sha256=bad_sha,
                    baseline_path=before_path, choices_path=choices_path,
                    pins=pins, target=target, selected_choice='A',
                    task_not_before=now - 60, now=now,
                )
            observation['observed_raw_sha256'] = digest(raw_a)
            observation['working_document_unchanged'] = False
            bad_sha = save(observation_path, observation)
            with self.assertRaisesRegex(ContractRejected, 'schema'):
                validate_edit_rerun_observation(
                    observation_path, observation_sha256=bad_sha,
                    baseline_path=before_path, choices_path=choices_path,
                    pins=pins, target=target, selected_choice='A',
                    task_not_before=now - 60, now=now,
                )


if __name__ == '__main__':
    unittest.main()
