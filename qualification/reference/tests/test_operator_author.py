"""Installation binding checks; no provider access or qualification issued."""

import base64
import copy
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from author_operator import checked_statement, SCHEMA
from common import canonical, Refusal


class Operator(unittest.TestCase):
    def setUp(self):
        self.key = SimpleNamespace(principal='raw:synthetic-only-operator',
            principal_method='raw-key-v1', verification_method='synthetic-only-method', suite='ed25519-v1')
        self.installation = {'recipe_digest': '1' * 64, 'profile_lock_sha256': '2' * 64,
            'trusted_context_sha256': '3' * 64, 'provider': 'stripe',
            'alias': 'recipe-qualification', 'deployment': 'production'}
        self.statement = {'schema': SCHEMA, 'operator_principal': self.key.principal,
            'principal_method': self.key.principal_method, 'verification_method': self.key.verification_method,
            'signature_suite': self.key.suite, 'installation': self.installation, 'issued_at': int(time.time())}

    def request(self, statement):
        return {'statement': statement, 'preimage_b64': base64.urlsafe_b64encode(
            SCHEMA.encode() + b'\0' + canonical(statement)).rstrip(b'=').decode()}

    def test_every_installation_field_is_bound_even_when_preimage_is_consistent(self):
        checked_statement(self.request(self.statement), self.key, self.installation)
        for field in self.installation:
            statement = copy.deepcopy(self.statement)
            statement['installation'][field] = 'changed'
            with self.subTest(field=field), self.assertRaisesRegex(Refusal, 'statement-binding'):
                checked_statement(self.request(statement), self.key, self.installation)

    def test_unknown_fields_other_keys_stale_time_and_preimage_substitution_refuse(self):
        for change in ['unknown', 'principal', 'future', 'stale', 'preimage']:
            request = self.request(copy.deepcopy(self.statement))
            if change == 'unknown': request['statement']['authority'] = 'unreviewed'
            if change == 'principal': request['statement']['operator_principal'] = 'raw:other'
            if change == 'future': request['statement']['issued_at'] += 300
            if change == 'stale': request['statement']['issued_at'] -= 300
            if change == 'preimage': request['preimage_b64'] = 'c3Vic3RpdHV0ZWQ'
            with self.subTest(change=change), self.assertRaises(Refusal):
                checked_statement(request, self.key, self.installation)


if __name__ == '__main__':
    unittest.main()
