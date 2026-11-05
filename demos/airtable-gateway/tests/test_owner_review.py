"""HTTP authentication/display-correlation tests; no native authority claim.

The installed browser journey separately exercises actual native review/signing.
"""
import copy
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from demo_common import Refusal
from owner_review import OwnerReviewServer, RENDERER, native_review


def packet():
    return {'schema': 'auths.private-effect-signing/2', 'renderer': RENDERER,
            'literal_review': json.dumps({'schema': 'auths.private-effect-review/2',
                'effect_id_hex': '00' * 32, 'binding_canonical': '{}',
                'native': {'body': '<script>untrusted text</script>' + 'x' * 20000 + 'END-OF-REVIEW'},
                'semantic': {}}), 'approval_request': {'schema': 'auths.exact-effect-approval/1',
                    'effect': [0] * 32, 'approver': [0] * 32, 'not_before': 0, 'expires_at': 1},
            'signing_message_hex': '00'}


class OwnerChannel(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        Path(self.directory.name).chmod(0o700)
        self.owner = OwnerReviewServer(self.directory.name, 0)
        self.origin = 'http://127.0.0.1:' + str(self.owner.server.server_address[1])
        self.headers = {}

    def tearDown(self):
        self.owner.stop()
        self.directory.cleanup()

    def call(self, path, value=None, *, headers=None, raw=None):
        body = raw if raw is not None else None if value is None else json.dumps(value).encode()
        selected = dict(self.headers)
        if body is not None:
            selected.update({'Origin': self.origin, 'Content-Type': 'application/json'})
        selected.update(headers or {})
        request = urllib.request.Request(self.origin + path, data=body, headers=selected)
        try:
            response = urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.load(response), response.headers

    def login(self):
        status, result, headers = self.call('/api/login', {'credential': self.owner.credential})
        self.assertEqual(status, 200)
        self.assertIsNone(headers.get('Set-Cookie'), 'cookies would cross localhost ports')
        self.headers = {'Authorization': 'Bearer ' + result['bearer'], 'X-Owner-CSRF': result['csrf']}

    def pending(self):
        failures = []
        def request():
            try:
                self.owner.request(packet())
            except Refusal as error:
                failures.append(str(error))
        thread = threading.Thread(target=request)
        thread.start()
        deadline = time.monotonic() + 3
        while self.owner.pending is None:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(.002)
        return thread, failures

    def test_owner_channel_refuses_unauthenticated_and_cross_origin_decisions(self):
        self.assertEqual(self.call('/api/review')[0], 401)
        self.assertEqual(self.call('/api/login', {'credential': self.owner.credential},
                                  headers={'Origin': 'http://attacker.invalid'})[0], 403)
        self.login()
        self.assertEqual(self.call('/api/review', headers={'Host': 'attacker.invalid'})[0], 403)
        thread, failures = self.pending()
        identifier = self.owner.pending.identifier
        decision = {'review_id': identifier, 'decision': 'approve', 'renderer': RENDERER}
        self.assertEqual(self.call('/api/decision', decision, headers={'Authorization': ''})[0], 403)
        self.assertEqual(self.call('/api/decision', decision, headers={'X-Owner-CSRF': ''})[0], 403)
        self.assertEqual(self.call('/api/decision', decision, headers={'Origin': 'http://attacker.invalid'})[0], 403)
        self.assertEqual(self.call('/api/decision', {**decision, 'review_id': 'substituted'})[0], 409)
        self.assertEqual(self.call('/api/decision', {**decision, 'renderer': 'unsupported'})[0], 409)
        self.assertFalse(self.owner.pending.event.is_set())
        self.assertEqual(self.call('/api/decision', {**decision, 'decision': 'decline'})[0], 200)
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, ['demo.owner-review-declined-or-expired'])

    def test_complete_review_is_unchanged_and_only_its_decision_releases_the_waiter(self):
        self.login()
        thread, failures = self.pending()
        status, value, _ = self.call('/api/review')
        self.assertEqual(status, 200)
        self.assertEqual(value['native'], packet())
        self.assertIn('END-OF-REVIEW', value['native']['literal_review'])
        self.assertTrue(thread.is_alive())
        self.assertEqual(self.call('/api/decision', {'review_id': value['review_id'],
            'decision': 'approve', 'renderer': RENDERER})[0], 200)
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(self.call('/api/decision', {'review_id': value['review_id'],
            'decision': 'approve', 'renderer': RENDERER})[0], 409)

    def test_expired_replaced_and_cookie_only_sessions_cannot_read_private_reviews(self):
        self.login()
        original = dict(self.headers)
        self.login()
        self.assertEqual(self.call('/api/review', headers=original)[0], 401)
        self.assertEqual(self.call('/api/review', headers={'Authorization': '',
            'Cookie': 'auths_owner=' + self.headers['Authorization'][7:]})[0], 401)
        with self.owner.lock:
            self.owner.session['until'] = time.monotonic() - 1
        self.assertEqual(self.call('/api/review')[0], 401)

    def test_malformed_duplicate_and_oversized_commands_are_refused(self):
        self.login()
        for raw in [b'{"decision":"approve","decision":"decline"}', b'[]', b'x' * 1025]:
            self.assertEqual(self.call('/api/decision', raw=raw)[0], 400)
        self.assertIsNone(self.owner.pending)

    def test_unsupported_truncated_and_mismatched_review_cannot_be_presented(self):
        for change in [lambda p: p.update(renderer='unsupported'),
                       lambda p: p.update(literal_review=p['literal_review'][:-1]),
                       lambda p: p['approval_request'].update(effect=[1] * 32),
                       lambda p: p['approval_request'].pop('expires_at'),
                       lambda p: p.update(literal_review='x' * 131073)]:
            value = copy.deepcopy(packet())
            change(value)
            with self.assertRaises(Refusal):
                native_review(value)


if __name__ == '__main__':
    unittest.main()
