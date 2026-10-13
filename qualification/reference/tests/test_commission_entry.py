"""Signer-source pinning only; fixtures issue no commissioning authority."""

import base64
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'run'))
import commission
from common import Refusal, canonical


class Source(unittest.TestCase):
    def test_contract_is_rederived_from_this_checkout_not_copied_from_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs = Path(temporary)
            family = 'stripe-platform-refund-v1'
            tuple_value = {'recipe_family': family, 'provider_contract_id': '1' * 64}
            (inputs / 'tuple.json').write_bytes(canonical(tuple_value))
            issuer = commission.ROOT / 'target/release/auths-qualification'
            with patch.object(commission, 'call', return_value=('1' * 64 + '\n').encode()) as called:
                self.assertEqual(commission.source_contract(family, inputs, issuer), tuple_value)
                self.assertEqual(called.call_args.args[0], [issuer, 'contract-id', '--contract',
                    commission.ROOT / 'qualification/families' / family / 'contract.json'])
            for changed in [dict(tuple_value, provider_contract_id='2' * 64),
                            dict(tuple_value, recipe_family='airtable-record-update-v1')]:
                (inputs / 'tuple.json').write_bytes(canonical(changed))
                with patch.object(commission, 'call', return_value=('1' * 64 + '\n').encode()):
                    with self.assertRaises(Refusal): commission.source_contract(family, inputs, issuer)
            with self.assertRaises(Refusal): commission.source_contract('../../unreviewed', inputs, issuer)

    def test_seed_parser_has_no_filename_command_or_noncanonical_encoding_input(self):
        synthetic = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b'=').decode()
        self.assertEqual(commission.signing_seed(synthetic), synthetic.encode())
        for value in [None, synthetic + '=', synthetic + '\n', '$(unreviewed)',
                      '/tmp/unreviewed', '!' * 43, synthetic[:-1] + 'v']:
            with self.assertRaises(Refusal): commission.signing_seed(value)


if __name__ == '__main__':
    unittest.main()
