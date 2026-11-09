#!/usr/bin/env python3
"""Bounded AP075 baseline experiment against the same installed provider double."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import secrets
import sys
import tempfile
import time
from urllib.request import Request, urlopen

from baseline import Baseline, canonical, serve as serve_baseline


def main():
    sys.path.insert(0, '/opt/demo')
    from double import serve
    destination = Path('/evidence')
    rows = []
    for name in ['parameter-substitution', 'duplicate-approver', 'final-capacity-race',
                 'response-loss-replay', 'revocation-before-entry', 'exact-approved-positive']:
        with tempfile.TemporaryDirectory(prefix='ap075-baseline-') as temporary:
            path = Path(temporary)
            ledger = path / 'provider.jsonl'
            credential = 'rk_test_ap075_' + secrets.token_hex(24)
            provider, _, refunds = serve(hashlib.sha256(credential.encode()).hexdigest(), ledger)
            gateway = Baseline(path / 'state.sqlite', 'http://127.0.0.1:'
                               + str(provider.server_address[1]), credential)
            ingress = serve_baseline(gateway)

            def request(route, token, value):
                call = Request('http://127.0.0.1:' + str(ingress.server_address[1]) + route,
                               data=canonical(value), headers={'Authorization': 'Bearer ' + token,
                                                               'Content-Type': 'application/json'})
                with urlopen(call, timeout=20) as response:
                    return json.loads(response.read(16384))

            def submit(value):
                return request('/submit', actor, value)
            actor = gateway.token('agent', 'refund')
            managers = [gateway.token(x, 'approve') for x in ['manager-a', 'manager-b']]
            action = {'operation': name, 'payment_intent': 'pi_demo_09' if name == 'response-loss-replay'
                      else 'pi_demo_00', 'amount': 1000, 'currency': 'usd'}
            for token in managers:
                request('/approve', token, action)
            started = time.monotonic()
            try:
                if name == 'parameter-substitution':
                    value = submit(dict(action, amount=999))
                    assert value['outcome'] == 'denied' and not refunds
                elif name == 'duplicate-approver':
                    action = dict(action, operation='new-operation')
                    request('/approve', managers[0], action)
                    request('/approve', managers[0], action)
                    value = submit(action)
                    assert value['outcome'] == 'denied' and not refunds
                elif name == 'final-capacity-race':
                    second = dict(action, operation='second-operation', payment_intent='pi_demo_01')
                    for token in managers:
                        request('/approve', token, second)
                    with ThreadPoolExecutor(max_workers=8) as pool:
                        replies = list(pool.map(lambda n: submit([action, second][n % 2]), range(16)))
                    assert len(refunds) == 1 and gateway.accounting()['amount'] == 1000
                    value = {'contenders': len(replies), 'outcome': 'one-effect-within-capacity'}
                elif name == 'response-loss-replay':
                    value = submit(action)
                    assert value['outcome'] == 'unknown' and len(refunds) == 1
                    before = ledger.read_bytes()
                    assert submit(action)['outcome'] == 'unknown'
                    assert ledger.read_bytes() == before and gateway.accounting()['amount'] == 1000
                elif name == 'revocation-before-entry':
                    request('/disable', gateway.token('operator', 'admin'), {})
                    value = submit(action)
                    assert value['outcome'] == 'denied' and not refunds
                else:
                    value = submit(action)
                    assert value['outcome'] == 'response-recorded' and len(refunds) == 1
                rows.append({'case': name, 'status': 'pass', 'result': value,
                             'elapsed_seconds': time.monotonic() - started,
                             'applied_effects': len(refunds), 'accounting': gateway.accounting()})
            finally:
                ingress.shutdown()
                ingress.server_close()
                provider.shutdown()
                provider.server_close()
    report = {'schema': 'auths.security-assessment-comparison/1', 'baseline_cases': rows,
              'baseline': 'lab HS256 scoped identity + exact approval records + transactional SQLite + idempotency',
              'is_oauth_deployment': False, 'production_security_assessed': False,
              'no_auths_authorization_code_used': True,
              'not_implemented': ['delegated authority chains/ancestor identity',
                                  'portable public-key authorization/effect evidence',
                                  'multi-host admission', 'native independent recovery proof'],
              'commercial_demand_validated': False,
              'interpretation': 'Basic exact approval, transactional limits and conservative replay are achievable '
                                'with conventional mechanisms; no uniqueness or market advantage follows.'}
    (destination / 'baseline-comparison.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'baseline_cases': len(rows), 'all_passed': True}))


if __name__ == '__main__':
    main()
