"""Rule rollback and actual-witness boundaries, without network or authority."""

from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import Refusal
import network_fault as network


class Network(unittest.TestCase):
    def rules(self):
        value = object.__new__(network.Rules)
        value.removals = []
        return value

    def test_only_own_rules_are_removed_in_reverse_order_even_if_one_removal_fails(self):
        rules, calls = self.rules(), []
        def command(executable, table, arguments):
            calls.append((executable, table, arguments))
        with patch.object(rules, 'command', command):
            rules.add('iptables', 'nat', ['-A', 'OUTPUT', '-d', '192.0.2.1', '-j', 'REDIRECT'])
            rules.add('ip6tables', 'filter', ['-A', 'OUTPUT', '-d', '2001:db8::1', '-j', 'REJECT'])
            rules.__exit__(None, None, None)
        self.assertEqual([item[2][0] for item in calls], ['-A', '-A', '-D', '-D'])
        self.assertEqual(calls[2][0], 'ip6tables')
        self.assertEqual(calls[3][0], 'iptables')
        self.assertFalse(rules.removals)
        rules.removals = [('iptables', 'nat', ['-D', 'first']), ('ip6tables', 'filter', ['-D', 'second'])]
        calls.clear()
        def fail(executable, table, arguments):
            command(executable, table, arguments)
            raise Refusal('qualification.network.rule-refused')
        with patch.object(rules, 'command', fail), self.assertRaisesRegex(Refusal, 'cleanup-refused'):
            rules.__exit__(None, None, None)
        self.assertEqual(len(calls), 2)
        self.assertFalse(rules.removals)

    def test_pending_native_scope_and_monotonicity_are_required_to_arm_a_fault(self):
        before = {'schema': 'auths.gateway-execution-witness/1', 'scope': '1' * 32,
            'credential_lease_calls': 0, 'write_transport_entries': 0, 'read_transport_entries': 0}
        class Deployment:
            current = before
            def witness(self, host, context): return self.current
        deployment = Deployment()
        witness = network.NativeWitness(deployment, 0, 0)
        self.assertFalse(witness.entered())
        deployment.current = dict(before, credential_lease_calls=1, write_transport_entries=1)
        self.assertTrue(witness.entered())
        for changed in [dict(deployment.current, scope='2' * 32),
                        dict(deployment.current, write_transport_entries=2), before]:
            deployment.current = changed
            with self.assertRaises(Refusal): witness.entered()

    def test_visibility_fault_waits_for_the_observation_lease(self):
        before = {'schema': 'auths.gateway-execution-witness/1', 'scope': '1' * 32,
            'credential_lease_calls': 0, 'write_transport_entries': 0, 'read_transport_entries': 0}
        class Deployment:
            current = before
            def witness(self, host, context): return self.current
        deployment = Deployment()
        witness = network.NativeWitness(deployment, 0, 0, observation=True)
        deployment.current = dict(before, credential_lease_calls=1, write_transport_entries=1)
        self.assertFalse(witness.entered(), 'losing the write response is a different scenario')
        deployment.current = dict(deployment.current, credential_lease_calls=2, read_transport_entries=1)
        self.assertTrue(witness.entered())


if __name__ == '__main__':
    unittest.main()
