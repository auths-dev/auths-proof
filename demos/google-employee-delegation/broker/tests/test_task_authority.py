from __future__ import annotations

import time
import unittest

from auths import _native

from employee_read_demo.task_authority import plan_agent_grant
from test_admission import task


class TaskAuthorityTests(unittest.TestCase):
    def test_native_child_plan_commits_all_approved_read_bodies(self) -> None:
        now = int(time.time())
        root_key = _native.DevelopmentEd25519Key.generate()
        employee_key = _native.DevelopmentEd25519Key.generate()
        agent_key = _native.DevelopmentEd25519Key.generate()
        baseline = task(now)
        descriptor = type(baseline)(**{**baseline.__dict__,
                                       "employee_principal": employee_key.principal,
                                       "agent_principal": agent_key.principal})
        root = _native.Principal(root_key.principal)
        employee = _native.Principal(descriptor.employee_principal)
        audience = f"mcp://{descriptor.service}"
        resource = f"{audience}/tools/google_drive_document_read"
        request = _native.GrantRequest(
            employee, "auths.mcp", 2, [("tools/call", resource)],
            descriptor.not_before - 1, descriptor.expires_at + 1,
            [audience], None, None, 1, None, "raw-key-baseline", [],
        )
        unsigned = _native.root_grant(root, request)
        signing = _native.prepare_signing(
            unsigned, root_key.principal_method,
            root_key.verification_method, root_key.suite,
        )
        parent = signing.complete(root_key.sign(signing.signing_preimage))
        plan = plan_agent_grant(descriptor, _native.inspect_signed(parent),
                                assurance_floor="raw-key-baseline")
        self.assertTrue(plan.diff.action_narrowed)
        self.assertEqual(plan.diff.delegation_depth, (1, 0))


if __name__ == "__main__":
    unittest.main()
