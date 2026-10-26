"""A signed browser task remains identifiable after uncertain activation."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import Mock

from employee_read_demo.app import _activate_signed_write_task
from employee_read_demo.operator_authority import OperatorDenied


class WriteActivationResponseTests(unittest.TestCase):
    def test_unconfigured_gateway_keeps_signed_task_pending(self) -> None:
        self.assertEqual(_activate_signed_write_task("task-1", None),
                         "approved_pending_gateway_activation")
        flow = Mock(gateway_state_dir=None)
        self.assertEqual(_activate_signed_write_task("task-1", flow),
                         "approved_pending_gateway_activation")
        flow.activate.assert_not_called()

    def test_success_reports_activation(self) -> None:
        flow = Mock(gateway_state_dir=Path("/private/tmp/gateway"))
        self.assertEqual(_activate_signed_write_task("task-1", flow),
                         "activated_awaiting_agent_proposal")
        flow.activate.assert_called_once_with("task-1")

    def test_uncertain_result_does_not_repeat_signed_task(self) -> None:
        flow = Mock(gateway_state_dir=Path("/private/tmp/gateway"))
        flow.activate.side_effect = OperatorDenied("activation outcome unknown")
        self.assertEqual(_activate_signed_write_task("task-1", flow),
                         "signed_activation_unconfirmed")
        flow.activate.assert_called_once_with("task-1")


if __name__ == "__main__":
    unittest.main()
