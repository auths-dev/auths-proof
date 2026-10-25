from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from employee_read_demo.google_gateway_credential_shim import (
    GatewayWriteCredentialDenied, install_jules_write_lease,
)
from employee_read_demo.google_write_credential import WriteCredentialPins
from employee_read_demo.token_store import TokenLease
from employee_read_demo.write_handoff import WriteHandoffPins


class GoogleGatewayCredentialShimTests(unittest.TestCase):
    def pins(self) -> WriteCredentialPins:
        return WriteCredentialPins(
            producer=WriteHandoffPins(
                company="atlas-studio", instance="run-1", definition_hash="a" * 64,
                customer_id="customer-1", jules_subject="subject-1",
                jules_email="jules@example.test", evidence_sha256="b" * 64,
            ),
            client_id="desktop-client-1", primary_domain="example.test",
            connection_id="jules-write-1", connection_generation=1,
        )

    def install(self, *, now: int = 1000):
        return install_jules_write_lease(
            evidence_path=Path("/private/evidence.json"),
            grant_path=Path("/private/grant.json"),
            pins=self.pins(),
            gateway_binary=Path("/opt/auths/bin/auths-gateway"),
            state_dir=Path("/private/gateway"),
            recipe_path=Path("/opt/auths/recipe.json"),
            profile_lock_path=Path("/opt/auths/profile.lock.json"),
            trusted_context_path=Path("/private/trust.cbor"),
            recipe_digest="c" * 64,
            alias="jules-write",
            now=now,
        )

    def test_checked_bearer_reaches_only_gateway_stdin(self) -> None:
        with patch(
            "employee_read_demo.google_gateway_credential_shim.lease_jules_write_token",
            return_value=TokenLease("private-access", 2000),
        ) as lease, patch(
            "employee_read_demo.google_gateway_credential_shim.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, b"installed", b""),
        ) as run:
            installed = self.install()
        self.assertEqual((installed.connection_subject, installed.expires_at),
                         ("subject-1", 2000))
        lease.assert_called_once()
        args, kwargs = run.call_args
        command = args[0]
        self.assertEqual(command[command.index("--account-label") + 1], "subject-1")
        self.assertEqual(command[command.index("--provider") + 1], "google")
        self.assertEqual(kwargs["input"], b"private-access")
        self.assertNotIn("private-access", repr(command))
        self.assertNotIn("private-access", repr(installed))

    def test_short_lease_and_child_failure_do_not_expose_secret(self) -> None:
        with patch(
            "employee_read_demo.google_gateway_credential_shim.lease_jules_write_token",
            return_value=TokenLease("private-access", 1600),
        ), patch("employee_read_demo.google_gateway_credential_shim.subprocess.run") as run:
            with self.assertRaises(GatewayWriteCredentialDenied):
                self.install()
            run.assert_not_called()
        with patch(
            "employee_read_demo.google_gateway_credential_shim.lease_jules_write_token",
            return_value=TokenLease("private-access", 2000),
        ), patch(
            "employee_read_demo.google_gateway_credential_shim.subprocess.run",
            return_value=subprocess.CompletedProcess([], 1, b"private-access", b"private-access"),
        ):
            with self.assertRaises(GatewayWriteCredentialDenied) as caught:
                self.install()
            self.assertNotIn("private-access", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
