from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from employee_read_demo.google_gateway_credential_shim import (
    GatewayReadCredentialDenied, GatewayWriteCredentialDenied,
    install_jules_read_lease, install_jules_write_lease,
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

    def install(self, *, now: int = 1000, companion: bool = False):
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
            companion_recipe_path=(Path("/opt/auths/populate-recipe.json")
                                   if companion else None),
            companion_profile_lock_path=(Path("/opt/auths/populate-profile.lock.json")
                                         if companion else None),
            companion_recipe_digest=("d" * 64 if companion else None),
            now=now,
        )

    def install_read(self, *, now: int = 1000):
        return install_jules_read_lease(
            evidence_path=Path("/private/evidence.json"),
            grant_path=Path("/private/grant.json"),
            write_credential_pins=self.pins(),
            gateway_binary=Path("/opt/auths/bin/auths-gateway"),
            state_dir=Path("/private/gateway"),
            read_recipe_path=Path("/opt/auths/read-recipe.json"),
            read_profile_lock_path=Path("/opt/auths/read-profile.lock.json"),
            read_recipe_digest="d" * 64,
            read_alias="jules-read",
            now=now,
        )

    def test_checked_bearer_reaches_only_gateway_stdin(self) -> None:
        with patch(
            "employee_read_demo.google_gateway_credential_shim.lease_jules_write_token",
            return_value=TokenLease("private-access", 2000),
        ) as lease, patch(
            "employee_read_demo.google_gateway_credential_shim.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, json.dumps({
                "schema": "auths.gateway-install-result/1",
                "connection_id": "conn_AAAAAAAAAAAAAAAAAAAAAA",
                "credential_generation": 1,
                "recipe_digest": "c" * 64,
                "task_companion_digest": None,
                "joined": False,
            }).encode(), b""),
        ) as run:
            installed = self.install()
        self.assertEqual((installed.connection_id, installed.connection_subject,
                          installed.expires_at),
                         ("conn_AAAAAAAAAAAAAAAAAAAAAA", "subject-1", 2000))
        lease.assert_called_once()
        args, kwargs = run.call_args
        command = args[0]
        self.assertEqual(command[command.index("--account-label") + 1], "subject-1")
        self.assertEqual(command[command.index("--provider") + 1], "google")
        self.assertIn("--connection-json", command)
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
        with patch(
            "employee_read_demo.google_gateway_credential_shim.lease_jules_write_token",
            return_value=TokenLease("private-access", 2000),
        ), patch(
            "employee_read_demo.google_gateway_credential_shim.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, b"unexpected", b"private-access"),
        ):
            with self.assertRaisesRegex(GatewayWriteCredentialDenied,
                                        "inspect state before retry") as caught:
                self.install()
            self.assertNotIn("private-access", str(caught.exception))

    def test_companion_recipe_is_pinned_in_install_command_and_result(self) -> None:
        with patch(
            "employee_read_demo.google_gateway_credential_shim.lease_jules_write_token",
            return_value=TokenLease("private-access", 2000),
        ), patch(
            "employee_read_demo.google_gateway_credential_shim.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, json.dumps({
                "schema": "auths.gateway-install-result/1",
                "connection_id": "conn_AAAAAAAAAAAAAAAAAAAAAA",
                "credential_generation": 1,
                "recipe_digest": "c" * 64,
                "task_companion_digest": "d" * 64,
                "joined": False,
            }).encode(), b""),
        ) as run:
            installed = self.install(companion=True)
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--task-companion-approve-digest") + 1],
                         "d" * 64)
        self.assertEqual(command[command.index("--task-companion-recipe") + 1],
                         "/opt/auths/populate-recipe.json")
        self.assertEqual(installed.connection_subject, "subject-1")
        with patch(
            "employee_read_demo.google_gateway_credential_shim.lease_jules_write_token",
            return_value=TokenLease("private-access", 2000),
        ), patch(
            "employee_read_demo.google_gateway_credential_shim.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, json.dumps({
                "schema": "auths.gateway-install-result/1",
                "connection_id": "conn_AAAAAAAAAAAAAAAAAAAAAA",
                "credential_generation": 1,
                "recipe_digest": "c" * 64,
                "task_companion_digest": None,
                "joined": False,
            }).encode(), b""),
        ):
            with self.assertRaisesRegex(GatewayWriteCredentialDenied,
                                        "inspect state before retry"):
                self.install(companion=True)

    def test_incomplete_companion_is_refused_before_credential_lease(self) -> None:
        with patch(
            "employee_read_demo.google_gateway_credential_shim.lease_jules_write_token",
        ) as lease:
            with self.assertRaises(GatewayWriteCredentialDenied):
                install_jules_write_lease(
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
                    companion_recipe_path=Path("/opt/auths/populate-recipe.json"),
                    now=1000,
                )
            lease.assert_not_called()

    def test_checked_read_bearer_uses_a_distinct_connection_and_stdin(self) -> None:
        with patch(
            "employee_read_demo.google_gateway_credential_shim.lease_jules_write_token",
            return_value=TokenLease("private-access", 2000),
        ) as lease, patch(
            "employee_read_demo.google_gateway_credential_shim.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, json.dumps({
                "outcome": "read-connection-installed",
                "connection_id": "conn_BBBBBBBBBBBBBBBBBBBBBB",
                "connection_generation": 1,
                "recipe_digest": "d" * 64,
            }).encode(), b""),
        ) as run:
            installed = self.install_read()
        self.assertEqual((installed.connection_id, installed.connection_subject,
                          installed.recipe_digest, installed.expires_at),
                         ("conn_BBBBBBBBBBBBBBBBBBBBBB", "subject-1", "d" * 64, 2000))
        lease.assert_called_once()
        args, kwargs = run.call_args
        command = args[0]
        self.assertEqual(command[1], "task-read-connect")
        self.assertEqual(command[command.index("--account-subject") + 1], "subject-1")
        self.assertEqual(kwargs["input"], b"private-access")
        self.assertNotIn("private-access", repr(command))
        self.assertNotIn("private-access", repr(installed))

    def test_read_install_failures_keep_bearer_private(self) -> None:
        with patch(
            "employee_read_demo.google_gateway_credential_shim.lease_jules_write_token",
            return_value=TokenLease("private-access", 1600),
        ), patch("employee_read_demo.google_gateway_credential_shim.subprocess.run") as run:
            with self.assertRaises(GatewayReadCredentialDenied):
                self.install_read()
            run.assert_not_called()
        with patch(
            "employee_read_demo.google_gateway_credential_shim.lease_jules_write_token",
            return_value=TokenLease("private-access", 2000),
        ), patch(
            "employee_read_demo.google_gateway_credential_shim.subprocess.run",
            return_value=subprocess.CompletedProcess([], 1, b"private-access", b"private-access"),
        ):
            with self.assertRaises(GatewayReadCredentialDenied) as caught:
                self.install_read()
            self.assertNotIn("private-access", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
