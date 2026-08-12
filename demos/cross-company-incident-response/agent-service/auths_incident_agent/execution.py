from __future__ import annotations

import base64
import json
import sqlite3
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Literal, Optional

from auths._errors import ProviderOperationError
from auths._application_profile import (
    ApplicationExecutionContext,
    ApplicationOutcome,
    ApplicationReceipt,
    ApplicationReservation,
)
from auths._receipts import AttestedReceipt, verify_receipt
from auths._runtime import RuntimeApplied, RuntimeKernel, TransitionGates

from .domain_profile import EdgeActionInput


class SqliteExecutionStore:
    def __init__(self, path: Path, *, plan_lifetime: int = 600) -> None:
        self._path = path
        self._plan_lifetime = plan_lifetime
        self._kernel = RuntimeKernel()
        self._initialize()

    async def reserve(self, value: ApplicationReservation) -> str:
        connection = self._database()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT * FROM executions WHERE idempotency_key = ?",
                (value.idempotency_key,),
            ).fetchone()
            if current is not None:
                equal = _reservation_equal(current, value)
                connection.rollback()
                return self._kernel.replay(True, equal)
            collision = connection.execute(
                "SELECT 1 FROM executions WHERE command_commitment = ?",
                (value.command_commitment,),
            ).fetchone()
            if collision is not None:
                connection.rollback()
                return "exact-replay"
            if value.plan_commitment is not None:
                plan = connection.execute(
                    "SELECT * FROM plans WHERE commitment = ?",
                    (value.plan_commitment,),
                ).fetchone()
                if plan is None:
                    if value.member_index != 0 or value.member_count is None:
                        connection.rollback()
                        return "out-of-order"
                    connection.execute(
                        "INSERT INTO plans(commitment, member_count, next_member, expires_at) VALUES (?, ?, 0, ?)",
                        (
                            value.plan_commitment,
                            value.member_count,
                            value.observed_at + self._plan_lifetime,
                        ),
                    )
                    plan = connection.execute(
                        "SELECT * FROM plans WHERE commitment = ?",
                        (value.plan_commitment,),
                    ).fetchone()
                if (
                    value.observed_at > plan["expires_at"]
                    or value.member_count != plan["member_count"]
                ):
                    connection.rollback()
                    return "expired"
                if value.member_index != plan["next_member"]:
                    connection.rollback()
                    return "out-of-order"
            state = self._applied(
                None,
                "record-decision",
                TransitionGates(
                    core_authorized=True,
                    policy_eligible=True,
                    configuration_matches=True,
                    not_revoked=True,
                    not_expired=True,
                ),
            )
            state = self._applied(
                state,
                "reserve",
                TransitionGates(
                    configuration_matches=True,
                    not_revoked=True,
                    not_expired=True,
                    capacity_available=True,
                ),
            )
            state = self._applied(
                state,
                "record-execution-intent",
                TransitionGates(
                    configuration_matches=True,
                    not_revoked=True,
                    not_expired=True,
                    execution_intent_present=True,
                ),
            )
            connection.execute(
                """
                INSERT INTO executions(
                  idempotency_key, command_commitment, authority_commitment,
                  context_commitment, plan_commitment, member_index, member_count,
                  state, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    value.idempotency_key,
                    value.command_commitment,
                    value.authority_commitment,
                    value.context_commitment,
                    value.plan_commitment,
                    value.member_index,
                    value.member_count,
                    state,
                    value.observed_at,
                ),
            )
            connection.commit()
            return "reserved"
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    async def authorize_credential(self, idempotency_key: str) -> str:
        return self._transition_flag(idempotency_key, "credential_authorized")

    async def enter_provider(self, idempotency_key: str) -> str:
        connection = self._database()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = _execution(connection, idempotency_key)
            state = self._applied(
                row["state"],
                "start-attempt",
                TransitionGates(
                    configuration_matches=True,
                    not_revoked=True,
                    not_expired=True,
                    execution_intent_present=True,
                    credential_authorized=bool(row["credential_authorized"]),
                ),
            )
            state = self._applied(
                state,
                "mark-provider-call-entered",
                TransitionGates(attempt_present=True),
            )
            connection.execute(
                "UPDATE executions SET state = ?, attempt_present = 1, provider_entered = 1 WHERE idempotency_key = ?",
                (state, idempotency_key),
            )
            connection.commit()
            return "entered"
        except (KeyError, RuntimeError):
            connection.rollback()
            return "conflict"
        finally:
            connection.close()

    async def finish(
        self,
        idempotency_key: str,
        outcome: ApplicationOutcome,
        decision_receipt: AttestedReceipt,
        execution_receipt: Optional[AttestedReceipt],
    ) -> str:
        verify_receipt(decision_receipt)
        if execution_receipt is not None:
            verify_receipt(execution_receipt)
        connection = self._database()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = _execution(connection, idempotency_key)
            state = self._finish_state(row, outcome)
            connection.execute(
                """
                UPDATE executions
                SET state = ?, outcome = ?, decision_receipt = ?, execution_receipt = ?, completed_at = ?
                WHERE idempotency_key = ?
                """,
                (
                    state,
                    outcome,
                    _receipt_json(decision_receipt),
                    None
                    if execution_receipt is None
                    else _receipt_json(execution_receipt),
                    int(time.time()),
                    idempotency_key,
                ),
            )
            if outcome == "succeeded" and row["plan_commitment"] is not None:
                updated = connection.execute(
                    "UPDATE plans SET next_member = next_member + 1 WHERE commitment = ? AND next_member = ?",
                    (row["plan_commitment"], row["member_index"]),
                ).rowcount
                if updated != 1:
                    connection.rollback()
                    return "conflict"
            connection.execute(
                "INSERT INTO timeline(at, company, kind, detail) VALUES (?, ?, ?, ?)",
                (
                    int(time.time()),
                    "auths",
                    "execution",
                    f"{idempotency_key} stored as {state}",
                ),
            )
            connection.commit()
            return "stored"
        except (KeyError, RuntimeError):
            connection.rollback()
            return "conflict"
        finally:
            connection.close()

    def record_credential_acquisition(self, idempotency_key: str) -> None:
        with self._database() as connection:
            connection.execute(
                "UPDATE counters SET value = value + 1 WHERE name = 'credential_acquisitions'"
            )
            connection.execute(
                "INSERT INTO timeline(at, company, kind, detail) VALUES (?, 'auths', 'credential', ?)",
                (int(time.time()), f"credential acquired for {idempotency_key}"),
            )

    def record_provider_call(self, idempotency_key: str) -> None:
        with self._database() as connection:
            connection.execute(
                "UPDATE counters SET value = value + 1 WHERE name = 'provider_calls'"
            )
            connection.execute(
                "INSERT INTO timeline(at, company, kind, detail) VALUES (?, 'auths', 'provider', ?)",
                (int(time.time()), f"provider entered for {idempotency_key}"),
            )

    def snapshot(self) -> dict[str, Any]:
        with self._database() as connection:
            executions = [
                _execution_json(row)
                for row in connection.execute(
                    "SELECT * FROM executions ORDER BY observed_at, idempotency_key"
                )
            ]
            counters = {
                row["name"]: row["value"]
                for row in connection.execute("SELECT * FROM counters")
            }
            timeline = [
                dict(row)
                for row in connection.execute("SELECT * FROM timeline ORDER BY id")
            ]
        return {"executions": executions, "counters": counters, "timeline": timeline}

    def reset(self) -> None:
        with self._database() as connection:
            connection.execute("DELETE FROM executions")
            connection.execute("DELETE FROM plans")
            connection.execute("DELETE FROM timeline")
            connection.execute("UPDATE counters SET value = 0")

    def reconcile(
        self,
        idempotency_key: str,
        conclusion: Literal["effect", "non-effect", "inconclusive"],
    ) -> str:
        operations = {
            "effect": "reconcile-effect",
            "non-effect": "reconcile-non-effect",
            "inconclusive": "reconcile-inconclusive",
        }
        connection = self._database()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = _execution(connection, idempotency_key)
            state = self._applied(
                row["state"],
                operations[conclusion],
                TransitionGates(
                    reconciliation_fresh=True,
                    reconciliation_matches=True,
                ),
            )
            connection.execute(
                "UPDATE executions SET state = ? WHERE idempotency_key = ?",
                (state, idempotency_key),
            )
            connection.execute(
                "INSERT INTO timeline(at, company, kind, detail) VALUES (?, 'auths', 'reconciliation', ?)",
                (int(time.time()), f"{idempotency_key} reconciled as {state}"),
            )
            connection.commit()
            return state
        except (KeyError, RuntimeError):
            connection.rollback()
            return "conflict"
        finally:
            connection.close()

    def _transition_flag(self, idempotency_key: str, field: str) -> str:
        if field != "credential_authorized":
            raise ValueError("unsupported transition flag")
        connection = self._database()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = _execution(connection, idempotency_key)
            state = self._applied(
                row["state"],
                "authorize-credential",
                TransitionGates(
                    configuration_matches=True,
                    not_revoked=True,
                    not_expired=True,
                    execution_intent_present=True,
                    credential_authorized=bool(row[field]),
                ),
            )
            connection.execute(
                f"UPDATE executions SET state = ?, {field} = 1 WHERE idempotency_key = ?",
                (state, idempotency_key),
            )
            connection.commit()
            return "authorized"
        except (KeyError, RuntimeError):
            connection.rollback()
            return "conflict"
        finally:
            connection.close()

    def _finish_state(self, row: sqlite3.Row, outcome: ApplicationOutcome) -> str:
        state = row["state"]
        if outcome == "succeeded":
            return self._applied(
                state,
                "commit",
                TransitionGates(
                    attempt_present=bool(row["attempt_present"]),
                    provider_call_entered=bool(row["provider_entered"]),
                    definite_effect=True,
                ),
            )
        if outcome == "outcome-unknown":
            return self._applied(
                state,
                "mark-outcome-unknown",
                TransitionGates(attempt_present=bool(row["attempt_present"])),
            )
        return self._applied(
            state,
            "release",
            TransitionGates(
                attempt_present=bool(row["attempt_present"]),
                cancellation_allowed=outcome == "cancelled",
                definite_non_effect=outcome == "failed",
            ),
        )

    def _applied(
        self, current: Optional[str], operation: str, gates: TransitionGates
    ) -> str:
        result = self._kernel.transition(current, operation, gates)
        if not isinstance(result, RuntimeApplied):
            raise RuntimeError(result.code)
        return result.state

    def _database(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialize(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._database() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS plans (
                  commitment BLOB PRIMARY KEY,
                  member_count INTEGER NOT NULL,
                  next_member INTEGER NOT NULL,
                  expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS executions (
                  idempotency_key TEXT PRIMARY KEY,
                  command_commitment BLOB NOT NULL UNIQUE,
                  authority_commitment BLOB NOT NULL,
                  context_commitment BLOB NOT NULL,
                  plan_commitment BLOB,
                  member_index INTEGER,
                  member_count INTEGER,
                  state TEXT NOT NULL,
                  credential_authorized INTEGER NOT NULL DEFAULT 0,
                  attempt_present INTEGER NOT NULL DEFAULT 0,
                  provider_entered INTEGER NOT NULL DEFAULT 0,
                  outcome TEXT,
                  decision_receipt TEXT,
                  execution_receipt TEXT,
                  observed_at INTEGER NOT NULL,
                  completed_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS counters (
                  name TEXT PRIMARY KEY,
                  value INTEGER NOT NULL
                );
                INSERT OR IGNORE INTO counters(name, value) VALUES
                  ('credential_acquisitions', 0), ('provider_calls', 0);
                CREATE TABLE IF NOT EXISTS timeline (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  at INTEGER NOT NULL,
                  company TEXT NOT NULL,
                  kind TEXT NOT NULL,
                  detail TEXT NOT NULL
                );
                """
            )


class IncidentCredentials:
    def __init__(
        self,
        store: SqliteExecutionStore,
        *,
        service_token: str,
        certificate_fingerprint: str,
    ) -> None:
        self._store = store
        self._service_token = service_token
        self._certificate_fingerprint = certificate_fingerprint

    async def acquire(
        self, command: EdgeActionInput, context: ApplicationExecutionContext
    ) -> dict[str, str]:
        self._store.record_credential_acquisition(context.idempotency_key)
        if command.device == "firewall-eu-west-2" and self._service_token:
            return {"authorization": f"Bearer {self._service_token}"}
        if command.device == "cache-eu-west-2":
            return {"x-auths-client-cert-sha256": self._certificate_fingerprint}
        raise ProviderOperationError("unsupported")


class IncidentProvider:
    def __init__(
        self,
        store: SqliteExecutionStore,
        *,
        northstar_url: str,
        edgeshield_url: str,
        fault: Literal["none", "unknown-after-firewall"] = "none",
    ) -> None:
        self._store = store
        self._northstar_url = northstar_url.rstrip("/")
        self._edgeshield_url = edgeshield_url.rstrip("/")
        self._fault = fault

    async def execute(
        self,
        command: EdgeActionInput,
        credential: object,
        context: ApplicationExecutionContext,
    ) -> dict[str, Any]:
        if type(credential) is not dict:
            raise ProviderOperationError("rejected")
        self._store.record_provider_call(context.idempotency_key)
        if command == EdgeActionInput(
            "northstar",
            "firewall-eu-west-2",
            "apply-config",
            185,
            "184".zfill(64),
        ):
            result = _provider_post(
                f"{self._northstar_url}/api/firewall/apply",
                {
                    "incidentId": "INC-2026-0811",
                    "region": "eu-west-2",
                    "operation": "apply-config",
                },
                credential,
            )
            if self._fault == "unknown-after-firewall":
                raise RuntimeError("provider response was lost after the effect")
            return result
        if command == EdgeActionInput(
            "northstar",
            "cache-eu-west-2",
            "execute",
            992,
            "991".zfill(64),
        ):
            delivery = _provider_post(
                f"{self._edgeshield_url}/api/iroh/exchange",
                {"envelopeHex": context.canonical_command.hex()},
                {},
            )
            if not delivery.get("delivered"):
                raise ProviderOperationError("unavailable")
            result = _provider_post(
                f"{self._edgeshield_url}/api/cache/purge",
                {
                    "incidentId": "INC-2026-0811",
                    "region": "eu-west-2",
                    "operation": "execute",
                },
                credential,
            )
            return {"transport": delivery, "provider": result}
        raise ProviderOperationError("unsupported")


def canonical_result(value: dict[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def application_receipt_json(value: ApplicationReceipt) -> dict[str, Any]:
    return {
        "idempotencyKey": value.idempotency_key,
        "commandCommitment": value.command_commitment.hex(),
        "authorityCommitment": value.authority_commitment.hex(),
        "contextCommitment": value.context_commitment.hex(),
        "planCommitment": None
        if value.plan_commitment is None
        else value.plan_commitment.hex(),
        "stateClaim": value.state_claim,
        "outcome": value.outcome,
        "observedAt": value.observed_at,
        "decisionReceipt": json.loads(_receipt_json(value.decision_receipt)),
        "executionReceipt": None
        if value.execution_receipt is None
        else json.loads(_receipt_json(value.execution_receipt)),
    }


def _provider_post(
    url: str, payload: dict[str, Any], headers: dict[str, str]
) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(),
        method="POST",
        headers={"content-type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            result = json.loads(response.read())
    except urllib.error.HTTPError as error:
        if error.code < 500:
            raise ProviderOperationError("rejected") from None
        raise ProviderOperationError("unavailable") from None
    except (TimeoutError, urllib.error.URLError):
        raise RuntimeError("provider outcome is unknown") from None
    if type(result) is not dict:
        raise RuntimeError("provider outcome is unknown")
    return result


def _execution(connection: sqlite3.Connection, idempotency_key: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM executions WHERE idempotency_key = ?", (idempotency_key,)
    ).fetchone()
    if row is None:
        raise KeyError(idempotency_key)
    return row


def _reservation_equal(row: sqlite3.Row, value: ApplicationReservation) -> bool:
    return (
        bytes(row["command_commitment"]) == value.command_commitment
        and bytes(row["authority_commitment"]) == value.authority_commitment
        and bytes(row["context_commitment"]) == value.context_commitment
        and _optional_bytes(row["plan_commitment"]) == value.plan_commitment
        and row["member_index"] == value.member_index
        and row["member_count"] == value.member_count
    )


def _optional_bytes(value: object) -> Optional[bytes]:
    return None if value is None else bytes(value)


def _receipt_json(value: AttestedReceipt) -> str:
    return json.dumps(
        {
            "kind": value.kind,
            "receiptId": value.receipt_id.hex(),
            "bytes": base64.b64encode(value.bytes).decode(),
            "signer": {
                "principal": value.signer.principal,
                "verificationMethod": value.signer.verification_method,
                "suite": value.signer.suite,
                "evidence": base64.b64encode(value.signer.evidence).decode(),
            },
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _execution_json(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "idempotencyKey": row["idempotency_key"],
        "commandCommitment": bytes(row["command_commitment"]).hex(),
        "authorityCommitment": bytes(row["authority_commitment"]).hex(),
        "contextCommitment": bytes(row["context_commitment"]).hex(),
        "planCommitment": None
        if row["plan_commitment"] is None
        else bytes(row["plan_commitment"]).hex(),
        "memberIndex": row["member_index"],
        "memberCount": row["member_count"],
        "state": row["state"],
        "outcome": row["outcome"],
        "decisionReceipt": None
        if row["decision_receipt"] is None
        else json.loads(row["decision_receipt"]),
        "executionReceipt": None
        if row["execution_receipt"] is None
        else json.loads(row["execution_receipt"]),
        "observedAt": row["observed_at"],
        "completedAt": row["completed_at"],
    }
