"""Owner-side review of a separately signed agent write before human confirmation.

The agent proof/action are staged as owner-private files under an approved task.
The installed gateway binary verifies them and compiles the closed request; no
browser-supplied request or review JSON is accepted. This module never submits
to the provider or opens a credential.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .agent_registry import AgentBinding
from .demo_co_contract import _unique_pairs
from .enrollment import EmployeeBinding
from .operator_authority import OperatorDenied
from .operator_cli import _private_read, _private_write
from .task_write_card import build_exact_write_card
from .task_write_intent import ReviewedWrite, project_exact_write
from .task_write_operator_cli import _reviewed_profile
from .task_write_package import load_task_write_package
from .task_write_proofs import PreparedHumanAction, prepare_exact_confirmation, task_commitment


_TASK_ID = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class PreparedConfirmation:
    nonce: str
    task_id: str
    card: dict
    intent: dict
    review: ReviewedWrite
    signing_preimage: bytes
    expires_at: int


@dataclass(frozen=True)
class _Pending:
    employee: EmployeeBinding
    agent: AgentBinding
    task_id: str
    intent: dict
    review: ReviewedWrite
    action: PreparedHumanAction


class TaskWriteConfirmationFlow:
    def __init__(self, *, authority_path: Path, installation_path: Path,
                 recipe_path: Path, profile_lock_path: Path,
                 read_recipe_path: Path | None = None,
                 read_profile_lock_path: Path | None = None,
                 private_output_dir: Path, gateway_binary: Path,
                 gateway_sha256: str,
                 preflight: Callable[[dict, ReviewedWrite], None] | None = None,
                 gateway_state_dir: Path | None = None) -> None:
        if (private_output_dir.is_symlink() or not private_output_dir.is_dir()
                or private_output_dir.stat().st_mode & 0o077
                or type(gateway_sha256) is not str
                or _HEX64.fullmatch(gateway_sha256) is None):
            raise OperatorDenied("confirmation installation is unavailable")
        self.authority_path = authority_path
        self.installation_path = installation_path
        self.recipe_path = recipe_path
        self.profile_lock_path = profile_lock_path
        self.read_recipe_path = read_recipe_path
        self.read_profile_lock_path = read_profile_lock_path
        self.private_output_dir = private_output_dir
        self.gateway_binary = gateway_binary
        self.gateway_sha256 = gateway_sha256
        self.preflight = preflight
        if gateway_state_dir is not None and not gateway_state_dir.is_absolute():
            raise OperatorDenied("gateway state directory must be absolute")
        self.gateway_state_dir = gateway_state_dir
        self._pending: dict[str, _Pending] = {}
        self._lock = threading.Lock()

    def _binary(self) -> Path:
        path = self.gateway_binary
        if (not path.is_absolute() or path.is_symlink() or not path.is_file()
                or not path.stat().st_mode & stat.S_IXUSR):
            raise OperatorDenied("reviewed gateway binary is unavailable")
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != self.gateway_sha256:
            raise OperatorDenied("reviewed gateway binary changed")
        return path

    def _task_dir(self, task_id: str) -> Path:
        if type(task_id) is not str or _TASK_ID.fullmatch(task_id) is None:
            raise OperatorDenied("write task ID is invalid")
        directory = self.private_output_dir / task_id
        if (directory.is_symlink() or not directory.is_dir()
                or directory.stat().st_mode & 0o077):
            raise OperatorDenied("private write task is unavailable")
        return directory

    def _review(self, task_id: str, employee: EmployeeBinding,
                agent: AgentBinding, now: int) -> tuple[dict, ReviewedWrite]:
        directory = self._task_dir(task_id)
        package = load_task_write_package(self.authority_path, now=now)
        try:
            card = json.loads(_private_read(directory / "task-card.json", 16_384),
                              object_pairs_hook=_unique_pairs)
            public = json.loads(_private_read(directory / "agent-package.json", 262_144),
                                object_pairs_hook=_unique_pairs)
            recipe = json.loads(self.recipe_path.read_bytes(), object_pairs_hook=_unique_pairs)
            proof = _private_read(directory / "agent.proof", 4 * 1024 * 1024)
            action = _private_read(directory / "agent.action", 64 * 1024)
            trust = _private_read(directory / "trusted-context.cbor", 262_144)
        except (OSError, PermissionError, ValueError, UnicodeDecodeError) as error:
            raise OperatorDenied("staged agent proposal is unavailable") from error
        if (type(card) is not dict or card.get("task_id") != task_id
                or card.get("human_principal") != employee.principal
                or card.get("agent_principal") != agent.agent_principal
                or type(card.get("not_before")) is not int
                or type(card.get("expires_at")) is not int
                or not card["not_before"] <= now < card["expires_at"]
                or type(card.get("write_scopes")) is not list
                or len(card["write_scopes"]) != 1
                or type(card["write_scopes"][0]) is not dict
                or type(card["write_scopes"][0].get("handle")) is not str
                or type(card.get("purpose")) is not str
                or type(public) is not dict
                or public.get("task_id") != task_id
                or public.get("agent_principal") != agent.agent_principal
                or public.get("task_commitment") != task_commitment(card)
                or public.get("recipe_digest") != package.recipe_digest
                or trust != package.authority.trusted_template):
            raise OperatorDenied("staged proposal disagrees with signed task")
        refreshed = build_exact_write_card(
            package, employee, agent, installation_path=self.installation_path,
            recipe_path=self.recipe_path, profile_lock_path=self.profile_lock_path,
            resource_handle=card["write_scopes"][0]["handle"],
            purpose=card["purpose"], now=now,
            read_recipe_path=self.read_recipe_path,
            read_profile_lock_path=self.read_profile_lock_path,
            read_resource_handle=(card["read_scopes"][0]["handle"]
                                  if card.get("read_scopes") else None),
        )
        if set(card) != set(refreshed):
            raise OperatorDenied("installed task scope changed")
        for key, reviewed in card.items():
            if key not in {"task_id", "not_before", "expires_at"} and refreshed[key] != reviewed:
                raise OperatorDenied("installed task scope changed")
        _, _, recipe_sha, lock_sha = _reviewed_profile(
            self.recipe_path, self.profile_lock_path,
        )
        if (recipe_sha != package.recipe_source_sha256
                or lock_sha != package.profile_lock_sha256):
            raise OperatorDenied("reviewed recipe changed")
        try:
            completed = subprocess.run([
                str(self._binary()), "review-submission",
                "--recipe", str(self.recipe_path),
                "--profile-lock", str(self.profile_lock_path),
                "--trusted-context", str(directory / "trusted-context.cbor"),
                "--proof", str(directory / "agent.proof"),
                "--action", str(directory / "agent.action"),
                "--evaluated-at", str(now),
            ], capture_output=True, check=False, timeout=10)
            if completed.returncode != 0 or len(completed.stdout) > 131_072:
                raise OperatorDenied("gateway refused staged agent proposal")
            review = json.loads(completed.stdout, object_pairs_hook=_unique_pairs)
        except (OSError, subprocess.TimeoutExpired, ValueError) as error:
            raise OperatorDenied("gateway review is unavailable") from error
        if (_private_read(directory / "agent.proof", 4 * 1024 * 1024) != proof
                or _private_read(directory / "agent.action", 64 * 1024) != action):
            raise OperatorDenied("agent proposal changed during gateway review")
        if not proof or not action or type(recipe) is not dict:
            raise OperatorDenied("staged agent proposal is invalid")
        return card, project_exact_write(card, review, recipe, package.recipe_digest)

    def prepare(self, *, task_id: str, employee: EmployeeBinding,
                agent: AgentBinding, now: int | None = None) -> PreparedConfirmation:
        now = int(time.time()) if now is None else now
        card, review = self._review(task_id, employee, agent, now)
        if self.preflight is not None:
            self.preflight(card, review)
        package = load_task_write_package(self.authority_path, now=now)
        action = prepare_exact_confirmation(package.authority, review.intent, now=now)
        nonce = secrets.token_urlsafe(24)
        with self._lock:
            self._pending[nonce] = _Pending(
                employee, agent, task_id, review.intent, review, action,
            )
        return PreparedConfirmation(
            nonce, task_id, card, review.intent, review,
            action.signing_preimage, action.expires_at,
        )

    def complete(self, *, nonce: str, employee: EmployeeBinding,
                 agent: AgentBinding, signature: bytes,
                 now: int | None = None) -> Path:
        now = int(time.time()) if now is None else now
        with self._lock:
            pending = self._pending.pop(nonce, None)
        if (pending is None or pending.employee != employee
                or pending.agent != agent or now >= pending.action.expires_at):
            raise OperatorDenied("exact write review is unavailable")
        card, current = self._review(pending.task_id, employee, agent, now)
        if current != pending.review or current.intent != pending.intent:
            raise OperatorDenied("agent proposal changed during exact review")
        if self.preflight is not None:
            self.preflight(card, current)
        signed = pending.action.complete(signature, now=now)
        directory = self._task_dir(pending.task_id)
        _private_write(directory / "confirmation.proof", signed.proof)
        try:
            _private_write(directory / "confirmation.action", signed.action)
        except BaseException:
            (directory / "confirmation.proof").unlink(missing_ok=True)
            raise
        return directory

    def activate(self, task_id: str) -> None:
        """Register the browser-signed task once in the private gateway journal."""
        if self.gateway_state_dir is None:
            raise OperatorDenied("gateway task execution is not configured")
        directory = self._task_dir(task_id)
        _private_read(directory / "task.proof", 4 * 1024 * 1024)
        _private_read(directory / "task.action", 64 * 1024)
        try:
            result = subprocess.run([
                str(self._binary()), "task-activate",
                "--state-dir", str(self.gateway_state_dir),
                "--proof", str(directory / "task.proof"),
                "--action", str(directory / "task.action"),
            ], capture_output=True, check=False, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise OperatorDenied(
                "gateway task activation outcome is unknown; inspect state",
            ) from error
        if (result.returncode != 0 or len(result.stdout) > 4096
                or result.stdout.strip() != b'{"outcome":"task-activated"}'):
            raise OperatorDenied(
                "gateway task activation outcome is unknown; inspect state",
            )

    def revoke(self, *, task_id: str, employee: EmployeeBinding) -> None:
        """Stop future reads and writes for one task owned by this employee."""
        if self.gateway_state_dir is None:
            raise OperatorDenied("gateway task execution is not configured")
        directory = self._task_dir(task_id)
        try:
            card = json.loads(_private_read(directory / "task-card.json", 16_384),
                              object_pairs_hook=_unique_pairs)
        except (OSError, PermissionError, ValueError, UnicodeDecodeError) as error:
            raise OperatorDenied("signed task card is unavailable") from error
        if (type(card) is not dict or card.get("task_id") != task_id
                or card.get("company_id") != employee.company_id
                or card.get("human_principal") != employee.principal):
            raise OperatorDenied("task is not owned by this employee")
        try:
            result = subprocess.run([
                str(self._binary()), "task-revoke",
                "--state-dir", str(self.gateway_state_dir),
                "--task-id", task_id,
            ], capture_output=True, check=False, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise OperatorDenied(
                "gateway task revocation outcome is unknown; inspect state",
            ) from error
        if (result.returncode != 0 or len(result.stdout) > 4096
                or result.stdout.strip() != b'{"outcome":"task-revoked"}'):
            raise OperatorDenied(
                "gateway task revocation outcome is unknown; inspect state",
            )

    def submit(self, *, task_id: str, employee: EmployeeBinding,
               agent: AgentBinding, now: int | None = None) -> dict:
        """Recheck Jules's edit precondition, then submit one exact agent write.

        The signed Docs action itself carries requiredRevisionId, so a change
        between this read-only check and Google entry is refused by Google.
        An uncertain gateway result is never retried here.
        """
        if self.gateway_state_dir is None or self.preflight is None:
            raise OperatorDenied("gateway task execution is not configured")
        now = int(time.time()) if now is None else now
        card, review = self._review(task_id, employee, agent, now)
        directory = self._task_dir(task_id)
        _private_read(directory / "confirmation.proof", 4 * 1024 * 1024)
        _private_read(directory / "confirmation.action", 64 * 1024)
        self.preflight(card, review)
        try:
            result = subprocess.run([
                str(self._binary()), "task-submit",
                "--state-dir", str(self.gateway_state_dir),
                "--task-id", task_id,
                "--agent-proof", str(directory / "agent.proof"),
                "--agent-action", str(directory / "agent.action"),
                "--confirmation-proof", str(directory / "confirmation.proof"),
                "--confirmation-action", str(directory / "confirmation.action"),
            ], capture_output=True, check=False, timeout=90)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise OperatorDenied(
                "gateway write outcome is unknown; inspect state before retry",
            ) from error
        if result.returncode != 0 or len(result.stdout) > 8192:
            raise OperatorDenied(
                "gateway write outcome is unknown; inspect state before retry",
            )
        try:
            outcome = json.loads(result.stdout, object_pairs_hook=_unique_pairs)
        except (UnicodeDecodeError, ValueError) as error:
            raise OperatorDenied(
                "gateway write outcome is unknown; inspect state before retry",
            ) from error
        if type(outcome) is not dict:
            raise OperatorDenied(
                "gateway write outcome is unknown; inspect state before retry",
            )
        kind = outcome.get("outcome")
        fields = {
            "denied": {"code"}, "indeterminate": {"code"},
            "not-entered": {"code"}, "unknown": set(),
            "response-recorded": {"status"},
            "observed": {"status", "matched"},
            "observed-by-provider": {"status", "evidence"},
        }
        if (kind not in fields or set(outcome) != {"outcome"} | fields[kind]
                or ("code" in outcome and
                    (type(outcome["code"]) is not str
                     or not 1 <= len(outcome["code"]) <= 128))
                or ("status" in outcome and outcome["status"] is not None
                    and (type(outcome["status"]) is not int
                         or not 100 <= outcome["status"] <= 599))
                or ("matched" in outcome and type(outcome["matched"]) is not bool)
                or ("evidence" in outcome and type(outcome["evidence"]) is not dict)):
            raise OperatorDenied(
                "gateway write outcome is unknown; inspect state before retry",
            )
        # Return only public status fields; provider response and document
        # content never leave gateway/producer custody through this endpoint.
        return {key: outcome[key] for key in ("outcome", "code", "status", "matched")
                if key in outcome and type(outcome[key]) in (str, int, bool)}
