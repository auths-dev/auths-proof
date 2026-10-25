"""Short owner-side browser ceremony for an exact human write task.

The caller checks Google login, active employee enrollment, active registered
agent and pinned producer resource before preparation and again at completion.
This class never holds the employee key or a provider token. It stores the
signed task proof privately for the gateway operator and returns only public
agent grant material to the browser after both signatures are verified.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .agent_registry import AgentBinding
from .enrollment import EmployeeBinding
from .operator_authority import OperatorDenied
from .operator_cli import _private_write
from .task_write_card import build_exact_write_card
from .task_write_delegation import PreparedAgentDelegation, prepare_agent_delegation
from .task_write_package import load_task_write_package
from .task_write_proofs import PreparedHumanAction, prepare_task_approval


@dataclass(frozen=True)
class PreparedWriteTask:
    nonce: str
    card: dict
    account_label: str
    resource_label: str
    grant_preimage: bytes
    task_preimage: bytes
    expires_at: int


@dataclass(frozen=True)
class CompletedWriteTask:
    task_id: str
    agent_principal: str
    expires_at: int
    agent_package: dict
    private_task_dir: Path


@dataclass(frozen=True)
class _Pending:
    employee: EmployeeBinding
    agent: AgentBinding
    card: dict
    task_action: PreparedHumanAction
    child: PreparedAgentDelegation
    expires_at: int


class TaskWriteBrowserFlow:
    def __init__(self, *, authority_path: Path, installation_path: Path,
                 recipe_path: Path, profile_lock_path: Path,
                 private_output_dir: Path) -> None:
        if (private_output_dir.is_symlink() or not private_output_dir.is_dir()
                or private_output_dir.stat().st_mode & 0o077):
            raise OperatorDenied("task output directory must be owner-private")
        self.authority_path = authority_path
        self.installation_path = installation_path
        self.recipe_path = recipe_path
        self.profile_lock_path = profile_lock_path
        self.private_output_dir = private_output_dir
        self._pending: dict[str, _Pending] = {}
        self._lock = threading.Lock()

    def prepare(self, *, employee: EmployeeBinding, agent: AgentBinding,
                employee_identity_packet: bytes, agent_identity_packet: bytes,
                resource_handle: str, resource_label: str, account_label: str,
                purpose: str, now: int | None = None) -> PreparedWriteTask:
        now = int(time.time()) if now is None else now
        if (not resource_label or len(resource_label) > 256
                or not account_label or len(account_label) > 256):
            raise OperatorDenied("task resource or account label is invalid")
        package = load_task_write_package(self.authority_path, now=now)
        card = build_exact_write_card(
            package, employee, agent, installation_path=self.installation_path,
            recipe_path=self.recipe_path, profile_lock_path=self.profile_lock_path,
            resource_handle=resource_handle, purpose=purpose, now=now,
        )
        task_action = prepare_task_approval(package.authority, card, now=now)
        child = prepare_agent_delegation(
            package.authority, employee_identity_packet, agent_identity_packet,
            card, package.recipe_digest,
        )
        nonce = secrets.token_urlsafe(24)
        expires_at = min(task_action.expires_at, card["expires_at"])
        with self._lock:
            self._pending[nonce] = _Pending(
                employee, agent, card, task_action, child, expires_at,
            )
        return PreparedWriteTask(
            nonce, card, account_label, resource_label,
            child.signing_preimage, task_action.signing_preimage, expires_at,
        )

    def complete(self, *, nonce: str, employee: EmployeeBinding,
                 agent: AgentBinding, grant_signature: bytes,
                 task_signature: bytes, now: int | None = None) -> CompletedWriteTask:
        now = int(time.time()) if now is None else now
        with self._lock:
            pending = self._pending.pop(nonce, None)
        if (pending is None or pending.employee != employee or pending.agent != agent
                or now >= pending.expires_at):
            raise OperatorDenied("task signing ceremony is unavailable")
        current = load_task_write_package(self.authority_path, now=now)
        if (current.authority != pending.task_action.authority
                or current.recipe_digest != pending.child.recipe_digest):
            raise OperatorDenied("task authority changed during browser review")
        refreshed = build_exact_write_card(
            current, employee, agent, installation_path=self.installation_path,
            recipe_path=self.recipe_path, profile_lock_path=self.profile_lock_path,
            resource_handle=pending.card["write_scopes"][0]["handle"],
            purpose=pending.card["purpose"], now=now,
        )
        for key, reviewed in pending.card.items():
            if key not in {"task_id", "not_before", "expires_at"} and refreshed[key] != reviewed:
                raise OperatorDenied("installed task scope changed during browser review")
        agent_package = pending.child.complete(grant_signature, now=now)
        signed_task = pending.task_action.complete(task_signature, now=now)
        task_dir = self.private_output_dir / pending.card["task_id"]
        task_dir.mkdir(mode=0o700)
        try:
            _private_write(task_dir / "task.proof", signed_task.proof)
            _private_write(task_dir / "task.action", signed_task.action)
            _private_write(task_dir / "agent-package.json", json.dumps(
                agent_package, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8"))
        except BaseException:
            for name in ("task.proof", "task.action", "agent-package.json"):
                (task_dir / name).unlink(missing_ok=True)
            task_dir.rmdir()
            raise
        return CompletedWriteTask(
            pending.card["task_id"], pending.agent.agent_principal,
            pending.card["expires_at"], agent_package, task_dir,
        )
