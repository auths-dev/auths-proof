"""Short owner-side browser ceremony for a human write task.

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
from .task_write_delegation import (
    PreparedAgentDelegation, prepare_agent_delegation,
    prepare_agent_read_delegation, prepare_agent_companion_write_delegation,
)
from .task_write_package import load_task_write_package
from .task_write_proofs import PreparedHumanAction, prepare_task_approval


@dataclass(frozen=True)
class PreparedWriteTask:
    nonce: str
    card: dict
    account_label: str
    resource_label: str
    write_tool: str
    companion_write_tool: str | None
    grant_preimage: bytes
    read_grant_preimage: bytes | None
    companion_grant_preimage: bytes | None
    task_preimage: bytes
    read_resource_label: str | None
    expires_at: int


@dataclass(frozen=True)
class CompletedWriteTask:
    task_id: str
    agent_principal: str
    expires_at: int
    agent_package: dict
    read_agent_package: dict | None
    companion_agent_package: dict | None
    private_task_dir: Path


@dataclass(frozen=True)
class _Pending:
    employee: EmployeeBinding
    agent: AgentBinding
    card: dict
    task_action: PreparedHumanAction
    child: PreparedAgentDelegation
    read_child: PreparedAgentDelegation | None
    companion_child: PreparedAgentDelegation | None
    expires_at: int


class TaskWriteBrowserFlow:
    def __init__(self, *, authority_path: Path, installation_path: Path,
                 recipe_path: Path, profile_lock_path: Path,
                 read_recipe_path: Path | None = None,
                 read_profile_lock_path: Path | None = None,
                 companion_recipe_path: Path | None = None,
                 companion_profile_lock_path: Path | None = None,
                 upfront_allowed_arguments: list[dict] | None = None,
                 private_output_dir: Path) -> None:
        if (private_output_dir.is_symlink() or not private_output_dir.is_dir()
                or private_output_dir.stat().st_mode & 0o077):
            raise OperatorDenied("task output directory must be owner-private")
        self.authority_path = authority_path
        self.installation_path = installation_path
        self.recipe_path = recipe_path
        self.profile_lock_path = profile_lock_path
        self.read_recipe_path = read_recipe_path
        self.read_profile_lock_path = read_profile_lock_path
        self.companion_recipe_path = companion_recipe_path
        self.companion_profile_lock_path = companion_profile_lock_path
        self.upfront_allowed_arguments = upfront_allowed_arguments
        self.private_output_dir = private_output_dir
        self._pending: dict[str, _Pending] = {}
        self._lock = threading.Lock()

    def prepare(self, *, employee: EmployeeBinding, agent: AgentBinding,
                employee_identity_packet: bytes, agent_identity_packet: bytes,
                resource_handle: str, resource_label: str, account_label: str,
                read_resource_handle: str | None = None,
                read_resource_label: str | None = None,
                pending_child: dict | None = None,
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
            read_recipe_path=self.read_recipe_path,
            read_profile_lock_path=self.read_profile_lock_path,
            read_resource_handle=read_resource_handle,
            companion_recipe_path=self.companion_recipe_path,
            companion_profile_lock_path=self.companion_profile_lock_path,
            pending_child=pending_child,
            upfront_allowed_arguments=self.upfront_allowed_arguments,
        )
        task_action = prepare_task_approval(package.authority, card, now=now)
        child = prepare_agent_delegation(
            package.authority, employee_identity_packet, agent_identity_packet,
            card, package.recipe_digest,
        )
        read_child = None
        if package.read is not None:
            if not read_resource_label or len(read_resource_label) > 256:
                raise OperatorDenied("task read label is invalid")
            read_child = prepare_agent_read_delegation(
                package.authority, employee_identity_packet,
                agent_identity_packet, card, package.read.recipe_digest,
            )
        elif read_resource_label is not None:
            raise OperatorDenied("task read label has no reviewed source")
        companion_child = None
        if package.companion_write is not None:
            companion_child = prepare_agent_companion_write_delegation(
                package.authority, employee_identity_packet,
                agent_identity_packet, card,
                package.companion_write.recipe_digest,
            )
        nonce = secrets.token_urlsafe(24)
        expires_at = min(task_action.expires_at, card["expires_at"])
        with self._lock:
            self._pending[nonce] = _Pending(
                employee, agent, card, task_action, child, read_child,
                companion_child, expires_at,
            )
        return PreparedWriteTask(
            nonce, card, account_label, resource_label,
            f"{package.authority.provider_service}/{package.authority.provider_tool}",
            (None if package.companion_write is None else
             f"{package.companion_write.service}/{package.companion_write.tool}"),
            child.signing_preimage,
            None if read_child is None else read_child.signing_preimage,
            None if companion_child is None else companion_child.signing_preimage,
            task_action.signing_preimage, read_resource_label, expires_at,
        )

    def complete(self, *, nonce: str, employee: EmployeeBinding,
                 agent: AgentBinding, grant_signature: bytes,
                 task_signature: bytes, read_grant_signature: bytes | None = None,
                 companion_grant_signature: bytes | None = None,
                 now: int | None = None) -> CompletedWriteTask:
        now = int(time.time()) if now is None else now
        with self._lock:
            pending = self._pending.pop(nonce, None)
        if (pending is None or pending.employee != employee or pending.agent != agent
                or now >= pending.expires_at):
            raise OperatorDenied("task signing ceremony is unavailable")
        current = load_task_write_package(self.authority_path, now=now)
        if (current.authority != pending.task_action.authority
                or current.recipe_digest != pending.child.recipe_digest
                or (current.read is None) != (pending.read_child is None)
                or (current.read is not None and
                    current.read.recipe_digest != pending.read_child.recipe_digest)
                or (current.companion_write is None) !=
                (pending.companion_child is None)
                or (current.companion_write is not None and
                    current.companion_write.recipe_digest !=
                    pending.companion_child.recipe_digest)):
            raise OperatorDenied("task authority changed during browser review")
        refreshed = build_exact_write_card(
            current, employee, agent, installation_path=self.installation_path,
            recipe_path=self.recipe_path, profile_lock_path=self.profile_lock_path,
            resource_handle=pending.card["write_scopes"][0]["handle"],
            purpose=pending.card["purpose"], now=now,
            read_recipe_path=self.read_recipe_path,
            read_profile_lock_path=self.read_profile_lock_path,
            read_resource_handle=(pending.card["read_scopes"][0]["handle"]
                                  if pending.read_child is not None else None),
            companion_recipe_path=self.companion_recipe_path,
            companion_profile_lock_path=self.companion_profile_lock_path,
            pending_child=pending.card.get("pending_child"),
            upfront_allowed_arguments=pending.card.get("upfront_allowed_arguments"),
        )
        for key, reviewed in pending.card.items():
            if key not in {"task_id", "not_before", "expires_at"} and refreshed[key] != reviewed:
                raise OperatorDenied("installed task scope changed during browser review")
        agent_package = pending.child.complete(grant_signature, now=now)
        if pending.read_child is None:
            if read_grant_signature is not None:
                raise OperatorDenied("task has no read grant to sign")
            read_agent_package = None
        else:
            if read_grant_signature is None:
                raise OperatorDenied("task read grant signature is missing")
            read_agent_package = pending.read_child.complete(
                read_grant_signature, now=now,
            )
        if pending.companion_child is None:
            if companion_grant_signature is not None:
                raise OperatorDenied("task has no companion write grant to sign")
            companion_agent_package = None
        else:
            if companion_grant_signature is None:
                raise OperatorDenied("task companion write grant signature is missing")
            companion_agent_package = pending.companion_child.complete(
                companion_grant_signature, now=now,
            )
        signed_task = pending.task_action.complete(task_signature, now=now)
        task_dir = self.private_output_dir / pending.card["task_id"]
        task_dir.mkdir(mode=0o700)
        try:
            _private_write(task_dir / "task.proof", signed_task.proof)
            _private_write(task_dir / "task.action", signed_task.action)
            _private_write(task_dir / "task-card.json", json.dumps(
                pending.card, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8"))
            _private_write(task_dir / "trusted-context.cbor", current.authority.trusted_template)
            _private_write(task_dir / "agent-package.json", json.dumps(
                agent_package, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8"))
            if read_agent_package is not None:
                _private_write(task_dir / "agent-read-package.json", json.dumps(
                    read_agent_package, sort_keys=True, separators=(",", ":"),
                ).encode("utf-8"))
            if companion_agent_package is not None:
                _private_write(task_dir / "agent-companion-write-package.json", json.dumps(
                    companion_agent_package, sort_keys=True, separators=(",", ":"),
                ).encode("utf-8"))
        except BaseException:
            for name in ("task.proof", "task.action", "task-card.json",
                         "trusted-context.cbor", "agent-package.json",
                         "agent-read-package.json",
                         "agent-companion-write-package.json"):
                (task_dir / name).unlink(missing_ok=True)
            task_dir.rmdir()
            raise
        return CompletedWriteTask(
            pending.card["task_id"], pending.agent.agent_principal,
            pending.card["expires_at"], agent_package,
            read_agent_package, companion_agent_package, task_dir,
        )
