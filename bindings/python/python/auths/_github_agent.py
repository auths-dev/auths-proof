"""Typed client for the launch GitHub issue-agent vertical.

GitHub semantics remain in the Rust service.  This module validates
developer-shaped values, transports them, and projects the closed outcomes.
It never handles a GitHub credential or implements authorization policy.
"""

from __future__ import annotations

import asyncio
import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping, Optional, Sequence, Union, cast

_SCHEMA = "auths-github-agent/v1"
_MAX_RESPONSE_BYTES = 1_048_576
_MAX_CANDIDATE_BYTES = 2 * 1_048_576
_DEFAULT_TIMEOUT_SECONDS = 120.0

GitHubDenialFixture = Literal[
    "prohibited-path",
    "candidate-changed",
    "repository-changed",
    "issue-changed",
    "base-advanced",
    "malformed-bundle",
]


@dataclass(frozen=True)
class GitHubAgentBoundary:
    repository: str
    issue_number: int
    base_ref: str
    base_revision: str
    allowed_paths: tuple[str, ...]
    protected_paths: tuple[str, ...]
    minimum_expiry_seconds: int
    maximum_expiry_seconds: int
    branch_budget: Literal[1]
    draft_pull_request_budget: Literal[1]
    agent_credential_present: Literal[False]


@dataclass(frozen=True)
class GitHubAgentTask:
    repository: str
    issue_number: int
    base_ref: str
    base_revision: str
    allowed_paths: Sequence[str]
    protected_paths: Sequence[str]
    expires_in_seconds: int
    branch_budget: Literal[1]
    draft_pull_request_budget: Literal[1]
    agent_label: str


@dataclass(frozen=True)
class GitHubCandidateFile:
    path: Union[str, Path]
    base_revision: str
    candidate_revision: str


@dataclass(frozen=True)
class GitHubCandidateInspection:
    kind: Literal["inspected", "denied"]
    candidate_revision: Optional[str]
    changed_paths: tuple[str, ...]
    direct_push: Literal[
        "refused-without-credential", "not-attempted", "unexpectedly-accepted"
    ]
    decision_code: str
    credential_would_be_requested: bool


@dataclass(frozen=True)
class GitHubAgentOutcome:
    kind: Literal["completed", "denied", "indeterminate", "replayed", "reconciled"]
    code: str
    credential_requests: Union[int, Literal["unknown"]]
    mutations: Union[int, Literal["unknown"]]
    next: Literal["none", "reconcile"]
    branch_ref: Optional[str] = None
    pull_request_number: Optional[int] = None
    pull_request_url: Optional[str] = None


@dataclass(frozen=True)
class GitHubVerifiedReceipts:
    kind: Literal["verified"]
    workflow_id: str
    count: int


class GitHubAgentSession:
    """Opaque capability naming one bounded delegated GitHub task."""

    __slots__ = (
        "_session_id",
        "workflow_id",
        "expires_at",
        "target_ref",
        "agent_principal",
        "required_configuration",
        "executed_configuration",
    )

    def __init__(
        self,
        session_id: str,
        workflow_id: str,
        expires_at: int,
        target_ref: str,
        agent_principal: str,
        required_configuration: str,
        executed_configuration: str,
        *,
        _token: object,
    ) -> None:
        if _token is not _SESSION_TOKEN:
            raise TypeError("Auths GitHub agent sessions are opaque")
        self._session_id = session_id
        self.workflow_id = workflow_id
        self.expires_at = expires_at
        self.target_ref = target_ref
        self.agent_principal = agent_principal
        self.required_configuration = required_configuration
        self.executed_configuration = executed_configuration

    def __repr__(self) -> str:
        return f"GitHubAgentSession(workflow_id={self.workflow_id!r})"


_SESSION_TOKEN = object()


class GitHubAgentError(RuntimeError):
    """One bounded error returned by the GitHub agent service."""

    def __init__(self, code: str, detail: str, status: int) -> None:
        super().__init__(detail)
        self.code = code
        self.status = status


class GitHubAgentClient:
    """Client for one operator-approved GitHub issue-agent deployment."""

    def __init__(self, endpoint: str, timeout_seconds: float) -> None:
        self._endpoint = _endpoint(endpoint)
        if not 0.1 <= timeout_seconds <= 120.0:
            raise ValueError("Auths GitHub agent timeout is outside bounds")
        self._timeout_seconds = timeout_seconds

    async def boundary(self) -> GitHubAgentBoundary:
        value = await self._call("/v1/demo/scenario")
        budgets = _record(value.get("budgets"), "budgets")
        expiry = _record(value.get("expiry"), "expiry")
        if (
            budgets.get("branches") != 1
            or budgets.get("draft_pull_requests") != 1
            or value.get("agent_credential_present") is not False
        ):
            raise TypeError("Auths GitHub agent boundary is unsafe")
        return GitHubAgentBoundary(
            repository=_string(value.get("repository"), "repository"),
            issue_number=_integer(value.get("issue_number"), "issue number"),
            base_ref=_string(value.get("base_ref"), "base ref"),
            base_revision=_string(value.get("base_revision"), "base revision"),
            allowed_paths=_strings(value.get("allowed_paths"), "allowed paths"),
            protected_paths=_strings(value.get("denied_paths"), "protected paths"),
            minimum_expiry_seconds=_integer(
                expiry.get("minimum_seconds"), "minimum expiry"
            ),
            maximum_expiry_seconds=_integer(
                expiry.get("maximum_seconds"), "maximum expiry"
            ),
            branch_budget=1,
            draft_pull_request_budget=1,
            agent_credential_present=False,
        )

    async def delegate(self, task: GitHubAgentTask) -> GitHubAgentSession:
        _validate_task(task)
        value = await self._call(
            "/v1/demo/sessions",
            {
                "repository": task.repository,
                "issueNumber": task.issue_number,
                "baseRef": task.base_ref,
                "baseRevision": task.base_revision,
                "allowedPaths": list(task.allowed_paths),
                "protectedPaths": list(task.protected_paths),
                "expiresInSeconds": task.expires_in_seconds,
                "branchBudget": task.branch_budget,
                "draftPullRequestBudget": task.draft_pull_request_budget,
                "agentLabel": task.agent_label,
            },
        )
        required_configuration = _string(
            value.get("required_configuration"), "required configuration"
        )
        executed_configuration = _string(
            value.get("executed_configuration"), "executed configuration"
        )
        if required_configuration != executed_configuration:
            raise TypeError("Auths GitHub agent verifier configuration mismatch")
        return GitHubAgentSession(
            _string(value.get("session_id"), "session id"),
            _string(value.get("workflow_id"), "workflow id"),
            _integer(value.get("expires_at"), "expiry"),
            _string(value.get("target_ref"), "target ref"),
            _string(value.get("agent_principal"), "agent principal"),
            required_configuration,
            executed_configuration,
            _token=_SESSION_TOKEN,
        )

    async def inspect_candidate(
        self, session: GitHubAgentSession, candidate: GitHubCandidateFile
    ) -> GitHubCandidateInspection:
        path = Path(candidate.path)
        if not candidate.base_revision or not candidate.candidate_revision:
            raise TypeError("Auths GitHub candidate file is invalid")
        metadata = await asyncio.to_thread(path.stat)
        if (
            not path.is_file()
            or metadata.st_size == 0
            or metadata.st_size > _MAX_CANDIDATE_BYTES
        ):
            raise TypeError("Auths GitHub candidate file is outside bounds")
        bundle = await asyncio.to_thread(path.read_bytes)
        if not bundle or len(bundle) > _MAX_CANDIDATE_BYTES:
            raise TypeError("Auths GitHub candidate file changed outside bounds")
        encoded = base64.urlsafe_b64encode(bundle).rstrip(b"=").decode("ascii")
        value = await self._call(
            f"/v1/demo/sessions/{_session_id(session)}/candidate",
            {
                "kind": "bundle",
                "bundleBase64url": encoded,
                "baseRevision": candidate.base_revision,
                "candidateRevision": candidate.candidate_revision,
            },
        )
        return _inspection(value)

    async def inspect_fixture(
        self,
        session: GitHubAgentSession,
        fixture: Union[Literal["exact"], GitHubDenialFixture],
    ) -> GitHubCandidateInspection:
        value = await self._call(
            f"/v1/demo/sessions/{_session_id(session)}/candidate",
            {"kind": "fixture", "experiment": fixture},
        )
        return _inspection(value)

    async def execute(self, session: GitHubAgentSession) -> GitHubAgentOutcome:
        return await self._operate(session, "execute")

    async def replay(self, session: GitHubAgentSession) -> GitHubAgentOutcome:
        return await self._operate(session, "replay")

    async def reconcile(self, session: GitHubAgentSession) -> GitHubAgentOutcome:
        return await self._operate(session, "reconcile")

    async def verify_receipts(
        self, session: GitHubAgentSession
    ) -> GitHubVerifiedReceipts:
        value = await self._call(f"/v1/demo/receipts/demo-{_session_id(session)}")
        receipts = value.get("receipts")
        if not isinstance(receipts, list):
            raise TypeError("receipts are malformed")
        workflow_id = _string(value.get("workflow_id"), "workflow id")
        if not receipts or workflow_id != session.workflow_id:
            raise TypeError(
                "Auths GitHub agent receipt timeline is not bound to the session"
            )
        return GitHubVerifiedReceipts(
            kind="verified",
            workflow_id=workflow_id,
            count=len(receipts),
        )

    async def _operate(
        self,
        session: GitHubAgentSession,
        operation: Literal["execute", "replay", "reconcile"],
    ) -> GitHubAgentOutcome:
        session_id = _session_id(session)
        try:
            value = await self._call(
                f"/v1/demo/sessions/{session_id}/{operation}", {}
            )
            return _outcome(value)
        except Exception:
            return GitHubAgentOutcome(
                kind="indeterminate",
                code="transport-uncertain",
                credential_requests="unknown",
                mutations="unknown",
                next="reconcile",
            )

    async def _call(
        self, path: str, body: Optional[Mapping[str, object]] = None
    ) -> dict[str, Any]:
        return await asyncio.to_thread(self._call_sync, path, body)

    def _call_sync(
        self, path: str, body: Optional[Mapping[str, object]]
    ) -> dict[str, Any]:
        encoded = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            urllib.parse.urljoin(self._endpoint, path.lstrip("/")),
            data=encoded,
            method="GET" if body is None else "POST",
            headers={"content-type": "application/json"},
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=self._timeout_seconds,
                context=ssl.create_default_context(),
            ) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
                status = response.status
        except urllib.error.HTTPError as error:
            raw = error.read(_MAX_RESPONSE_BYTES + 1)
            status = error.code
        if not raw or len(raw) > _MAX_RESPONSE_BYTES:
            raise TypeError("Auths GitHub agent response is outside bounds")
        value = _record(json.loads(raw), "Auths GitHub agent response")
        if status < 200 or status >= 300:
            raise GitHubAgentError(
                str(value.get("code", f"http-{status}")),
                str(value.get("detail", "GitHub agent request failed")),
                status,
            )
        if value.get("schema") != _SCHEMA:
            raise TypeError("Auths GitHub agent schema mismatch")
        return value


def create_github_agent_client(
    *, endpoint: str, timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS
) -> GitHubAgentClient:
    """Open the typed GitHub issue-agent launch client."""

    return GitHubAgentClient(endpoint, timeout_seconds)


def _inspection(value: Mapping[str, Any]) -> GitHubCandidateInspection:
    candidate = _record(value.get("candidate"), "candidate")
    preview = _record(candidate.get("preview"), "candidate preview")
    direct = _record(candidate.get("direct_push"), "direct push")
    status = _string(candidate.get("status"), "candidate status")
    if status not in ("inspected", "denied"):
        raise TypeError("invalid candidate status")
    direct_push = _string(direct.get("result"), "direct push result")
    if direct_push not in (
        "refused-without-credential",
        "not-attempted",
        "unexpectedly-accepted",
    ):
        raise TypeError("invalid direct-push result")
    if status == "inspected" and direct_push != "refused-without-credential":
        raise TypeError("inspected candidate did not prove credential isolation")
    paths = candidate.get("changed_paths", [])
    if not isinstance(paths, list):
        raise TypeError("changed paths are malformed")
    changed = tuple(
        _string(_record(path, "changed path").get("path"), "changed path")
        for path in paths
    )
    credential = preview.get("credential_would_be_requested")
    if not isinstance(credential, bool):
        raise TypeError("credential projection is malformed")
    return GitHubCandidateInspection(
        kind=cast(Literal["inspected", "denied"], status),
        candidate_revision=candidate.get("candidate_revision")
        if isinstance(candidate.get("candidate_revision"), str)
        else None,
        changed_paths=changed,
        direct_push=cast(
            Literal[
                "refused-without-credential", "not-attempted", "unexpectedly-accepted"
            ],
            direct_push,
        ),
        decision_code=_string(preview.get("code"), "decision code"),
        credential_would_be_requested=credential,
    )


def _outcome(value: Mapping[str, Any]) -> GitHubAgentOutcome:
    decision = _record(value.get("decision"), "decision")
    execution = _record(value.get("execution"), "execution")
    code = _string(decision.get("code"), "decision code")
    decision_class = _string(decision.get("class"), "decision class")
    if decision_class not in ("authorized", "denied", "indeterminate"):
        raise TypeError("invalid GitHub agent decision class")
    status = execution.get("status")
    replay = execution.get("replay")
    if replay == "original-receipt-returned":
        kind = "replayed"
    elif isinstance(status, str) and status.startswith("reconciled"):
        kind = "reconciled"
    elif decision_class == "denied":
        kind = "denied"
    elif decision_class == "indeterminate":
        kind = "indeterminate"
    else:
        kind = "completed"
    return GitHubAgentOutcome(
        kind=cast(
            Literal["completed", "denied", "indeterminate", "replayed", "reconciled"],
            kind,
        ),
        code=code,
        credential_requests=(
            _uncertain_integer(value.get("credential_requests"))
            if decision_class == "indeterminate"
            else _integer(value.get("credential_requests"), "credential requests")
        ),
        mutations=(
            _uncertain_integer(value.get("mutations"))
            if decision_class == "indeterminate"
            else _integer(value.get("mutations"), "mutation count")
        ),
        next="reconcile" if decision_class == "indeterminate" else "none",
        branch_ref=execution.get("branch_ref")
        if isinstance(execution.get("branch_ref"), str)
        else None,
        pull_request_number=_optional_integer(execution.get("pull_request_number")),
        pull_request_url=execution.get("pull_request_url")
        if isinstance(execution.get("pull_request_url"), str)
        else None,
    )


def _validate_task(task: GitHubAgentTask) -> None:
    if (
        not isinstance(task.issue_number, int)
        or task.issue_number < 1
        or not isinstance(task.expires_in_seconds, int)
        or task.expires_in_seconds < 1
        or task.branch_budget != 1
        or task.draft_pull_request_budget != 1
    ):
        raise TypeError("Auths GitHub agent task is outside bounds")
    values = (
        task.repository,
        task.base_ref,
        task.base_revision,
        task.agent_label,
        *task.allowed_paths,
        *task.protected_paths,
    )
    if any(not isinstance(value, str) or not value or len(value) > 1_024 for value in values):
        raise TypeError("Auths GitHub agent task contains an invalid string")


def _session_id(session: GitHubAgentSession) -> str:
    if not isinstance(session, GitHubAgentSession):
        raise TypeError("forged Auths GitHub agent session")
    return session._session_id


def _endpoint(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    local = parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if (
        (parsed.scheme != "https" and not local)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Auths GitHub agent endpoint must be HTTPS or loopback HTTP")
    return value.rstrip("/") + "/"


def _record(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise TypeError(f"{label} is malformed")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise TypeError(f"{label} is malformed")
    return value


def _integer(value: object, label: str) -> int:
    result = _optional_integer(value)
    if result is None:
        raise TypeError(f"{label} is malformed")
    return result


def _optional_integer(value: object) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _uncertain_integer(value: object) -> Union[int, Literal["unknown"]]:
    integer = _optional_integer(value)
    return "unknown" if integer is None else integer


def _strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise TypeError(f"{label} is malformed")
    return tuple(value)


__all__ = [
    "GitHubAgentBoundary",
    "GitHubAgentClient",
    "GitHubAgentError",
    "GitHubAgentOutcome",
    "GitHubAgentSession",
    "GitHubAgentTask",
    "GitHubCandidateFile",
    "GitHubCandidateInspection",
    "GitHubDenialFixture",
    "GitHubVerifiedReceipts",
    "create_github_agent_client",
]
