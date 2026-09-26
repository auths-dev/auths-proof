"""``auths approve``: interactive, ``--yes``, and refusing runs."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest

from auths import _native
from auths.authoring import (
    ApprovalMember,
    ApprovalProposal,
    approval_requests,
    collect_approvals,
    propose_mcp_approval,
)
from auths.self_hosted import ExactMcpTool, IntegerField, StringField

SEEDS = {"agent": 0x11, "manager-a": 0xA1, "manager-b": 0xB2}


@dataclass(frozen=True)
class Refund:
    amount: int
    payment_intent: str


TOOL = ExactMcpTool(
    service="payments",
    name="refund_v1",
    command_type=Refund,
    fields={
        "amount": IntegerField(1, 10_000_000),
        "payment_intent": StringField(min_length=1, max_length=64),
    },
)


def _principal(name: str) -> str:
    return _native.DevelopmentEd25519Key.from_seed(bytes([SEEDS[name]]) * 32).principal


def _proposal() -> ApprovalProposal[Refund]:
    return propose_mcp_approval(
        contract=TOOL,
        command=Refund(1500, "pi_cli_0001"),
        required=3,
        approvers=[ApprovalMember(_principal(name)) for name in SEEDS],
        requester=_principal("agent"),
        challenge=bytes([0x63]) * 32,
        evaluation_time=int(time.time()) - 5,
    )


@pytest.fixture
def workspace(tmp_path: Path) -> tuple[Path, ApprovalProposal[Refund]]:
    proposal = _proposal()
    for request in approval_requests(proposal):
        name = next(name for name in SEEDS if _principal(name) == request.approver)
        (tmp_path / f"{name}.request").write_text(request.text + "\n")
    (tmp_path / "manager-a.seed").write_bytes(bytes([SEEDS["manager-a"]]) * 32)
    (tmp_path / "manager-a.signer.json").write_text(
        json.dumps(
            {
                "schema": "auths.approval-signer/1",
                "custody": "development-ed25519",
                "seed_file": "manager-a.seed",
            }
        )
    )
    return tmp_path, proposal


def _command(directory: Path, request: str, *extra: str) -> list[str]:
    return [
        sys.executable,
        "-m",
        "auths._profile_cli",
        "approve",
        request,
        "--signer",
        str(directory / "manager-a.signer.json"),
        *extra,
    ]


def _run_on_terminal(command: list[str], answer: bytes) -> subprocess.CompletedProcess[str]:
    import pty

    controller, terminal = pty.openpty()
    try:
        process = subprocess.Popen(
            command, stdin=terminal, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        os.close(terminal)
        os.write(controller, answer)
        stdout, stderr = process.communicate(timeout=120)
    finally:
        os.close(controller)
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _run_without_terminal(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120
    )


def _status(proposal: ApprovalProposal[Refund], response: Optional[Path]) -> str:
    responses = [] if response is None else [response.read_text()]
    collection = collect_approvals(proposal, responses)
    return next(
        status.status
        for status in collection.statuses
        if status.approver == _principal("manager-a")
    )


_POSIX_TERMINAL = pytest.mark.skipif(sys.platform == "win32", reason="no pseudo-terminal on Windows")


@_POSIX_TERMINAL
def test_an_interactive_yes_approves_and_prints_only_the_review(
    workspace: tuple[Path, ApprovalProposal[Refund]],
) -> None:
    directory, proposal = workspace
    out = directory / "manager-a.response"
    result = _run_on_terminal(
        _command(directory, str(directory / "manager-a.request"), "--out", str(out)), b"y\n"
    )
    assert result.returncode == 0, result.stderr
    assert "Auths V1 · MCP approval" in result.stderr
    assert '  Arguments: {"amount":1500,"payment_intent":"pi_cli_0001"}' in result.stderr
    assert f"  {_principal('manager-a')} (you)" in result.stderr
    assert "Signer: development custody" in result.stderr
    assert "Approve this action? [y/N]" in result.stderr
    assert out.read_text().startswith("auths-as1-")
    assert _status(proposal, out) == "approved"


@_POSIX_TERMINAL
def test_an_interactive_default_answer_signs_nothing(
    workspace: tuple[Path, ApprovalProposal[Refund]],
) -> None:
    directory, _ = workspace
    out = directory / "manager-a.response"
    result = _run_on_terminal(
        _command(directory, str(directory / "manager-a.request"), "--out", str(out)), b"\n"
    )
    assert result.returncode == 1
    assert "nothing was signed" in result.stderr
    assert not out.exists()


def test_yes_approves_without_a_terminal(
    workspace: tuple[Path, ApprovalProposal[Refund]],
) -> None:
    directory, proposal = workspace
    text = (directory / "manager-a.request").read_text().strip()
    out = directory / "manager-a.response"
    result = _run_without_terminal(_command(directory, text, "--yes", "--out", str(out)))
    assert result.returncode == 0, result.stderr
    assert "Approve this action?" not in result.stderr
    assert _status(proposal, out) == "approved"


def test_without_a_terminal_or_yes_nothing_is_signed(
    workspace: tuple[Path, ApprovalProposal[Refund]],
) -> None:
    directory, proposal = workspace
    out = directory / "manager-a.response"
    result = _run_without_terminal(
        _command(directory, str(directory / "manager-a.request"), "--out", str(out))
    )
    assert result.returncode == 2
    assert "pass --yes" in result.stderr
    assert not out.exists()
    assert _status(proposal, None) == "pending"


def test_a_decline_is_signed_only_when_asked(
    workspace: tuple[Path, ApprovalProposal[Refund]],
) -> None:
    directory, proposal = workspace
    result = _run_without_terminal(
        _command(directory, str(directory / "manager-a.request"), "--decline", "--yes")
    )
    assert result.returncode == 0, result.stderr
    response = directory / "manager-a.response"
    response.write_text(result.stdout)
    assert _status(proposal, response) == "declined"


def test_a_tampered_request_is_refused_before_anything_is_signed(
    workspace: tuple[Path, ApprovalProposal[Refund]],
) -> None:
    directory, _ = workspace
    request = next(item for item in approval_requests(_proposal()) if item.approver == _principal("manager-a"))
    tampered = request.data.replace(b'"amount":1500', b'"amount":9500')
    assert tampered != request.data
    (directory / "tampered.request").write_bytes(tampered)
    out = directory / "manager-a.response"
    result = _run_without_terminal(
        _command(directory, str(directory / "tampered.request"), "--yes", "--out", str(out))
    )
    assert result.returncode == 1
    assert "approval.action-mismatch" in result.stderr
    assert "Approve this action?" not in result.stderr
    assert not out.exists()
