"""Contract tests for exact self-hosted MCP operations."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from auths.self_hosted import AuthorizedCommand, ExactMcpTool, StringField, verify_command
from auths.testkit import development_mcp_artifacts


@dataclass(frozen=True)
class ExampleCommand:
    value: str


TOOL = ExactMcpTool(
    service="example-service",
    name="set_value",
    command_type=ExampleCommand,
    fields={"value": StringField(min_length=1, max_length=32)},
)


def test_authorized_projection_is_derived_from_verified_action() -> None:
    artifacts = development_mcp_artifacts(
        service="example-service",
        name="set_value",
        arguments={"value": "approved"},
    )
    result = verify_command(
        contract=TOOL,
        proof=artifacts.proof,
        action=artifacts.action,
        trusted_context=artifacts.trusted_context,
    )
    assert isinstance(result, AuthorizedCommand)
    assert result.command == ExampleCommand("approved")
    assert len(result.action_commitment) == 32


def test_mutated_proof_action_does_not_project_command() -> None:
    artifacts = development_mcp_artifacts(
        service="example-service",
        name="set_value",
        arguments={"value": "approved"},
    )
    changed = bytearray(artifacts.action)
    changed[-1] ^= 1
    result = verify_command(
        contract=TOOL,
        proof=artifacts.proof,
        action=bytes(changed),
        trusted_context=artifacts.trusted_context,
    )
    assert result.kind != "authorized"


def test_other_tool_is_not_this_contract() -> None:
    artifacts = development_mcp_artifacts(
        service="example-service",
        name="other_tool",
        arguments={"value": "approved"},
    )
    result = verify_command(
        contract=TOOL,
        proof=artifacts.proof,
        action=artifacts.action,
        trusted_context=artifacts.trusted_context,
    )
    assert result.kind == "denied"


def test_schema_rejects_unknown_and_overlong_fields() -> None:
    with pytest.raises(ValueError):
        TOOL.validate_arguments({"value": "approved", "unexpected": "x"})
    with pytest.raises(ValueError):
        TOOL.validate_arguments({"value": "x" * 33})
