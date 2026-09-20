"""Contract tests for exact self-hosted MCP operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import pytest

from auths.self_hosted import (
    AuthorizedCommand,
    ArrayField,
    BooleanField,
    BytesField,
    ExactMcpTool,
    IntegerField,
    OptionalField,
    ObjectField,
    StringField,
    verify_command,
)
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


def test_command_constructor_cannot_change_projected_arguments() -> None:
    @dataclass(frozen=True)
    class MutatingCommand:
        value: str

        def __post_init__(self) -> None:
            object.__setattr__(self, "value", "different")

    contract = ExactMcpTool(
        service="example-service", name="set_value",
        command_type=MutatingCommand,
        fields={"value": StringField(min_length=1, max_length=32)},
    )
    with pytest.raises(ValueError, match="changed"):
        contract.validate_arguments({"value": "approved"})


def test_mutable_command_classes_are_not_supported() -> None:
    @dataclass
    class MutableCommand:
        value: str

    with pytest.raises(TypeError, match="frozen"):
        ExactMcpTool(
            service="example-service", name="set_value",
            command_type=MutableCommand,
            fields={"value": StringField(min_length=1, max_length=32)},
        )


def test_checked_integers_and_booleans_are_exact_and_not_interchangeable() -> None:
    @dataclass(frozen=True)
    class MixedCommand:
        count: int
        enabled: bool
        retry_count: Optional[int]

    contract = ExactMcpTool(
        service="example-service", name="set_value",
        command_type=MixedCommand,
        fields={"count": IntegerField(minimum=-5, maximum=10),
                "enabled": BooleanField(),
                "retry_count": OptionalField(IntegerField(minimum=0, maximum=3))},
    )
    artifacts = development_mcp_artifacts(
        service="example-service", name="set_value",
        arguments={"count": 3, "enabled": True, "retry_count": None},
    )
    result = verify_command(
        contract=contract, proof=artifacts.proof, action=artifacts.action,
        trusted_context=artifacts.trusted_context,
    )
    assert isinstance(result, AuthorizedCommand)
    assert result.command == MixedCommand(3, True, None)
    for invalid in (
        {"count": True, "enabled": True, "retry_count": None},
        {"count": 11, "enabled": True, "retry_count": None},
        {"count": 3.5, "enabled": True, "retry_count": None},
        {"count": 3, "enabled": 1, "retry_count": None},
        {"count": 3, "enabled": True, "retry_count": "2"},
    ):
        with pytest.raises(ValueError):
            contract.validate_arguments(invalid)
    with pytest.raises(ValueError, match="bounds"):
        IntegerField(minimum=True, maximum=10)
    with pytest.raises(ValueError, match="bounds"):
        StringField(min_length=True, max_length=10)
    with pytest.raises(TypeError, match="inner"):
        OptionalField(object())


def test_command_annotations_must_match_the_bounded_schema() -> None:
    @dataclass(frozen=True)
    class WrongType:
        enabled: int

    with pytest.raises(TypeError, match="annotation"):
        ExactMcpTool(
            service="example-service", name="set_value",
            command_type=WrongType, fields={"enabled": BooleanField()},
        )


def test_command_constructor_cannot_coerce_a_verified_value() -> None:
    @dataclass(frozen=True)
    class CoercingCommand:
        enabled: bool

        def __post_init__(self) -> None:
            object.__setattr__(self, "enabled", int(self.enabled))

    contract = ExactMcpTool(
        service="example-service", name="set_value",
        command_type=CoercingCommand, fields={"enabled": BooleanField()},
    )
    with pytest.raises(ValueError, match="changed"):
        contract.validate_arguments({"enabled": True})


def test_nested_array_and_bytes_project_only_from_verified_arguments() -> None:
    @dataclass(frozen=True)
    class Target:
        record_id: str

    @dataclass(frozen=True)
    class NestedCommand:
        target: Target
        labels: tuple[str, ...]
        payload: bytes

    contract = ExactMcpTool(
        service="example-service", name="nested_v1", command_type=NestedCommand,
        fields={
            "target": ObjectField(Target, {"record_id": StringField(1, 32)}),
            "labels": ArrayField(StringField(1, 16), 1, 3),
            "payload": BytesField(2, 16),
        },
    )
    arguments = {
        "target": {"record_id": "rec-1"}, "labels": ["demo"], "payload": "AQI"
    }
    artifacts = development_mcp_artifacts(
        service="example-service", name="nested_v1", arguments=arguments,
    )
    result = verify_command(
        contract=contract, proof=artifacts.proof, action=artifacts.action,
        trusted_context=artifacts.trusted_context,
    )
    assert isinstance(result, AuthorizedCommand)
    assert result.command == NestedCommand(Target("rec-1"), ("demo",), b"\x01\x02")
    for malformed in (
        {**arguments, "payload": "AQI="},
        {**arguments, "labels": []},
        {**arguments, "target": {"record_id": "rec-1", "other": "x"}},
    ):
        with pytest.raises(ValueError):
            contract.validate_arguments(malformed)
