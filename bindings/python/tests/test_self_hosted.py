"""Contract tests for exact self-hosted MCP operations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional

import pytest
from auths import _native
from auths.self_hosted import (
    ArrayField,
    AuthorizedCommand,
    BooleanField,
    BytesField,
    EnumField,
    ExactMcpTool,
    IntegerField,
    ObjectField,
    OptionalField,
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
        retry_count: Optional[int]  # noqa: UP045 -- Python 3.9 typing support

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


def test_closed_enum_projects_only_declared_variants() -> None:
    @dataclass(frozen=True)
    class EnumCommand:
        status: Literal["open", "in_progress", "closed"]
        maybe: Optional[Literal["open", "closed"]]  # noqa: UP045 -- Python 3.9 typing support
        history: tuple[Literal["open", "closed"], ...]

    contract = ExactMcpTool(
        service="example-service", name="set_status_v1", command_type=EnumCommand,
        fields={
            "status": EnumField(("open", "in_progress", "closed")),
            "maybe": OptionalField(EnumField(("open", "closed"))),
            "history": ArrayField(EnumField(("open", "closed")), 2, 3),
        },
    )
    arguments = {"status": "in_progress", "maybe": None, "history": ["open", "open"]}
    artifacts = development_mcp_artifacts(
        service=contract.service, name=contract.name, arguments=arguments,
    )
    verdict = verify_command(
        contract=contract, proof=artifacts.proof, action=artifacts.action,
        trusted_context=artifacts.trusted_context,
    )
    assert isinstance(verdict, AuthorizedCommand)
    assert verdict.command == EnumCommand("in_progress", None, ("open", "open"))
    corpus = json.loads((Path(__file__).parents[3] / "bindings/fixtures/self-hosted-profile/enum-hostile-cases.json").read_text())
    for case in corpus["cases"]:
        candidate = {**arguments, case["field"]: case["value"]}
        if case["valid"]:
            assert contract.validate_arguments(candidate)
        else:
            with pytest.raises(ValueError):
                contract.validate_arguments(candidate)

    @dataclass(frozen=True)
    class WrongEnum:
        status: Literal["closed", "in_progress", "open"]

    with pytest.raises(TypeError, match="annotation"):
        ExactMcpTool(
            service="example-service", name="set_status_v1", command_type=WrongEnum,
            fields={"status": EnumField(("open", "in_progress", "closed"))},
        )

    for variants in ((), ("open", "open"), ("open", "open status"), tuple(str(i) for i in range(33))):
        with pytest.raises(ValueError):
            EnumField(variants)


def test_enum_canonical_action_matches_shared_cross_language_corpus() -> None:
    root = Path(__file__).parents[3]
    corpus = json.loads((root / "bindings/fixtures/self-hosted-profile/enum-action-vectors.json").read_text())
    grant = _native.parse_signed(
        "grant", (root / "target/binding-vectors/mcp.signed-root-grant.cbor").read_bytes()
    )

    @dataclass(frozen=True)
    class Status:
        status: Literal["open", "in_progress", "closed"]

    contract = ExactMcpTool(
        service=corpus["service"], name=corpus["tool"], command_type=Status,
        fields={"status": EnumField(("open", "in_progress", "closed"))},
    )
    for case in corpus["cases"]:
        prepared = contract.prepare(
            Status(case["status"]),
            actor=_native.Principal("key:sha256:MPL4hHxgoCRRtbEjYAedm50CmSM11XgLojSwwYeRi1E"),
            terminal_grant=grant, challenge=bytes([0x22]) * 32, evaluation_time=50,
        )
        assert prepared.arguments_json.decode() == case["arguments_json"]
        assert prepared.canonical_action.hex() == case["action_hex"]
        assert prepared.action_commitment.hex() == case["commitment_hex"]
