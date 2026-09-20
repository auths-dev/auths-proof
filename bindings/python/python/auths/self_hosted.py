"""Exact, application-owned MCP operations over native Auths verification.

This module authorizes an action. It does not hold provider credentials or
qualify an application's provider request, result, or reconciliation logic.
"""

from __future__ import annotations

import json
import time
import types
from dataclasses import dataclass, fields as dataclass_fields, is_dataclass
from typing import (
    Generic,
    Literal,
    Mapping,
    TypeVar,
    Union,
    cast,
    get_args,
    get_origin,
    get_type_hints,
)

from . import _native
from .verify import VerificationResult, _project

CommandT = TypeVar("CommandT")


@dataclass(frozen=True)
class StringField:
    min_length: int = 0
    max_length: int = 256

    def __post_init__(self) -> None:
        if (
            type(self.min_length) is not int
            or type(self.max_length) is not int
            or not 0 <= self.min_length <= self.max_length <= 4096
        ):
            raise ValueError("string field bounds are invalid")

    def validate(self, value: object) -> str:
        if type(value) is not str:
            raise ValueError("expected a string")
        encoded = value.encode("utf-8")
        if not self.min_length <= len(encoded) <= self.max_length:
            raise ValueError("string outside declared byte bounds")
        return value


@dataclass(frozen=True)
class IntegerField:
    minimum: int
    maximum: int

    def __post_init__(self) -> None:
        if (
            type(self.minimum) is not int
            or type(self.maximum) is not int
            or not -(2**53 - 1) <= self.minimum <= self.maximum <= 2**53 - 1
        ):
            raise ValueError("integer field bounds are invalid")

    def validate(self, value: object) -> int:
        if type(value) is not int or not self.minimum <= value <= self.maximum:
            raise ValueError("integer outside declared safe bounds")
        return cast(int, value)


@dataclass(frozen=True)
class BooleanField:
    def validate(self, value: object) -> bool:
        if type(value) is not bool:
            raise ValueError("expected a boolean")
        return cast(bool, value)


@dataclass(frozen=True)
class OptionalField:
    inner: StringField | IntegerField | BooleanField

    def __post_init__(self) -> None:
        if not isinstance(self.inner, (StringField, IntegerField, BooleanField)):
            raise TypeError("unsupported optional inner field")

    def validate(self, value: object) -> str | int | bool | None:
        return None if value is None else self.inner.validate(value)


Field = Union[StringField, IntegerField, BooleanField, OptionalField]


@dataclass(frozen=True)
class PreparedMcpAction(Generic[CommandT]):
    command: CommandT
    action: _native.McpAction
    canonical_action: bytes
    action_commitment: bytes
    arguments_json: bytes
    audience: str
    resource: str
    review_fields: tuple[tuple[str, str], ...]


class ExactMcpTool(Generic[CommandT]):
    """One fixed MCP service/tool with a closed, bounded command shape."""

    def __init__(
        self,
        *,
        service: str,
        name: str,
        command_type: type[CommandT],
        fields: Mapping[str, Field],
    ) -> None:
        if not is_dataclass(command_type):
            raise TypeError("command_type must be a dataclass")
        if not command_type.__dataclass_params__.frozen:
            raise TypeError("command_type must be a frozen dataclass")
        declared = tuple(field.name for field in dataclass_fields(command_type))
        if not declared or set(declared) != set(fields) or len(declared) > 32:
            raise ValueError("command fields must match the closed schema")
        if not all(
            isinstance(value, (StringField, IntegerField, BooleanField, OptionalField))
            for value in fields.values()
        ):
            raise TypeError("unsupported command field schema")
        annotations = get_type_hints(command_type)
        for field_name, schema in fields.items():
            inner = schema.inner if isinstance(schema, OptionalField) else schema
            expected: type[str] | type[int] | type[bool]
            if isinstance(inner, StringField):
                expected = str
            elif isinstance(inner, IntegerField):
                expected = int
            else:
                expected = bool
            annotation = annotations.get(field_name)
            if isinstance(schema, OptionalField):
                if (
                    get_origin(annotation) not in (Union, getattr(types, "UnionType", Union))
                    or set(get_args(annotation)) != {expected, type(None)}
                ):
                    raise TypeError(f"command annotation for {field_name} must match schema")
            elif annotation is not expected:
                raise TypeError(f"command annotation for {field_name} must match schema")
        _native.validate_mcp_service(service)
        # Native call construction validates the tool name and derived resource.
        _native.mcp_call(service, name, b"{}")
        self.service = service
        self.name = name
        self.command_type = command_type
        self.fields = dict(fields)

    def validate_arguments(self, arguments: Mapping[str, object]) -> CommandT:
        if set(arguments) != set(self.fields):
            raise ValueError("arguments do not match the exact command schema")
        checked = {
            name: schema.validate(arguments[name])
            for name, schema in self.fields.items()
        }
        command = self.command_type(**checked)
        if any(
            type(getattr(command, name)) is not type(value)
            or getattr(command, name) != value
            for name, value in checked.items()
        ):
            raise ValueError("command constructor changed verified arguments")
        return command

    def prepare(
        self,
        command: CommandT,
        *,
        actor: _native.Principal,
        terminal_grant: _native.SignedObject,
        challenge: bytes,
        evaluation_time: int,
    ) -> PreparedMcpAction[CommandT]:
        if type(command) is not self.command_type:
            raise TypeError("command does not belong to this exact tool")
        arguments = {name: getattr(command, name) for name in self.fields}
        checked = self.validate_arguments(arguments)
        encoded = _canonical_arguments(arguments)
        native = _native.prepare_mcp_action(
            self.service,
            self.name,
            encoded,
            actor,
            terminal_grant,
            bytes(challenge),
            evaluation_time,
        )
        canonical_action, _ = _native.inspect_mcp_action(native)
        return PreparedMcpAction(
            checked,
            native,
            bytes(canonical_action),
            bytes(_native.commit_canonical_v1("auths.canonical-action.v1", canonical_action)),
            encoded,
            native.audience,
            native.resource,
            tuple(native.review_fields),
        )


_AUTHORIZED_TOKEN = object()


class AuthorizedCommand(Generic[CommandT]):
    """A local projection from native verified bytes, not a provider capability."""

    __slots__ = ("kind", "command", "action_commitment", "decision")

    def __init__(
        self,
        token: object,
        command: CommandT,
        action_commitment: bytes,
        decision: VerificationResult,
    ) -> None:
        if token is not _AUTHORIZED_TOKEN:
            raise TypeError("authorized commands can only come from verification")
        self.kind: Literal["authorized"] = "authorized"
        self.command = command
        self.action_commitment = bytes(action_commitment)
        self.decision = decision


@dataclass(frozen=True)
class RejectedCommand:
    kind: Literal["denied", "indeterminate"]
    code: str
    source: Literal["auths-verifier", "developer-contract"]
    decision: VerificationResult


CommandResult = Union[AuthorizedCommand[CommandT], RejectedCommand]


def verify_command(
    *,
    contract: ExactMcpTool[CommandT],
    proof: bytes,
    action: bytes,
    trusted_context: bytes,
) -> CommandResult[CommandT]:
    """Verify once, then project only the exact named, bounded command."""
    native, sealed = _native.verify_exact_mcp_command(
        bytes(proof),
        bytes(action),
        bytes(trusted_context),
        contract.service,
        contract.name,
    )
    decision = _project(native, f"auths-{time.time_ns():x}")
    if decision.kind != "authorized":
        return RejectedCommand(decision.kind, decision.code, "auths-verifier", decision)
    if sealed is None:
        return RejectedCommand(
            "denied", "self-hosted.contract-mismatch", "developer-contract", decision
        )
    commitment = bytes(sealed.action_commitment)
    call = _native.consume_mcp_command(sealed, contract.service)
    try:
        arguments = json.loads(call.arguments_json, object_pairs_hook=_unique_pairs)
        if not isinstance(arguments, dict):
            raise ValueError("MCP arguments must be an object")
        command = contract.validate_arguments(cast(Mapping[str, object], arguments))
    except (TypeError, ValueError):
        return RejectedCommand(
            "denied", "self-hosted.contract-mismatch", "developer-contract", decision
        )
    return AuthorizedCommand(_AUTHORIZED_TOKEN, command, commitment, decision)


def _canonical_arguments(arguments: Mapping[str, object]) -> bytes:
    encoded = json.dumps(
        arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    if len(encoded) > 4096:
        raise ValueError("MCP arguments exceed the native action bound")
    return encoded


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate MCP argument key")
        result[key] = value
    return result


__all__ = [
    "AuthorizedCommand",
    "BooleanField",
    "CommandResult",
    "ExactMcpTool",
    "IntegerField",
    "OptionalField",
    "PreparedMcpAction",
    "RejectedCommand",
    "StringField",
    "verify_command",
]
