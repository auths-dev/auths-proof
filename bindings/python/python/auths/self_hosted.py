"""Exact, application-owned MCP operations over native Auths verification.

This module authorizes an action. It does not hold provider credentials or
qualify an application's provider request, result, or reconciliation logic.
"""

from __future__ import annotations

import base64
import json
import re
import time
import types
from collections.abc import Mapping
from dataclasses import dataclass, is_dataclass
from dataclasses import fields as dataclass_fields
from typing import (
    Generic,
    Literal,
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


class _UnknownEnumVariant(ValueError):
    code = "self-hosted.enum-variant-undeclared"
    stage = "contract"


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
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError("invalid Unicode in string field") from error
        if not self.min_length <= len(encoded) <= self.max_length:
            raise ValueError("string outside declared byte bounds")
        return value


@dataclass(frozen=True)
class EnumField:
    """One exact ASCII variant from an ordered, closed declaration."""

    variants: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.variants) is not tuple
            or not 1 <= len(self.variants) <= 32
            or any(type(item) is not str or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", item) for item in self.variants)
            or len(set(self.variants)) != len(self.variants)
        ):
            raise ValueError("enum variants must be unique bounded ASCII names")

    def validate(self, value: object) -> str:
        if type(value) is not str or value not in self.variants:
            raise _UnknownEnumVariant("unknown enum variant")
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
        return value


@dataclass(frozen=True)
class BooleanField:
    def validate(self, value: object) -> bool:
        if type(value) is not bool:
            raise ValueError("expected a boolean")
        return value


@dataclass(frozen=True)
class BytesField:
    min_length: int = 0
    max_length: int = 1024

    def __post_init__(self) -> None:
        if (
            type(self.min_length) is not int
            or type(self.max_length) is not int
            or not 0 <= self.min_length <= self.max_length <= 3072
        ):
            raise ValueError("bytes field bounds are invalid")

    def validate(self, value: object) -> bytes:
        if type(value) is not bytes or not self.min_length <= len(value) <= self.max_length:
            raise ValueError("bytes outside declared bounds")
        return value

    def from_wire(self, value: object) -> bytes:
        if type(value) is not str or "=" in value or len(value) > 4096:
            raise ValueError("expected unpadded base64url bytes")
        try:
            encoded = value.encode("ascii")
            decoded = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
        except (UnicodeEncodeError, ValueError) as error:
            raise ValueError("invalid base64url bytes") from error
        if base64.urlsafe_b64encode(decoded).rstrip(b"=") != encoded:
            raise ValueError("noncanonical base64url bytes")
        return self.validate(decoded)


@dataclass(frozen=True)
class ArrayField:
    inner: Field
    min_items: int
    max_items: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.inner, (StringField, EnumField, IntegerField, BooleanField, BytesField, ArrayField, ObjectField))
            or type(self.min_items) is not int
            or type(self.max_items) is not int
            or not 0 <= self.min_items <= self.max_items <= 32
        ):
            raise ValueError("array field bounds or item schema are invalid")


@dataclass(frozen=True)
class ObjectField:
    command_type: type[object]
    fields: Mapping[str, Field]

    def __post_init__(self) -> None:
        _check_dataclass_schema(self.command_type, self.fields)


@dataclass(frozen=True)
class OptionalField:
    inner: Field

    def __post_init__(self) -> None:
        if not isinstance(self.inner, (StringField, EnumField, IntegerField, BooleanField, BytesField, ArrayField, ObjectField)):
            raise TypeError("unsupported optional inner field")

Field = Union[StringField, EnumField, IntegerField, BooleanField, BytesField, ArrayField, ObjectField, OptionalField]  # noqa: UP007 -- Python 3.9 runtime union


def _check_dataclass_schema(command_type: type[object], schema: Mapping[str, Field]) -> None:
    if not is_dataclass(command_type):
        raise TypeError("command_type must be a dataclass")
    params = getattr(command_type, "__dataclass_params__", None)
    if params is None or not params.frozen:
        raise TypeError("command_type must be a frozen dataclass")
    declared = tuple(field.name for field in dataclass_fields(command_type))
    if not declared or set(declared) != set(schema) or len(declared) > 32:
        raise ValueError("command fields must match the closed schema")
    if not all(isinstance(item, (StringField, EnumField, IntegerField, BooleanField, BytesField, ArrayField, ObjectField, OptionalField)) for item in schema.values()):
        raise TypeError("unsupported command field schema")
    total, depth = _schema_limits(schema)
    if total > 32 or depth > 4:
        raise ValueError("command schema exceeds field or depth bounds")
    local_types: dict[str, type[object]] = {}

    def collect_types(item: Field) -> None:
        if isinstance(item, ObjectField):
            name = item.command_type.__name__
            previous = local_types.get(name)
            if previous is not None and previous is not item.command_type:
                raise TypeError("nested command types must have distinct names")
            local_types[name] = item.command_type
            for nested in item.fields.values():
                collect_types(nested)
        elif isinstance(item, (ArrayField, OptionalField)):
            collect_types(item.inner)

    for item in schema.values():
        collect_types(item)
    annotations = get_type_hints(command_type, localns=local_types)
    for name, item in schema.items():
        if not _annotation_matches(annotations.get(name), item):
            raise TypeError(f"command annotation for {name} must match schema")


def _schema_limits(fields: Mapping[str, Field]) -> tuple[int, int]:
    counts = [_field_limits(item) for item in fields.values()]
    return sum(count for count, _ in counts), 1 + max((depth for _, depth in counts), default=0)


def _field_limits(field: Field) -> tuple[int, int]:
    if isinstance(field, OptionalField):
        return _field_limits(field.inner)
    if isinstance(field, ArrayField):
        count, depth = _field_limits(field.inner)
        return count, 1 + depth
    if isinstance(field, ObjectField):
        return _schema_limits(field.fields)
    return 1, 0


def _annotation_matches(annotation: object, schema: Field) -> bool:
    if isinstance(schema, EnumField):
        return get_origin(annotation) is Literal and get_args(annotation) == schema.variants
    if isinstance(schema, OptionalField):
        return (
            get_origin(annotation) in (Union, getattr(types, "UnionType", Union))
            and len(get_args(annotation)) == 2
            and type(None) in get_args(annotation)
            and any(_annotation_matches(item, schema.inner) for item in get_args(annotation) if item is not type(None))
        )
    if isinstance(schema, ArrayField):
        arguments = get_args(annotation)
        return (
            get_origin(annotation) is tuple
            and len(arguments) == 2
            and arguments[1] is Ellipsis
            and _annotation_matches(arguments[0], schema.inner)
        )
    return annotation is _type_for(schema)


def _type_for(schema: Field) -> object:
    if isinstance(schema, StringField):
        return str
    if isinstance(schema, IntegerField):
        return int
    if isinstance(schema, BooleanField):
        return bool
    if isinstance(schema, BytesField):
        return bytes
    if isinstance(schema, ObjectField):
        return schema.command_type
    raise TypeError("unsupported scalar field annotation")


def _field_value(schema: Field, value: object, *, wire: bool) -> object:
    if isinstance(schema, OptionalField):
        return None if value is None else _field_value(schema.inner, value, wire=wire)
    if isinstance(schema, BytesField):
        return schema.from_wire(value) if wire else schema.validate(value)
    if isinstance(schema, ArrayField):
        if (wire and type(value) is not list) or (not wire and type(value) is not tuple):
            raise ValueError("expected a bounded array")
        items = cast(Union[list[object], tuple[object, ...]], value)
        if not schema.min_items <= len(items) <= schema.max_items:
            raise ValueError("array item count outside declared bounds")
        return tuple(_field_value(schema.inner, item, wire=wire) for item in items)
    if isinstance(schema, ObjectField):
        if wire:
            if type(value) is not dict or set(value) != set(schema.fields):
                raise ValueError("object does not match the closed schema")
            source: Mapping[str, object] = cast(Mapping[str, object], value)
        else:
            if type(value) is not schema.command_type:
                raise ValueError("object does not match its generated type")
            source = {name: getattr(value, name) for name in schema.fields}
        checked = {name: _field_value(field, source[name], wire=wire) for name, field in schema.fields.items()}
        result = schema.command_type(**checked)
        if any(getattr(result, name) != checked[name] for name in checked):
            raise ValueError("object constructor changed validated values")
        return result
    return schema.validate(value)


def _wire_value(schema: Field, value: object) -> object:
    checked = _field_value(schema, value, wire=False)
    if isinstance(schema, OptionalField):
        return None if checked is None else _wire_value(schema.inner, checked)
    if isinstance(schema, BytesField):
        assert isinstance(checked, bytes)
        return base64.urlsafe_b64encode(checked).rstrip(b"=").decode("ascii")
    if isinstance(schema, ArrayField):
        assert isinstance(checked, tuple)
        return [_wire_value(schema.inner, item) for item in checked]
    if isinstance(schema, ObjectField):
        return {name: _wire_value(field, getattr(checked, name)) for name, field in schema.fields.items()}
    return checked


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
        _check_dataclass_schema(command_type, fields)
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
            name: _field_value(schema, arguments[name], wire=True)
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

    def encode(self, command: CommandT) -> dict[str, object]:
        """Produce bounded argument values for authoring or local test fixtures.

        The returned mapping is not authorization; verification still projects
        only from the native-verified action bytes.
        """
        if type(command) is not self.command_type:
            raise TypeError("command does not belong to this exact tool")
        return {
            name: _wire_value(schema, getattr(command, name))
            for name, schema in self.fields.items()
        }

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
        arguments = self.encode(command)
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

    __slots__ = ("action_commitment", "command", "decision", "kind")

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


CommandResult = Union[AuthorizedCommand[CommandT], RejectedCommand]  # noqa: UP007 -- Python 3.9 runtime union


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
            raise TypeError("MCP arguments must be an object")
        command = contract.validate_arguments(cast(Mapping[str, object], arguments))
    except _UnknownEnumVariant:
        return RejectedCommand(
            "denied", "self-hosted.enum-variant-undeclared", "developer-contract", decision
        )
    except (TypeError, ValueError):
        return RejectedCommand(
            "denied", "self-hosted.contract-mismatch", "developer-contract", decision
        )
    return AuthorizedCommand(_AUTHORIZED_TOKEN, command, commitment, decision)


def _canonical_arguments(arguments: Mapping[str, object]) -> bytes:
    preliminary = json.dumps(
        arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    encoded = bytes(_native.canonicalize_mcp_arguments_json(preliminary))
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
    "ArrayField",
    "AuthorizedCommand",
    "BooleanField",
    "BytesField",
    "CommandResult",
    "EnumField",
    "ExactMcpTool",
    "IntegerField",
    "ObjectField",
    "OptionalField",
    "PreparedMcpAction",
    "RejectedCommand",
    "StringField",
    "verify_command",
]
