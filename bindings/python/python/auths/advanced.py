"""Bounded inspection APIs for canonical Auths data."""

from ._native import (
    AuthorizationPlan,
    McpAction,
    SignedObject,
    TrustedContext,
    UnsignedObject,
    VerifiedAction,
    inspect_mcp_action,
    inspect_plan,
    inspect_signed,
    inspect_trusted_context,
    inspect_unsigned,
    inspect_verified_action,
    parse_signed,
    parse_trusted_context,
    parse_unsigned,
    unsigned_from_signed,
)


def canonical_action_bytes(action: VerifiedAction) -> bytes:
    """Returns decision data that cannot be promoted back into authority."""

    return inspect_verified_action(action)


def unsigned_object_bytes(value: UnsignedObject) -> bytes:
    return inspect_unsigned(value)


def signed_object_bytes(value: SignedObject) -> bytes:
    return inspect_signed(value)


def authorization_plan_bytes(value: AuthorizationPlan) -> bytes:
    return inspect_plan(value)


def mcp_action_bytes(value: McpAction) -> tuple[bytes, bytes]:
    return inspect_mcp_action(value)


def trusted_context_bytes(value: TrustedContext) -> bytes:
    return inspect_trusted_context(value)


def parse_signed_object(kind: str, value: bytes) -> SignedObject:
    return parse_signed(kind, value)


def parse_unsigned_object(kind: str, value: bytes) -> UnsignedObject:
    return parse_unsigned(kind, value)


def parse_trusted_context_bytes(value: bytes) -> TrustedContext:
    return parse_trusted_context(value)


def signed_object_statement(value: SignedObject) -> UnsignedObject:
    return unsigned_from_signed(value)


__all__ = [
    "authorization_plan_bytes",
    "canonical_action_bytes",
    "mcp_action_bytes",
    "parse_signed_object",
    "parse_trusted_context_bytes",
    "parse_unsigned_object",
    "signed_object_bytes",
    "signed_object_statement",
    "trusted_context_bytes",
    "unsigned_object_bytes",
]
