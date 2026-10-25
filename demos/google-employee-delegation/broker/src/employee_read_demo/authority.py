"""The only broker path from portable proof bytes to a read command."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .contracts import ReadCommand, TaskDescriptor, canonical_json


@dataclass(frozen=True)
class VerifiedRead:
    command: ReadCommand
    action_commitment: bytes
    native_code: str


def native_body_digest(command: ReadCommand, service: str) -> bytes:
    """Use the native MCP profile and codec for AllowedBodyDigests."""
    command.validate()
    from auths import _native
    args = _native.canonicalize_mcp_arguments_json(canonical_json(asdict(command)))
    call = _native.mcp_call(service, "google_drive_document_read", args)
    return bytes(_native.mcp_body_digest(call))


def verify_read(
    *, proof: bytes, action: bytes, trusted_template: bytes,
    challenge: bytes, evaluation_time: int, task: TaskDescriptor,
) -> VerifiedRead:
    """Bind broker-owned request context and consume the native sealed command.

    The caller cannot supply a trusted context or an unverified arguments object.
    A successful verification still needs task/state admission before token use.
    """
    if len(challenge) != 32 or not 0 < len(proof) <= 262_144 or not 0 < len(action) <= 262_144:
        raise ValueError("invalid proof, action or challenge size")
    from auths import _native
    from auths.self_hosted import (
        ExactMcpTool, IntegerField, StringField, AuthorizedCommand,
        verify_command,
    )

    tool = ExactMcpTool(
        service=task.service,
        name="google_drive_document_read",
        command_type=ReadCommand,
        fields={
            "contract": StringField(1, 64),
            "company_id": StringField(1, 64),
            "instance_id": StringField(1, 64),
            "task_id": StringField(1, 256),
            "task_commitment": StringField(64, 64),
            "connection_id": StringField(1, 256),
            "connection_generation": IntegerField(1, 2**31 - 1),
            "file_id": StringField(1, 256),
            "output": StringField(1, 16),
            "max_bytes": IntegerField(1, 262_144),
        },
    )
    template = _native.parse_trusted_context(trusted_template)
    bound = template.bind_request(f"mcp://{task.service}", challenge, evaluation_time)
    result = verify_command(
        contract=tool, proof=proof, action=action,
        trusted_context=bytes(_native.inspect_trusted_context(bound)),
    )
    if not isinstance(result, AuthorizedCommand):
        raise PermissionError(f"native verification refused: {result.code}")
    command = result.command
    command.validate()
    if command not in task.calls():
        raise PermissionError("verified action is outside the approved task")
    return VerifiedRead(command, result.action_commitment, result.decision.code)
