"""Closed task and read contracts. These values never confer Auths authority."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass

MAX_FILES = 8
MAX_CALL_BYTES = 262_144
MAX_TASK_BYTES = 4 * 1024 * 1024
MAX_PROVIDER_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_METADATA_BYTES = 16_384
MAX_CALLS = 16
MAX_ATTEMPTS = 40
MAX_DURATION = 15 * 60
_ID = re.compile(r"^[A-Za-z0-9_-]{1,256}$")
_NAME = re.compile(r"^[a-z][a-z0-9-]{0,63}$")


def valid_service(service: object) -> bool:
    return isinstance(service, str) and _NAME.fullmatch(service) is not None


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def commitment(domain: str, value: object) -> str:
    from auths import _native
    canonical = _native.canonicalize_mcp_arguments_json(canonical_json(value))
    return bytes(_native.commit_canonical_v1(domain, canonical)).hex()


@dataclass(frozen=True)
class ReadCommand:
    contract: str
    company_id: str
    instance_id: str
    task_id: str
    task_commitment: str
    connection_id: str
    connection_generation: int
    file_id: str
    output: str
    max_bytes: int

    def validate(self) -> None:
        if self.contract != "google-drive-document-read/v1" or self.output != "text":
            raise ValueError("unsupported read contract")
        if not _NAME.fullmatch(self.company_id) or not _NAME.fullmatch(self.instance_id):
            raise ValueError("invalid company or instance")
        if any(not _ID.fullmatch(value) for value in (self.task_id, self.connection_id, self.file_id)):
            raise ValueError("invalid opaque ID")
        if not re.fullmatch(r"[0-9a-f]{64}", self.task_commitment):
            raise ValueError("invalid task commitment")
        if type(self.connection_generation) is not int or self.connection_generation < 1:
            raise ValueError("invalid connection generation")
        if type(self.max_bytes) is not int or not 1 <= self.max_bytes <= MAX_CALL_BYTES:
            raise ValueError("invalid response ceiling")


@dataclass(frozen=True)
class TaskDescriptor:
    contract: str
    company_id: str
    instance_id: str
    environment_commitment: str
    employee_principal: str
    identity_binding_ref: str
    agent_principal: str
    service: str
    connection_id: str
    connection_generation: int
    file_ids: tuple[str, ...]
    output: str
    per_call_bytes: int
    max_calls: int
    max_total_bytes: int
    not_before: int
    expires_at: int
    task_id: str
    purpose: str

    def validate(self) -> None:
        if self.contract != "auths.google-read-task/v1":
            raise ValueError("unsupported task contract")
        if not _NAME.fullmatch(self.company_id) or not _NAME.fullmatch(self.instance_id):
            raise ValueError("invalid namespace")
        if not re.fullmatch(r"[0-9a-f]{64}", self.environment_commitment):
            raise ValueError("invalid environment commitment")
        if (not self.employee_principal or not self.agent_principal
                or self.employee_principal == self.agent_principal
                or len(self.employee_principal.encode("utf-8")) > 256
                or len(self.agent_principal.encode("utf-8")) > 256):
            raise ValueError("employee and agent must be distinct")
        if not valid_service(self.service) or self.output != "text":
            raise ValueError("unsupported service or output")
        if any(not _ID.fullmatch(x) for x in (self.connection_id, self.task_id, self.identity_binding_ref)):
            raise ValueError("invalid binding ID")
        if type(self.connection_generation) is not int or self.connection_generation < 1:
            raise ValueError("invalid connection generation")
        if not 1 <= len(self.file_ids) <= MAX_FILES or tuple(sorted(set(self.file_ids))) != self.file_ids:
            raise ValueError("file IDs must be sorted, unique and bounded")
        if any(not _ID.fullmatch(x) for x in self.file_ids):
            raise ValueError("invalid file ID")
        if type(self.per_call_bytes) is not int or not 1 <= self.per_call_bytes <= MAX_CALL_BYTES:
            raise ValueError("invalid call byte limit")
        if type(self.max_calls) is not int or not 1 <= self.max_calls <= MAX_CALLS:
            raise ValueError("invalid call limit")
        if type(self.max_total_bytes) is not int or not 1 <= self.max_total_bytes <= MAX_TASK_BYTES:
            raise ValueError("invalid task byte limit")
        if (any(type(x) is not int for x in (self.not_before, self.expires_at))
                or self.not_before < 1 or not 0 < self.expires_at - self.not_before <= MAX_DURATION):
            raise ValueError("invalid task validity")
        if not self.purpose or len(self.purpose.encode("utf-8")) > 256:
            raise ValueError("invalid purpose")

    @property
    def digest(self) -> str:
        self.validate()
        return commitment(self.contract, asdict(self))

    def calls(self) -> tuple[ReadCommand, ...]:
        digest = self.digest
        return tuple(ReadCommand(
            "google-drive-document-read/v1", self.company_id, self.instance_id,
            self.task_id, digest, self.connection_id, self.connection_generation,
            file_id, self.output, self.per_call_bytes,
        ) for file_id in self.file_ids)
