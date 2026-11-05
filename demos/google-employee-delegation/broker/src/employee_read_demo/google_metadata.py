"""Concrete Drive metadata reference, separate from transport and admission.

This application-owned domain reference grants no read, custody or disclosure
capability. AP074's native recipe cutover must compare against its corpus and
explicitly document stricter decoding instead of importing this code at runtime.
"""

from __future__ import annotations

from enum import Enum
import json

from .contracts import MAX_METADATA_BYTES, ReadCommand


class GoogleDenied(PermissionError):
    """Provider refusal; no private file detail is included."""


class GoogleUnavailable(RuntimeError):
    """Transport or malformed result; no retry authority is created."""


class DriveRepresentation(Enum):
    GOOGLE_DOCUMENT = "application/vnd.google-apps.document"
    PLAIN_TEXT = "text/plain"


def validate_metadata(body: bytes, command: ReadCommand) -> DriveRepresentation:
    """Validate one bounded transport response against the exact read resource.

    The caller owns status/media/time checks; the finite byte cap is rechecked. This reference preserves the
    existing optional size/trashed behavior and Python JSON duplicate handling.
    Native gateway decoding must additionally reject duplicate members.
    """
    if len(body) > MAX_METADATA_BYTES:
        raise GoogleUnavailable("Google metadata exceeds byte limit")
    try:
        metadata = json.loads(body)
    except (ValueError, UnicodeDecodeError) as error:
        raise GoogleUnavailable("Google metadata is malformed") from error
    if (not isinstance(metadata, dict) or metadata.get("id") != command.file_id
            or metadata.get("trashed") is True):
        raise GoogleDenied("Google document metadata did not match")
    capabilities = metadata.get("capabilities")
    if not isinstance(capabilities, dict) or capabilities.get("canDownload") is not True:
        raise GoogleDenied("Google does not permit download")
    try:
        representation = DriveRepresentation(metadata.get("mimeType"))
    except (ValueError, TypeError) as error:
        raise GoogleDenied("unsupported Google document type") from error
    if representation is DriveRepresentation.PLAIN_TEXT:
        size = metadata.get("size")
        if size is not None:
            try:
                permitted = str(size).isdecimal() and int(size) <= command.max_bytes
            except ValueError:
                permitted = False
            if not permitted:
                raise GoogleDenied("document exceeds approved byte limit")
    return representation
