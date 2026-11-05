"""Freeze the concrete AP070 metadata reference before native capability extraction."""
from __future__ import annotations

import json
import os
from pathlib import Path
import unittest

from employee_read_demo.contracts import MAX_METADATA_BYTES, ReadCommand
from employee_read_demo.google_metadata import (
    DriveRepresentation, GoogleDenied, GoogleUnavailable, validate_metadata,
)


class GoogleMetadataReferenceTests(unittest.TestCase):
    def test_metadata_reference_fixture_is_current(self) -> None:
        command = ReadCommand("google-drive-document-read/v1", "atlas", "instance", "task",
                              "a" * 64, "connection", 1, "file-A", "text", 1024)
        command.validate()
        base = {"id": "file-A", "mimeType": DriveRepresentation.PLAIN_TEXT.value,
                "capabilities": {"canDownload": True}}
        cases = []
        declarations = [
            ("plain-no-size", {}, "plain-text"),
            ("size-at-limit", {"size": "1024"}, "plain-text"),
            ("size-integer", {"size": 1024}, "plain-text"),
            ("size-zero", {"size": "0"}, "plain-text"),
            ("size-leading-zero", {"size": "01024"}, "plain-text"),
            ("size-unicode-decimal", {"size": "١٠٢٤"}, "plain-text"),
            ("size-null", {"size": None}, "plain-text"),
            ("size-over-limit", {"size": "1025"}, "denied"),
            ("size-negative", {"size": -1}, "denied"),
            ("size-float", {"size": 1.0}, "denied"),
            ("size-boolean", {"size": True}, "denied"),
            ("size-plus", {"size": "+1"}, "denied"),
            ("size-decimal-overflow", {"size": "9" * 5000}, "denied"),
            ("trashed", {"trashed": True}, "denied"),
            ("trashed-false", {"trashed": False}, "plain-text"),
            ("trashed-null", {"trashed": None}, "plain-text"),
            ("trashed-nonboolean", {"trashed": "true"}, "plain-text"),
            ("different-resource", {"id": "file-B"}, "denied"),
            ("numeric-resource", {"id": 1}, "denied"),
            ("download-denied", {"capabilities": {"canDownload": False}}, "denied"),
            ("download-number", {"capabilities": {"canDownload": 1}}, "denied"),
            ("download-absent", {"capabilities": {}}, "denied"),
            ("capabilities-null", {"capabilities": None}, "denied"),
            ("document", {"mimeType": DriveRepresentation.GOOGLE_DOCUMENT.value}, "google-document"),
            ("document-size-not-content-bound", {"mimeType": DriveRepresentation.GOOGLE_DOCUMENT.value, "size": "1025"}, "google-document"),
            ("unsupported-mime", {"mimeType": "application/pdf"}, "denied"),
            ("mime-null", {"mimeType": None}, "denied"),
            ("mime-array", {"mimeType": []}, "denied"),
        ]
        encoded = [(name, json.dumps({**base, **change}, ensure_ascii=False).encode(), expected)
                   for name, change, expected in declarations]
        encoded.extend([
            ("nonobject", b"[]", "denied"),
            ("missing-identity", b'{}', "denied"),
            ("invalid-json", b"{", "unavailable"),
            ("invalid-utf8", b"\xff", "unavailable"),
            ("utf16-reference", json.dumps(base).encode("utf-16-le"), "plain-text"),
            ("metadata-limit", json.dumps(base).encode().ljust(MAX_METADATA_BYTES, b" "), "plain-text"),
            ("metadata-limit-plus-one", json.dumps(base).encode().ljust(MAX_METADATA_BYTES+1, b" "), "unavailable"),
            ("duplicate-last-wins-reference", b'{"id":"file-B","id":"file-A","mimeType":"text/plain","capabilities":{"canDownload":true}}', "plain-text"),
        ])
        for name, body, expected in encoded:
            with self.subTest(name=name):
                try:
                    result = validate_metadata(body, command)
                    actual = "google-document" if result is DriveRepresentation.GOOGLE_DOCUMENT else "plain-text"
                except GoogleDenied:
                    actual = "denied"
                except GoogleUnavailable:
                    actual = "unavailable"
                self.assertEqual(actual, expected)
                cases.append({"case": name, "metadata_hex": body.hex(), "reference_result": actual,
                              "native_stricter_decode_required": name in {"duplicate-last-wins-reference", "utf16-reference", "trashed-nonboolean", "size-unicode-decimal"}})
        artifact = json.dumps({"schema": "auths.google-drive-metadata-reference/1",
            "scope": "pure concrete AP070 metadata reference; no transport, authority, state, native equivalence or live-provider claim",
            "file_id": command.file_id, "maximum_content_bytes": command.max_bytes,
            "hardening": ["Native bounded UTF-8 JSON must reject duplicate members, alternate encodings, nonboolean trash flags and non-ASCII decimal sizes even when this reference accepts them.",
                          "Non-string MIME values and oversized decimal conversions produce typed denial instead of Python runtime errors.",
                          "Status/media/transport limits and post-metadata freshness remain separate prerequisites."],
            "cases": cases}, indent=2, ensure_ascii=False).encode()+b"\n"
        destination = Path(__file__).resolve().parents[2]/"contracts"/"examples"/"google-metadata-reference.json"
        if os.environ.get("AUTHS_UPDATE_FIXTURES"):
            destination.write_bytes(artifact)
        self.assertEqual(destination.read_bytes(), artifact)


if __name__ == "__main__":
    unittest.main()
