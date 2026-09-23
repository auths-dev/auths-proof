"""Shape and consistency of the manual real-vendor OpenAPI rejection corpus.

The upstream documents are pinned by digest rather than committed. When
``AUTHS_OPENAPI_CORPUS_DIR`` holds them as ``<vendor>.json`` the pinned
bytes are verified as well.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

import pytest

_CORPUS = Path(__file__).parents[3] / "bindings/fixtures/openapi-corpus/cases.json"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_POINTER = re.compile(r"^#(/[^/]+)+$")
_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,111}$")
_FLAGS = {
    "--require",
    "--omit",
    "--closed",
    "--pick",
    "--literal",
    "--server",
    "--security",
    "--security-scheme",
    "--tool",
    "--max-bytes",
    "--max-items",
    "--range",
}
_VALUE_FLAGS = {"--max-bytes", "--max-items", "--range", "--pick", "--literal"}


def _corpus() -> dict[str, Any]:
    document = json.loads(_CORPUS.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _cases() -> list[dict[str, Any]]:
    cases = _corpus()["cases"]
    assert isinstance(cases, list)
    return cases


def test_corpus_header_and_vendors() -> None:
    corpus = _corpus()
    assert corpus["schema"] == "auths.openapi-manual-rejection-corpus/1"
    assert corpus["measurement"]["operationSliceLimitBytes"] == 256 * 1024
    assert corpus["measurement"]["refResolutionLimit"] == 256
    vendors = [case["vendor"] for case in _cases()]
    assert vendors == ["GitHub", "Todoist", "OpenAI"]
    finding_ids = [finding["id"] for finding in corpus["findings"]]
    assert len(finding_ids) == len(set(finding_ids))
    assert all(
        finding["status"] in {"open", "resolved"} for finding in corpus["findings"]
    )


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["vendor"])
def test_source_is_digest_pinned(case: dict[str, Any]) -> None:
    source = case["source"]
    assert source["url"].startswith("https://")
    assert _SHA256.fullmatch(source["sha256"])
    # Each pinned document must still fit the derivation input bound.
    assert 0 < source["bytes"] <= 32 * 1024 * 1024
    assert re.fullmatch(r"3\.[01]\.\d+", source["openapi"])
    if _REVISION.fullmatch(source["revision"]):
        assert source["revision"] in source["url"]
    else:
        assert source["revision"].startswith("unversioned URL")


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["vendor"])
def test_operation_is_a_single_https_write(case: dict[str, Any]) -> None:
    operation = case["operation"]
    assert operation["method"] in {"POST", "PUT", "PATCH", "DELETE"}
    assert operation["path"].startswith("/")
    assert operation["server"].startswith("https://")
    assert _POINTER.fullmatch(operation["bodySchema"])
    measured = case["measured"]
    limits = _corpus()["measurement"]
    assert measured["refCycle"] is False
    assert 0 < measured["inlinedOperationBytes"] <= limits["operationSliceLimitBytes"]
    assert 0 <= measured["refResolutionsInlined"] <= limits["refResolutionLimit"]
    assert measured["distinctComponentRefs"] <= measured["refResolutionsInlined"]


def _flag(override: str) -> str:
    flag, _, argument = override.partition(" ")
    assert flag in _FLAGS, override
    assert argument, override
    if flag in _VALUE_FLAGS:
        assert "=" in argument, override
    return flag


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["vendor"])
def test_every_rejection_has_a_recorded_repair(case: dict[str, Any]) -> None:
    rejections = case["unmodifiedRejections"]
    assert rejections
    pointers = [rejection["pointer"] for rejection in rejections]
    assert len(pointers) == len(set(pointers))
    repaired: list[str] = []
    for rejection in rejections:
        assert _POINTER.fullmatch(rejection["pointer"]), rejection
        assert re.match(r"^3\.[123] ", rejection["rule"]), rejection
        assert rejection["reason"].strip()
        assert rejection["overrides"], rejection
        for override in rejection["overrides"]:
            _flag(override)
        repaired.extend(rejection["overrides"])
    candidate = case["candidateOverrides"]
    assert len(candidate) == len(set(candidate))
    assert sorted(repaired) == sorted(candidate)


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["vendor"])
def test_tool_name_override_matches_grammar(case: dict[str, Any]) -> None:
    tools = [
        override.partition(" ")[2]
        for override in case["candidateOverrides"]
        if override.startswith("--tool ")
    ]
    operation_id = case["operation"]["operationId"]
    if _TOOL.fullmatch(operation_id):
        assert tools == []
    else:
        assert len(tools) == 1
        assert _TOOL.fullmatch(tools[0])


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["vendor"])
def test_pinned_source_bytes_when_available(case: dict[str, Any]) -> None:
    directory = os.environ.get("AUTHS_OPENAPI_CORPUS_DIR")
    if not directory:
        pytest.skip("AUTHS_OPENAPI_CORPUS_DIR is not set")
    path = Path(directory) / f"{case['vendor'].lower()}.json"
    data = path.read_bytes()
    assert len(data) == case["source"]["bytes"]
    assert hashlib.sha256(data).hexdigest() == case["source"]["sha256"]
    document = json.loads(data)
    assert document["openapi"] == case["source"]["openapi"]
    operation = document["paths"][case["operation"]["path"]][
        case["operation"]["method"].lower()
    ]
    assert operation["operationId"] == case["operation"]["operationId"]
    servers = [server["url"] for server in document["servers"]]
    assert servers == [case["operation"]["server"]]
