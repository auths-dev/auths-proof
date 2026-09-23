"""The packaged derive command reproduces the native derivation corpus.

Every byte comes from the Rust mapper through ``auths._native``; these tests
prove the Python route returns it unchanged, that the packaged generator's
lock agrees with each derived recipe, and that ``check`` and ``diff`` detect a
hand edit. Vendor cases run only when ``AUTHS_OPENAPI_CORPUS_DIR`` holds the
digest-pinned documents.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
from auths._profile_cli import derive_operation, main, parse_contract, render_lock

_ROOT = Path(__file__).parents[3]
_CORPUS = _ROOT / "bindings/fixtures/openapi-derivation"
_VENDORS = json.loads((_ROOT / "bindings/fixtures/openapi-corpus/cases.json").read_text(encoding="utf-8"))
_CASES: list[dict[str, Any]] = json.loads((_CORPUS / "cases.json").read_text(encoding="utf-8"))["cases"]
_UPDATE = os.environ.get("AUTHS_OPENAPI_DERIVATION_UPDATE") == "1"


def _document(case: dict[str, Any]) -> tuple[bytes, str]:
    source = case["document"]
    if "file" in source:
        path = _CORPUS / source["file"]
        return path.read_bytes(), path.name
    directory = os.environ.get("AUTHS_OPENAPI_CORPUS_DIR")
    if not directory:
        pytest.skip("AUTHS_OPENAPI_CORPUS_DIR is not set")
    pinned = next(entry for entry in _VENDORS["cases"] if entry["vendor"] == source["vendor"])
    name = f"{source['vendor'].lower()}.json"
    data = (Path(directory) / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == pinned["source"]["sha256"]
    return data, name


def _case(case_id: str) -> dict[str, Any]:
    return next(case for case in _CASES if case["id"] == case_id)


@pytest.mark.parametrize("case", _CASES, ids=lambda case: case["id"])
def test_native_route_reproduces_the_corpus(case: dict[str, Any]) -> None:
    document, name = _document(case)
    result = derive_operation(document, name, case["arguments"])
    expected = _CORPUS / "expected" / case["id"]
    report = (expected / "report.txt").read_text(encoding="utf-8")
    assert "\n".join(result["lines"]) + "\n" == report
    if case["outcome"] == "derived":
        assert result["ok"] is True
        for file_name, contents in result["files"].items():
            assert (expected / file_name).read_bytes() == contents.encode("utf-8"), file_name
        return
    assert result["ok"] is False
    rejections = [
        {"code": item["code"], "pointer": item["pointer"], "overrides": item["overrides"]}
        for item in result["diagnostics"]
    ]
    assert rejections == json.loads((expected / "rejections.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "case", [case for case in _CASES if case["outcome"] == "derived"], ids=lambda case: case["id"],
)
def test_packaged_generator_lock_binds_the_derived_recipe(case: dict[str, Any]) -> None:
    expected = _CORPUS / "expected" / case["id"]
    lock = render_lock(parse_contract((expected / "profile.toml").read_text(encoding="utf-8")))
    if _UPDATE:
        (expected / "profile.lock.json").write_text(lock, encoding="utf-8")
    assert (expected / "profile.lock.json").read_text(encoding="utf-8") == lock
    recipe = json.loads((expected / "recipe.json").read_text(encoding="utf-8"))
    assert json.loads(lock)["schema_digest"] == recipe["profile_schema_digest"]
    assert json.loads(lock)["tool"] == recipe["tool"]


def _derive(directory: Path, case_id: str, *extra: str) -> int:
    case = _case(case_id)
    return main([
        "derive", "--openapi", str(_CORPUS / case["document"]["file"]),
        "--directory", str(directory), *case["arguments"], *extra,
    ])


def test_derive_generate_check_and_hand_edit(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "notes"
    expected = _CORPUS / "expected" / "minimal-create-note"
    assert _derive(target, "minimal-create-note") == 0
    assert "claim:      derived shape only; provider effect unqualified" in capsys.readouterr().out
    for name in ("profile.toml", "recipe.json", "derivation.json"):
        assert (target / name).read_bytes() == (expected / name).read_bytes()
    manifest = target / "profile.toml"
    assert main(["generate", str(manifest)]) == 0
    assert (target / "profile.lock.json").read_bytes() == (expected / "profile.lock.json").read_bytes()
    assert main(["check", str(manifest)]) == 0
    capsys.readouterr()

    # Re-deriving unchanged inputs writes nothing; a changed override is not
    # accepted under the same version.
    before = {name: (target / name).stat().st_mtime_ns for name in ("profile.toml", "recipe.json", "derivation.json")}
    assert _derive(target, "minimal-create-note") == 0
    assert "wrote:      nothing; the files already match this derivation" in capsys.readouterr().out
    assert before == {name: (target / name).stat().st_mtime_ns for name in before}
    narrowed = [value.replace("title=100", "title=80") for value in _case("minimal-create-note")["arguments"]]
    changed = ["derive", "--openapi", str(_CORPUS / "documents/minimal.json"), "--directory", str(target), *narrowed]
    assert main(changed) == 1
    assert "contract.derive.version-required" in capsys.readouterr().err
    assert (target / "profile.toml").read_bytes() == (expected / "profile.toml").read_bytes()
    assert main([*changed, "--version", "2"]) == 0
    assert main(["check", str(manifest)]) == 1
    assert main(["generate", str(manifest)]) == 0
    assert main(["check", str(manifest)]) == 0
    capsys.readouterr()

    manifest.write_bytes(manifest.read_bytes().replace(b"max_bytes = 80", b"max_bytes = 79"))
    assert main(["check", str(manifest)]) == 1
    assert "profile.toml: derived file edited by hand" in capsys.readouterr().err
    assert main(["--json", "check", str(manifest)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["diagnostic"]["code"] == "profile.contract.derived-edited"
    assert main(["diff", str(manifest)]) == 0
    diff = capsys.readouterr().out
    assert "profile.toml: derived file edited by hand" in diff
    assert "profile.contract.version-required" in diff
    # derive refuses to overwrite a hand edit, even with a version bump.
    edited = manifest.read_bytes()
    assert main([*changed, "--version", "3"]) == 1
    assert "contract.derive.derived-edited" in capsys.readouterr().err
    assert manifest.read_bytes() == edited
    (target / "derivation.json").unlink()
    assert main(["diff", str(manifest)]) == 0
    assert "edited by hand" not in capsys.readouterr().out


def test_rejected_derivation_writes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "hostile"
    assert _derive(target, "hostile-object-union") == 1
    captured = capsys.readouterr()
    assert captured.err.startswith("REJECTED  contract\n")
    assert "contract.derive.unsupported-construct" in captured.err
    assert captured.err.rstrip().endswith("nothing written")
    assert not target.exists()
    case = _case("minimal-create-note-unmodified")
    assert main([
        "--json", "derive", "--openapi", str(_CORPUS / "documents/minimal.json"),
        "--directory", str(target), *case["arguments"],
    ]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["diagnostic"]["code"] == "contract.derive.query-parameter"
    assert report["diagnostic"]["stage"] == "contract"


def test_derive_refuses_hand_owned_files_and_unsafe_documents(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    owned = tmp_path / "owned"
    owned.mkdir()
    (owned / "profile.toml").write_text("# hand-owned\n", encoding="utf-8")
    assert _derive(owned, "minimal-create-note") == 1
    assert "contract.derive.directory-not-derived" in capsys.readouterr().err
    assert (owned / "profile.toml").read_text(encoding="utf-8") == "# hand-owned\n"
    link = tmp_path / "linked.json"
    link.symlink_to(_CORPUS / "documents/minimal.json")
    case = _case("minimal-create-note")
    assert main(["derive", "--openapi", str(link), "--directory", str(tmp_path / "out"), *case["arguments"]]) == 1
    assert "contract.derive.document-unreadable" in capsys.readouterr().err
    assert main(["derive", "--directory", str(tmp_path / "out"), *case["arguments"]]) == 1
    assert "--openapi is required" in capsys.readouterr().err


def test_derivation_record_is_read_by_the_shared_native_reader(tmp_path: Path) -> None:
    from auths._profile_cli import derived_edits

    target = tmp_path / "notes"
    assert _derive(target, "minimal-create-note") == 0
    record = target / "derivation.json"
    original = record.read_bytes()
    record.write_bytes(original.replace(b'"version": 1,', b'"version": 1.0,'))
    with pytest.raises(ValueError, match="derivation.json is invalid"):
        derived_edits(target)
    record.write_bytes(b"\xff" + original)
    with pytest.raises(ValueError, match="derivation.json is invalid"):
        derived_edits(target)
