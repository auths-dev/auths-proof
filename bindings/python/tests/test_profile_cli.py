"""The packaged profile tool emits an exact, version-bound operation."""

from __future__ import annotations

from pathlib import Path

import pytest
from auths._profile_cli import (
    parse_contract,
    profile_diff,
    render_adapter,
    render_generated,
    render_lock,
    render_run,
    render_vectors,
)

ROOT = Path(__file__).parents[2] / "fixtures" / "self-hosted-profile"
PROFILE = (ROOT / "profile.toml").read_text()


def test_generated_profile_binds_version_and_closed_schema() -> None:
    contract = parse_contract(PROFILE)
    generated = render_generated(contract)
    assert 'TOOL_NAME = "set_value_v2"' in generated
    assert "class ExampleSetValue:" in generated
    assert "retry_count: Optional[int]" in generated
    assert '"retry_count": OptionalField(IntegerField(minimum=0, maximum=3))' in generated
    assert "class ExampleSetValueTarget:" in generated
    assert "labels: tuple[str, ...]" in generated
    assert "payload: bytes" in generated
    assert 'status: Literal["open", "in_progress", "closed"]' in generated
    assert '"tool":"set_value_v2"' in render_vectors(contract)


def test_starter_keeps_provider_ownership_explicit() -> None:
    contract = parse_contract(PROFILE)
    adapter = render_adapter(contract)
    runner = render_run(contract)
    assert "class ApplicationAdapter:" in adapter
    assert "def credential(self) -> str:" in adapter
    assert "async def observe" in adapter
    assert "raise NotImplementedError" in adapter
    assert "expected_command" in runner
    assert "run_once(" in runner


def test_language_neutral_vector_fixture_is_exact() -> None:
    contract = parse_contract(PROFILE)
    assert render_vectors(contract) == (ROOT / "vectors.json").read_text()
    assert render_lock(contract) == (ROOT / "profile.lock.json").read_text()


@pytest.mark.parametrize(
    "change",
    [
        PROFILE.replace('max_bytes = 32', 'max_bytes = 32\nmax_bytes = 32'),
        PROFILE.replace('version = 2', 'version = 0'),
        PROFILE.replace('max_bytes = 32', 'max_bytes = 99999'),
        PROFILE.replace('type = "boolean"', 'type = "any"'),
        PROFILE.replace('variants = ["open", "in_progress", "closed"]', 'variants = []'),
        PROFILE.replace('variants = ["open", "in_progress", "closed"]', 'variants = ["open", "open"]'),
        PROFILE.replace('variants = ["open", "in_progress", "closed"]', 'variants = ["open", "Open!" ]'),
        PROFILE.replace('variants = ["open", "in_progress", "closed"]', 'variants = ["open", "closed",]'),
        PROFILE.replace('variants = ["open", "in_progress", "closed"]', 'variants = ["open"]\nunknown = 1'),
        PROFILE.replace('tool = "set_value"', 'tool = "set_value"\nunknown = "boolean"'),
    ],
)
def test_bad_profile_fails_closed(change: str) -> None:
    with pytest.raises(ValueError):
        parse_contract(change)


def test_profile_check_detects_generated_drift(tmp_path: Path) -> None:
    from auths._profile_cli import check_profile, write_profile

    contract = parse_contract(PROFILE)
    (tmp_path / "profile.toml").write_text(PROFILE)
    write_profile(tmp_path, contract)
    assert check_profile(tmp_path / "profile.toml") == ()
    (tmp_path / "generated.py").write_text("not generated")
    assert check_profile(tmp_path / "profile.toml") == ("generated.py has drifted",)


def test_same_version_schema_edit_is_rejected(tmp_path: Path) -> None:
    from auths._profile_cli import write_profile

    (tmp_path / "profile.toml").write_text(PROFILE)
    write_profile(tmp_path, parse_contract(PROFILE))
    changed = PROFILE.replace('max_bytes = 32', 'max_bytes = 31')
    (tmp_path / "profile.toml").write_text(changed)
    difference = profile_diff(tmp_path / "profile.toml")
    assert difference["code"] == "profile.contract.version-required"
    assert "arguments.fields.value.maximum" in difference["changed_fields"]
    assert difference["action_identity_changed"] is True
    with pytest.raises(ValueError, match="without a version bump"):
        write_profile(tmp_path, parse_contract(changed))


def test_enum_variant_reorder_needs_version_bump(tmp_path: Path) -> None:
    from auths._profile_cli import write_profile

    (tmp_path / "profile.toml").write_text(PROFILE)
    write_profile(tmp_path, parse_contract(PROFILE))
    changed = PROFILE.replace('variants = ["open", "in_progress", "closed"]',
                              'variants = ["closed", "in_progress", "open"]')
    (tmp_path / "profile.toml").write_text(changed)
    diff = profile_diff(tmp_path / "profile.toml")
    assert "arguments.fields.status.variants" in diff["changed_fields"]
    assert next(item for item in diff["changes"] if item["path"] == "arguments.fields.status.variants") == {
        "path": "arguments.fields.status.variants",
        "before": ["open", "in_progress", "closed"],
        "after": ["closed", "in_progress", "open"],
    }
    assert diff["code"] == "profile.contract.version-required"
    with pytest.raises(ValueError, match="without a version bump"):
        write_profile(tmp_path, parse_contract(changed))

    bumped = changed.replace("version = 2", "version = 3")
    (tmp_path / "profile.toml").write_text(bumped)
    write_profile(tmp_path, parse_contract(bumped))
    assert profile_diff(tmp_path / "profile.toml")["status"] == "current"


def test_json_diagnostic_distinguishes_stale_generated_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import json

    from auths._profile_cli import main, write_profile

    (tmp_path / "profile.toml").write_text(PROFILE)
    write_profile(tmp_path, parse_contract(PROFILE))
    (tmp_path / "generated.py").write_text("stale")
    assert main(["profile", "check", str(tmp_path / "profile.toml"), "--json"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["diagnostic"]["code"] == "profile.generated.stale"


def test_production_doctor_fails_without_explicit_authority(tmp_path: Path) -> None:
    from auths._profile_cli import main, write_profile

    (tmp_path / "profile.toml").write_text(PROFILE)
    write_profile(tmp_path, parse_contract(PROFILE))
    assert main(["profile", "doctor", str(tmp_path / "profile.toml"), "--production"]) == 1
