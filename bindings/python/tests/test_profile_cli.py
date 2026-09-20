"""The packaged profile tool emits an exact, version-bound operation."""

from __future__ import annotations

from pathlib import Path

import pytest

from auths._profile_cli import parse_contract, render_generated, render_vectors


PROFILE = """[profile]
name = "example-set-value"
version = 1
service = "example-service"
tool = "set_value"

[fields]
value = "string:1:32"
enabled = "boolean"
retry_count = "optional-integer:0:3"
"""


def test_generated_profile_binds_version_and_closed_schema() -> None:
    contract = parse_contract(PROFILE)
    generated = render_generated(contract)
    assert 'TOOL_NAME = "set_value_v1"' in generated
    assert "class ExampleSetValue:" in generated
    assert "retry_count: Optional[int]" in generated
    assert '"retry_count": OptionalField(IntegerField(minimum=0, maximum=3))' in generated
    assert '"tool":"set_value_v1"' in render_vectors(contract)


def test_language_neutral_vector_fixture_is_exact() -> None:
    root = Path(__file__).parents[2] / "fixtures" / "self-hosted-profile"
    assert render_vectors(parse_contract((root / "profile.toml").read_text())) == (
        root / "vectors.json"
    ).read_text()


@pytest.mark.parametrize(
    "change",
    [
        PROFILE.replace('value = "string:1:32"', 'value = "string:1:32"\nvalue = "string:1:32"'),
        PROFILE.replace('version = 1', 'version = 0'),
        PROFILE.replace('value = "string:1:32"', 'value = "string:0:99999"'),
        PROFILE.replace('enabled = "boolean"', 'enabled = "object"'),
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


def test_production_doctor_fails_without_explicit_authority(tmp_path: Path) -> None:
    from auths._profile_cli import main, write_profile

    (tmp_path / "profile.toml").write_text(PROFILE)
    write_profile(tmp_path, parse_contract(PROFILE))
    assert main(["profile", "doctor", str(tmp_path / "profile.toml"), "--production"]) == 1
