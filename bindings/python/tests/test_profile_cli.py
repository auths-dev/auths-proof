"""The packaged profile tool emits an exact, version-bound operation."""

from __future__ import annotations

import json
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
ADVERSARIAL = json.loads((ROOT / "adversarial-boundary-v1.json").read_text())


@pytest.mark.parametrize("case", ADVERSARIAL["profileCases"], ids=lambda case: case["id"])
def test_adversarial_profile_source_decision(case: dict[str, object]) -> None:
    lines = [
        line.replace('name = "probe"', f'name = "{case["name"]}"')
        for line in ADVERSARIAL["profileBaseLines"]
    ]
    source = str(case["prefix"]) + str(case["lineEnding"]).join(lines) + str(case["lineEnding"])
    if case["decision"] == "reject":
        with pytest.raises(ValueError):
            parse_contract(source)
    else:
        assert parse_contract(source).command == case["command"]


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
    assert main(["check", str(tmp_path / "profile.toml"), "--json"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["diagnostic"]["code"] == "profile.generated.stale"


def test_production_doctor_fails_without_explicit_authority(tmp_path: Path) -> None:
    from auths._profile_cli import main, write_profile

    (tmp_path / "profile.toml").write_text(PROFILE)
    write_profile(tmp_path, parse_contract(PROFILE))
    assert main(["doctor", str(tmp_path / "profile.toml"), "--production"]) == 1


def test_first_edit_after_init_does_not_need_a_premature_version_bump(tmp_path: Path) -> None:
    from auths._profile_cli import main

    package = tmp_path / "local_demo"
    assert main(["init", "--language", "python", "--name", "local-demo",
                 "--directory", str(package)]) == 0
    assert not (package / "profile.lock.json").exists()
    source = (package / "profile.toml").read_text()
    (package / "profile.toml").write_text(source.replace("max_bytes = 256", "max_bytes = 32"))
    assert main(["generate", str(package / "profile.toml")]) == 0
    assert (package / "profile.lock.json").exists()


def test_diff_before_first_lock_explains_new_identity(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from auths._profile_cli import main

    package = tmp_path / "new_operation"
    assert main(["init", "--language", "python", "--name", "new-operation",
                 "--directory", str(package)]) == 0
    capsys.readouterr()
    assert main(["diff", str(package / "profile.toml")]) == 0
    output = capsys.readouterr().out
    assert "no prior generated lock; this is a new action identity" in output
    assert "no field changes" not in output


def test_local_profile_suite_cannot_skip_mandatory_cases(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import json

    from auths._profile_cli import main

    package = tmp_path / "local_suite_trial"
    assert main(["init", "--language", "python", "--name", "local-suite-trial",
                 "--directory", str(package)]) == 0
    assert main(["generate", str(package / "profile.toml")]) == 0
    (package / "conformance.py").write_text(
        "from auths.testkit import ConformanceReport, ConformanceMetadata\n"
        "async def run():\n"
        "    return ConformanceReport(ConformanceMetadata(\"self-hosted-provider-adapter/1\", "
        "\"1\", \"local\", \"now\", \"test-results-only-not-security-certification\"), True, ())\n"
    )
    assert main(["test", str(package / "profile.toml"),
                 "--suite", "local_suite_trial.conformance:run", "--json"]) == 1
    result = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert result["ok"] is False
    assert result["diagnostic"]["code"] == "profile.provider.adapter-test-failed"
    assert "mandatory cases" in result["diagnostic"]["message"]
