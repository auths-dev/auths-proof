from __future__ import annotations

import os
from pathlib import Path

from auths_incident_agent import sdk


ROOT = Path(os.environ.get("AUTHS_REPO_ROOT", Path(__file__).resolve().parents[4]))


def test_cross_sdk_fixture_python_projection() -> None:
    fixture = sdk.portable_fixture(ROOT)
    assert fixture["python"]["kind"] == "denied"
    assert fixture["python"]["stage"] == "principal-control"
    assert fixture["python"]["code"] == "verifier-configuration-mismatch"


def test_mutation_is_denied_by_native_verifier() -> None:
    result = sdk.mutation_attack(ROOT)
    assert result["blocked"] is True
    assert result["evidence"]["kind"] == "denied"


def test_replay_and_runtime_transitions() -> None:
    assert sdk.replay_attack()["evidence"]["second"] == "exact-replay"
    assert sdk.expired_attack()["blocked"] is True
    assert sdk.remote_failure_attack("unknown")["evidence"]["state"] == "outcome-unknown"


def test_rotation_recipe() -> None:
    result = sdk.rotation_attack(
        "key:sha256:qogx823wE-Cfoq_WXwDS1D6S8jMOhJssOpaNRZOJCKs",
        "key:sha256:MPL4hHxgoCRRtbEjYAedm50CmSM11XgLojSwwYeRi1E",
    )
    assert result["evidence"]["previous"]["state"] == "superseded"
    assert result["evidence"]["current"]["state"] == "active"


def test_failure_matrix() -> None:
    assert sdk.remote_failure_attack("before")["evidence"]["state"] == "released"
    assert sdk.remote_failure_attack("after")["evidence"]["state"] == "committed"
    assert sdk.remote_failure_attack("unknown")["evidence"]["state"] == "outcome-unknown"
