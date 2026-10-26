"""Recompute the private provider/task join for Jules's owner activity view.

The optional manifest stays in the owner-only task directory. It names pinned
demo_co observations; it is never itself accepted as an effect verdict.
"""

from __future__ import annotations

from pathlib import Path

from .demo_co_contract import ContractRejected
from .google_create_negative_handoff import load_v4_final_pins
from .google_populate_failure_handoff import HEX64
from .google_populate_provider_v2_handoff import (
    ProviderV2SourcePins, validate_populate_provider_final_v2,
)
from .google_populate_provider_v2_join import (
    _PREFLIGHT, _private_json, join_populate_provider_final_v2,
)


MANIFEST_NAME = "provider-v2-evidence.json"
_OBSERVATIONS = ("setup", "inventory", "precreate", "blank", "final")


def _absolute_path(value: object) -> Path:
    if (type(value) is not str or not 1 <= len(value) <= 4096
            or not Path(value).is_absolute() or Path(value).is_symlink()):
        raise ContractRejected("provider v2 evidence path is invalid")
    return Path(value)


def _observation(manifest: dict, name: str) -> tuple[Path, str]:
    pin = manifest.get(name)
    if (type(pin) is not dict or set(pin) != {"path", "sha256"}
            or type(pin["sha256"]) is not str
            or HEX64.fullmatch(pin["sha256"]) is None):
        raise ContractRejected("provider v2 observation pin is invalid")
    return _absolute_path(pin["path"]), pin["sha256"]


def owner_provider_v2_effect(task_dir: Path, activity: dict,
                             lineage: dict) -> dict:
    """Verify producer bytes and task lineage, returning only redacted fields."""
    manifest, _ = _private_json(task_dir / MANIFEST_NAME, 16_384)
    if (set(manifest) != {"schema", "task_id", "source_v4_paths",
                          "v4_pins_path", "source", "preflight_name",
                          *_OBSERVATIONS}
            or manifest["schema"] != "auths.ap071-provider-v2-evidence/1"
            or manifest["task_id"] != task_dir.name
            or type(manifest["source_v4_paths"]) is not list
            or len(manifest["source_v4_paths"]) != 3
            or type(manifest["preflight_name"]) is not str
            or _PREFLIGHT.fullmatch(manifest["preflight_name"]) is None):
        raise ContractRejected("provider v2 evidence manifest is invalid")
    source = manifest["source"]
    if (type(source) is not dict
            or set(source) != {"document_id", "raw_sha256", "raw_byte_count"}):
        raise ContractRejected("provider v2 source pin is invalid")
    source_pins = ProviderV2SourcePins(**source)
    source_pins.validate()
    source_v4 = tuple(_absolute_path(path)
                      for path in manifest["source_v4_paths"])
    v4 = load_v4_final_pins(_absolute_path(manifest["v4_pins_path"]))
    observations = {name: _observation(manifest, name)
                    for name in _OBSERVATIONS}
    plan, _ = _private_json(task_dir / "effect-plan.json", 64_000)
    if type(plan.get("initial_text")) is not str:
        raise ContractRejected("provider v2 exact content is unavailable")
    provider = validate_populate_provider_final_v2(
        source_v4,
        *observations["setup"],
        *observations["inventory"],
        *observations["precreate"],
        *observations["blank"],
        *observations["final"],
        v4, expected_text=plan["initial_text"], source=source_pins,
    )
    return join_populate_provider_final_v2(
        task_dir, task_dir / manifest["preflight_name"],
        activity, lineage, provider,
    )
