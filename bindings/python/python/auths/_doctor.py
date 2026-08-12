from __future__ import annotations

import platform
import sys
from dataclasses import dataclass
from typing import Literal, Tuple

from . import _native

DoctorMode = Literal["development", "production", "unconfigured"]
DoctorState = Literal["in-memory", "file-backed", "durable", "unconfigured"]


@dataclass(frozen=True)
class DoctorReport:
    sdk_version: str
    runtime: str
    native_abi: int
    native_abi_compatible: bool
    semantic_subject: Literal["packaged-exact", "incompatible"]
    profiles: Tuple[str, ...]
    mode: DoctorMode
    state: DoctorState
    status: Literal["ready", "incompatible"]
    warnings: Tuple[str, ...]


def doctor(
    *, mode: DoctorMode = "unconfigured", state: DoctorState = "unconfigured"
) -> DoctorReport:
    abi = _native.native_abi_version()
    compatible = abi == 2
    return DoctorReport(
        sdk_version="1.0.0rc1",
        runtime=(
            f"CPython {sys.version_info.major}.{sys.version_info.minor} / "
            f"{_bounded(platform.system())} {_bounded(platform.machine())}"
        ),
        native_abi=abi,
        native_abi_compatible=compatible,
        semantic_subject="packaged-exact" if compatible else "incompatible",
        profiles=("mcp/1",),
        mode=mode,
        state=state,
        status="ready" if compatible else "incompatible",
        warnings=_warnings(mode, state),
    )


def render_doctor(report: DoctorReport) -> str:
    abi = (
        f"compatible (native/{report.native_abi})"
        if report.native_abi_compatible
        else f"incompatible (native/{report.native_abi})"
    )
    lines = (
        f"Auths SDK        {report.sdk_version}",
        f"Runtime          {report.runtime}",
        f"Native ABI       {abi}",
        f"Semantic subject {report.semantic_subject}",
        f"Profiles         {', '.join(report.profiles)}",
        f"Mode             {report.mode}",
        f"State            {report.state}",
        f"Status           {report.status} with {len(report.warnings)} warnings",
        *(f"Warning          {warning}" for warning in report.warnings),
    )
    return "\n".join(lines)


def _warnings(mode: DoctorMode, state: DoctorState) -> Tuple[str, ...]:
    warnings: list[str] = []
    if mode == "development":
        warnings.append("development custody and trust are not production")
    if mode == "unconfigured":
        warnings.append("application composition is not configured")
    if state == "in-memory":
        warnings.append("in-memory state is not production durable")
    if state == "file-backed":
        warnings.append("file-backed state is single-machine only")
    if state == "unconfigured":
        warnings.append("durable state is not configured")
    return tuple(warnings)


def _bounded(value: str) -> str:
    bounded = "".join(
        character if character.isalnum() or character in "._-" else "-"
        for character in value
    )
    return bounded[:64] or "unknown"
