"""Restricted, deterministic authoring for application-owned MCP profiles.

This CLI generates source; it never loads a provider credential or creates a
signer. Its deliberately small TOML subset is shared with the TypeScript CLI.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_IDENTITY = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,111}$")
_QUOTED = re.compile(r'^"([A-Za-z0-9_.:-]+)"$')
_INTEGER = re.compile(r"^(0|[1-9][0-9]{0,8})$")
_BOUND = 2**53 - 1


@dataclass(frozen=True)
class FieldSpec:
    name: str
    kind: str
    minimum: int | None = None
    maximum: int | None = None


@dataclass(frozen=True)
class ProfileContract:
    name: str
    version: int
    service: str
    tool: str
    command: str
    fields: tuple[FieldSpec, ...]

    @property
    def versioned_tool(self) -> str:
        return f"{self.tool}_v{self.version}"


def parse_contract(source: str) -> ProfileContract:
    """Parse only the bounded TOML subset the two packaged generators share."""
    if len(source.encode("utf-8")) > 16_384:
        raise ValueError("profile.toml exceeds 16 KiB")
    sections: dict[str, dict[str, str | int]] = {}
    current: str | None = None
    for original in source.splitlines():
        line = original.strip()
        if not line or line.startswith("#"):
            continue
        if line in ("[profile]", "[fields]"):
            current = line[1:-1]
            if current in sections:
                raise ValueError("duplicate profile section")
            sections[current] = {}
            continue
        if current is None or "=" not in line:
            raise ValueError("invalid profile.toml line")
        raw_key, raw_value = (part.strip() for part in line.split("=", 1))
        if not _KEY.fullmatch(raw_key) or raw_key in sections[current]:
            raise ValueError("invalid or duplicate profile key")
        quoted = _QUOTED.fullmatch(raw_value)
        if quoted:
            value: str | int = quoted.group(1)
        elif _INTEGER.fullmatch(raw_value):
            value = int(raw_value)
        else:
            raise ValueError("unsupported profile.toml value")
        sections[current][raw_key] = value
    if set(sections) != {"profile", "fields"}:
        raise ValueError("profile and fields sections are required")
    profile = sections["profile"]
    if not {"name", "version", "service", "tool"} <= set(profile) or set(profile) - {
        "name", "version", "service", "tool", "command"
    }:
        raise ValueError("profile identity fields are invalid")
    name, version, service, tool = (
        profile["name"], profile["version"], profile["service"], profile["tool"]
    )
    command = profile.get("command")
    if (
        not isinstance(name, str) or not _IDENTITY.fullmatch(name)
        or type(version) is not int or not 1 <= version <= 9999
        or not isinstance(service, str) or not _IDENTITY.fullmatch(service)
        or not isinstance(tool, str) or not _TOOL.fullmatch(tool)
        or len(f"{tool}_v{version}".encode("ascii")) > 128
    ):
        raise ValueError("profile identity or version is invalid")
    if command is None:
        command = "".join(part.capitalize() for part in re.split(r"[-_.]", name))
    if not isinstance(command, str) or not _KEY.fullmatch(command):
        raise ValueError("command type name is invalid")
    raw_fields = sections["fields"]
    if not 1 <= len(raw_fields) <= 32:
        raise ValueError("command field count is outside bounds")
    fields = tuple(_field(name, value) for name, value in raw_fields.items())
    return ProfileContract(name, version, service, tool, command, fields)


def _field(name: str, value: str | int) -> FieldSpec:
    if name in {"__proto__", "prototype", "constructor"} or not isinstance(value, str):
        raise ValueError("invalid command field")
    pieces = value.split(":")
    kind = pieces[0]
    if kind in {"boolean", "optional-boolean"} and len(pieces) == 1:
        return FieldSpec(name, kind)
    if kind not in {"string", "optional-string", "integer", "optional-integer"} or len(pieces) != 3:
        raise ValueError("unsupported command field schema")
    try:
        minimum, maximum = int(pieces[1]), int(pieces[2])
    except ValueError as error:
        raise ValueError("invalid command field bounds") from error
    if kind.endswith("string"):
        if not 0 <= minimum <= maximum <= 4096:
            raise ValueError("string byte bounds are invalid")
    elif not -_BOUND <= minimum <= maximum <= _BOUND:
        raise ValueError("integer bounds are invalid")
    return FieldSpec(name, kind, minimum, maximum)


def _python_type(field: FieldSpec) -> str:
    base = "str" if field.kind.endswith("string") else "int" if field.kind.endswith("integer") else "bool"
    return f"Optional[{base}]" if field.kind.startswith("optional-") else base


def _python_field(field: FieldSpec) -> str:
    if field.kind.endswith("string"):
        value = f"StringField(min_length={field.minimum}, max_length={field.maximum})"
    elif field.kind.endswith("integer"):
        value = f"IntegerField(minimum={field.minimum}, maximum={field.maximum})"
    else:
        value = "BooleanField()"
    return f"OptionalField({value})" if field.kind.startswith("optional-") else value


def render_generated(contract: ProfileContract) -> str:
    """Render a typed command and reusable exact-tool constructor."""
    annotations = "\n".join(f"    {field.name}: {_python_type(field)}" for field in contract.fields)
    schema = "\n".join(
        f'    "{field.name}": {_python_field(field)},' for field in contract.fields
    )
    return (
        '"""Generated by auths profile; edit profile.toml, then regenerate."""\n'
        "from __future__ import annotations\n\n"
        "from dataclasses import dataclass\n"
        "from typing import Optional, TypeVar\n\n"
        "from auths.self_hosted import (BooleanField, ExactMcpTool, IntegerField, "
        "OptionalField, StringField)\n\n"
        f'PROFILE_NAME = "{contract.name}"\n'
        f"PROFILE_VERSION = {contract.version}\n"
        f'TOOL_NAME = "{contract.versioned_tool}"\n\n'
        "@dataclass(frozen=True)\n"
        f"class {contract.command}:\n{annotations}\n\n"
        f"FIELDS = {{\n{schema}\n}}\n\n"
        "CommandT = TypeVar(\"CommandT\")\n\n"
        "def contract_for(command_type: type[CommandT]) -> ExactMcpTool[CommandT]:\n"
        f'    return ExactMcpTool(service="{contract.service}", name=TOOL_NAME, '
        "command_type=command_type, fields=FIELDS)\n\n"
        f"CONTRACT = contract_for({contract.command})\n"
    )


def _example(field: FieldSpec) -> str | int | bool | None:
    if field.kind.startswith("optional-"):
        return None
    if field.kind == "string":
        return "x" * (field.minimum if field.minimum is not None else 0)
    if field.kind == "integer":
        return field.minimum if field.minimum is not None else 0
    return False


def render_vectors(contract: ProfileContract) -> str:
    valid = {field.name: _example(field) for field in contract.fields}
    return json.dumps(
        {
            "schema": "auths.self-hosted-profile-vectors/1",
            "profile": contract.name,
            "version": contract.version,
            "service": contract.service,
            "tool": contract.versioned_tool,
            "valid_arguments_json": json.dumps(valid, sort_keys=True, separators=(",", ":")),
        },
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"


def write_profile(directory: Path, contract: ProfileContract) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "generated.py").write_text(render_generated(contract), encoding="utf-8")
    (directory / "vectors.json").write_text(render_vectors(contract), encoding="utf-8")


def check_profile(path: Path) -> tuple[str, ...]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16_384:
        raise ValueError("profile.toml must be a bounded regular file")
    contract = parse_contract(path.read_text(encoding="utf-8"))
    problems = []
    for name, expected in (
        ("generated.py", render_generated(contract)),
        ("vectors.json", render_vectors(contract)),
    ):
        target = path.parent / name
        if target.is_symlink() or not target.is_file() or target.read_text(encoding="utf-8") != expected:
            problems.append(f"{name} has drifted")
    return tuple(problems)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="auths")
    command = parser.add_subparsers(dest="command", required=True)
    profile = command.add_parser("profile")
    actions = profile.add_subparsers(dest="action", required=True)
    init = actions.add_parser("init")
    init.add_argument("--language", choices=("python",), required=True)
    init.add_argument("--name", required=True)
    init.add_argument("--directory", type=Path, default=Path("."))
    for name in ("generate", "check", "doctor"):
        action = actions.add_parser(name)
        action.add_argument("profile", type=Path, nargs="?", default=Path("profile.toml"))
        if name == "doctor":
            action.add_argument("--production", action="store_true")
            action.add_argument("--grant-file", type=Path)
            action.add_argument("--trust-file", type=Path)
            action.add_argument("--signer-adapter")
    args = parser.parse_args(argv)
    try:
        if args.action == "init":
            if not _IDENTITY.fullmatch(args.name):
                raise ValueError("profile name must be a bounded lowercase identifier")
            directory = args.directory
            if any((directory / name).exists() for name in ("profile.toml", "generated.py", "vectors.json")):
                raise ValueError("profile files already exist")
            source = (
                "[profile]\n"
                f'name = "{args.name}"\nversion = 1\n'
                f'service = "{args.name}"\ntool = "invoke"\n\n'
                '[fields]\nvalue = "string:1:256"\n'
            )
            contract = parse_contract(source)
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "profile.toml").write_text(source, encoding="utf-8")
            write_profile(directory, contract)
            print(f"created {directory / 'profile.toml'}; self-hosted, provider behavior unqualified")
        elif args.action == "generate":
            path: Path = args.profile
            contract = parse_contract(path.read_text(encoding="utf-8"))
            write_profile(path.parent, contract)
            print(f"generated {path.parent}; self-hosted, provider behavior unqualified")
        elif args.action == "check":
            problems = check_profile(args.profile)
            if problems:
                for problem in problems:
                    print(problem, file=sys.stderr)
                return 1
            print("profile current; self-hosted, provider behavior unqualified")
        else:
            problems = check_profile(args.profile)
            if problems:
                raise ValueError("; ".join(problems))
            print("contract: current; provider adapter: application-owned, unqualified")
            if args.production:
                from . import _native

                if not args.signer_adapter or not _IDENTITY.fullmatch(args.signer_adapter):
                    raise ValueError("production needs an explicit custody signer adapter identifier")
                if args.grant_file is None or args.trust_file is None:
                    raise ValueError("production needs separate --grant-file and --trust-file")
                for path, maximum in ((args.grant_file, 262_144), (args.trust_file, 262_144)):
                    if path.is_symlink() or not path.is_file() or not 1 <= path.stat().st_size <= maximum:
                        raise ValueError("production authority file is unavailable or outside bounds")
                _native.parse_signed("grant", args.grant_file.read_bytes())
                _native.parse_trusted_context(args.trust_file.read_bytes())
                if args.grant_file.resolve() == args.trust_file.resolve():
                    raise ValueError("grant and trusted context must use separate files")
                print("production inputs: structurally present; signer connectivity and trust provenance not checked")
            else:
                print("local testkit authority is development-only")
            print("profile doctor does not verify provider credentials or qualify adapter behavior")
    except (OSError, UnicodeError, ValueError) as error:
        print(f"auths profile: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
