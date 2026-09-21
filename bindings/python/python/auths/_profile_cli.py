"""Bounded source generator for application-owned exact MCP contracts.

The profile file is declarative. This command never loads credentials or
creates authority; provider behavior stays in the consumer repository.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_IDENTITY = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,111}$")
_QUOTED = re.compile(r'^"([A-Za-z0-9_.:-]+)"$')
_INTEGER = re.compile(r"^-?(0|[1-9][0-9]{0,15})$")
_SAFE_INTEGER = 2**53 - 1
_RESERVED = {"__proto__", "prototype", "constructor"}


@dataclass(frozen=True)
class FieldSpec:
    name: str
    kind: str
    minimum: int | None = None
    maximum: int | None = None
    fields: tuple[FieldSpec, ...] = ()
    inner: FieldSpec | None = None
    variants: tuple[str, ...] = ()


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
    """Parse the documented bounded TOML subset, rejecting unknown tables."""
    if len(source.encode("utf-8")) > 16_384:
        raise ValueError("profile.toml exceeds 16 KiB")
    tables: dict[str, dict[str, str | int | tuple[str, ...]]] = {}
    current: str | None = None
    for original in source.splitlines():
        line = original.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            if current in tables or not current or any(
                not _KEY.fullmatch(piece) for piece in current.split(".")
            ):
                raise ValueError("invalid or duplicate profile table")
            tables[current] = {}
            continue
        if current is None or "=" not in line:
            raise ValueError("invalid profile.toml line")
        raw_key, raw_value = (part.strip() for part in line.split("=", 1))
        if not _KEY.fullmatch(raw_key) or raw_key in _RESERVED or raw_key in tables[current]:
            raise ValueError("invalid or duplicate profile key")
        quoted = _QUOTED.fullmatch(raw_value)
        if raw_key == "variants" and raw_value.startswith("["):
            if not re.fullmatch(r'\[\s*(?:"[A-Za-z0-9_.:-]+"(?:\s*,\s*"[A-Za-z0-9_.:-]+")*)?\s*\]', raw_value):
                raise ValueError("invalid single-line enum variants")
            value: str | int | tuple[str, ...] = tuple(re.findall(r'"([A-Za-z0-9_.:-]+)"', raw_value))
        elif quoted:
            value = quoted.group(1)
        elif _INTEGER.fullmatch(raw_value):
            value = int(raw_value)
        else:
            raise ValueError("unsupported profile.toml value")
        tables[current][raw_key] = value
    profile = tables.get("profile")
    if profile is None or set(profile) - {"name", "version", "service", "tool", "command"} or not {
        "name", "version", "service", "tool"
    } <= set(profile):
        raise ValueError("profile identity fields are invalid")
    name, version, service, tool = (
        profile["name"], profile["version"], profile["service"], profile["tool"]
    )
    if (
        not isinstance(name, str) or not _IDENTITY.fullmatch(name)
        or type(version) is not int or not 1 <= version <= 9999
        or not isinstance(service, str) or not _IDENTITY.fullmatch(service)
        or not isinstance(tool, str) or not _TOOL.fullmatch(tool)
        or len(f"{tool}_v{version}".encode("ascii")) > 128
    ):
        raise ValueError("profile identity or version is invalid")
    command = profile.get("command")
    if command is None:
        command = "".join(part.capitalize() for part in re.split(r"[-_.]", name))
    if not isinstance(command, str) or not _KEY.fullmatch(command) or command in _RESERVED:
        raise ValueError("command type name is invalid")
    used = {"profile"}
    root = _node(tables, used, "arguments", "arguments", 1)
    if root.kind != "object" or not root.fields or set(tables) != used:
        raise ValueError("root arguments must be a closed object with no unknown tables")
    if _field_count(root) > 32 or _max_depth(root) > 4:
        raise ValueError("command schema exceeds field or depth bounds")
    if _maximum_json_bytes(root) > 4096:
        raise ValueError("worst-case canonical arguments exceed 4 KiB")
    return ProfileContract(name, version, service, tool, command, root.fields)


def _node(
    tables: dict[str, dict[str, str | int | tuple[str, ...]]], used: set[str], path: str,
    name: str, depth: int,
) -> FieldSpec:
    table = tables.get(path)
    if table is None or path in used or depth > 4:
        raise ValueError(f"missing, duplicate, or over-deep schema node: {path}")
    used.add(path)
    kind = table.get("type")
    if not isinstance(kind, str):
        raise ValueError(f"schema node type is invalid: {path}")
    if kind in {"string", "bytes", "integer"}:
        keys = {"type", "minimum", "maximum"} if kind == "integer" else {
            "type", "min_bytes", "max_bytes"
        }
        if set(table) != keys:
            raise ValueError(f"schema bounds are incomplete: {path}")
        minimum = table["minimum"] if kind == "integer" else table["min_bytes"]
        maximum = table["maximum"] if kind == "integer" else table["max_bytes"]
        if type(minimum) is not int or type(maximum) is not int or minimum > maximum:
            raise ValueError(f"invalid schema bounds: {path}")
        if kind == "string" and not 0 <= minimum <= maximum <= 4096:
            raise ValueError(f"invalid UTF-8 byte bounds: {path}")
        if kind == "bytes" and not 0 <= minimum <= maximum <= 3072:
            raise ValueError(f"invalid bytes bounds: {path}")
        if kind == "integer" and not -_SAFE_INTEGER <= minimum <= maximum <= _SAFE_INTEGER:
            raise ValueError(f"invalid safe-integer bounds: {path}")
        return FieldSpec(name, kind, minimum, maximum)
    if kind == "boolean":
        if set(table) != {"type"}:
            raise ValueError(f"unknown boolean schema key: {path}")
        return FieldSpec(name, "boolean")
    if kind == "enum":
        variants = table.get("variants")
        if (
            set(table) != {"type", "variants"}
            or type(variants) is not tuple
            or not 1 <= len(variants) <= 32
            or len(set(variants)) != len(variants)
            or any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", item) for item in variants)
        ):
            raise ValueError(f"enum variants are invalid: {path}")
        return FieldSpec(name, "enum", variants=variants)
    if kind == "object":
        if set(table) != {"type"}:
            raise ValueError(f"unknown object schema key: {path}")
        prefix = f"{path}.fields."
        names = [
            candidate[len(prefix):] for candidate in tables
            if candidate.startswith(prefix) and "." not in candidate[len(prefix):]
        ]
        if not 1 <= len(names) <= 32 or any(item in _RESERVED for item in names):
            raise ValueError(f"object field count or name is invalid: {path}")
        fields = tuple(
            _node(tables, used, f"{prefix}{item}", item, depth + 1)
            for item in names
        )
        return FieldSpec(name, "object", fields=fields)
    if kind == "array":
        if set(table) != {"type", "min_items", "max_items"}:
            raise ValueError(f"array bounds are incomplete: {path}")
        minimum, maximum = table["min_items"], table["max_items"]
        if type(minimum) is not int or type(maximum) is not int or not 0 <= minimum <= maximum <= 32:
            raise ValueError(f"invalid array bounds: {path}")
        inner = _node(tables, used, f"{path}.items", "items", depth + 1)
        if inner.kind == "nullable":
            raise ValueError("array items cannot be nullable")
        return FieldSpec(name, "array", minimum, maximum, inner=inner)
    if kind == "nullable":
        if set(table) != {"type"}:
            raise ValueError(f"unknown nullable schema key: {path}")
        inner = _node(tables, used, f"{path}.value", "value", depth)
        if inner.kind == "nullable":
            raise ValueError("nested nullable fields are unsupported")
        return FieldSpec(name, "nullable", inner=inner)
    raise ValueError(f"unsupported command field schema: {path}")


def _field_count(node: FieldSpec) -> int:
    if node.kind == "object":
        return sum(_field_count(item) for item in node.fields)
    if node.inner is not None:
        return _field_count(node.inner)
    return 1


def _max_depth(node: FieldSpec) -> int:
    if node.kind == "object":
        return 1 + max((_max_depth(item) for item in node.fields), default=0)
    if node.kind == "array":
        return 1 + _max_depth(node.inner) if node.inner is not None else 1
    if node.inner is not None:
        return _max_depth(node.inner)
    return 0


def _maximum_json_bytes(node: FieldSpec) -> int:
    if node.kind == "object":
        return 2 + sum(
            2 + len(item.name) + 1 + _maximum_json_bytes(item) for item in node.fields
        ) + max(0, len(node.fields) - 1)
    if node.kind == "array":
        count = node.maximum or 0
        return 2 + count * _maximum_json_bytes(node.inner) + max(0, count - 1) if node.inner else 2
    if node.kind == "nullable":
        return max(4, _maximum_json_bytes(node.inner)) if node.inner else 4
    if node.kind == "string":
        return 2 + 6 * (node.maximum or 0)
    if node.kind == "bytes":
        return 2 + 4 * ((node.maximum or 0) + 2) // 3
    if node.kind == "integer":
        return max(len(str(node.minimum)), len(str(node.maximum)))
    if node.kind == "enum":
        return 2 + max(len(item) for item in node.variants)
    return 5


def _node_json(node: FieldSpec) -> dict[str, object]:
    if node.kind == "enum":
        return {"type": "enum", "variants": list(node.variants)}
    value: dict[str, object] = {"kind": node.kind}
    if node.minimum is not None:
        value["minimum"] = node.minimum
    if node.maximum is not None:
        value["maximum"] = node.maximum
    if node.kind == "object":
        value["fields"] = {item.name: _node_json(item) for item in node.fields}
    if node.inner is not None:
        value["inner"] = _node_json(node.inner)
    return value


def _stable_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _schema_digest(contract: ProfileContract) -> str:
    root = FieldSpec("arguments", "object", fields=contract.fields)
    return hashlib.sha256(_stable_json(_node_json(root)).encode("utf-8")).hexdigest()


def _class_name(contract: ProfileContract, path: tuple[str, ...]) -> str:
    return contract.command + "".join(part.capitalize() for name in path for part in name.split("_"))


def _object_nodes(node: FieldSpec, path: tuple[str, ...]) -> list[tuple[tuple[str, ...], FieldSpec]]:
    found: list[tuple[tuple[str, ...], FieldSpec]] = []
    if node.kind == "object":
        for child in node.fields:
            found.extend(_object_nodes(child, path + (child.name,)))
        found.append((path, node))
    elif node.inner is not None:
        found.extend(_object_nodes(node.inner, path))
    return found


def _python_type(contract: ProfileContract, node: FieldSpec, path: tuple[str, ...]) -> str:
    if node.kind == "nullable" and node.inner is not None:
        return f"Optional[{_python_type(contract, node.inner, path)}]"
    if node.kind == "array" and node.inner is not None:
        return f"tuple[{_python_type(contract, node.inner, path)}, ...]"
    if node.kind == "object":
        return _class_name(contract, path)
    if node.kind == "enum":
        return "Literal[" + ", ".join(json.dumps(item) for item in node.variants) + "]"
    return {"string": "str", "bytes": "bytes", "integer": "int", "boolean": "bool"}[node.kind]


def _field_source(contract: ProfileContract, node: FieldSpec, path: tuple[str, ...]) -> str:
    if node.kind == "enum":
        return f"EnumField({node.variants!r})"
    if node.kind == "string":
        return f"StringField(min_length={node.minimum}, max_length={node.maximum})"
    if node.kind == "bytes":
        return f"BytesField(min_length={node.minimum}, max_length={node.maximum})"
    if node.kind == "integer":
        return f"IntegerField(minimum={node.minimum}, maximum={node.maximum})"
    if node.kind == "boolean":
        return "BooleanField()"
    if node.kind == "nullable" and node.inner is not None:
        return f"OptionalField({_field_source(contract, node.inner, path)})"
    if node.kind == "array" and node.inner is not None:
        return (
            f"ArrayField({_field_source(contract, node.inner, path)}, "
            f"min_items={node.minimum}, max_items={node.maximum})"
        )
    if node.kind == "object":
        fields = ", ".join(
            f'{json.dumps(child.name)}: {_field_source(contract, child, path + (child.name,))}'
            for child in node.fields
        )
        return f"ObjectField({_class_name(contract, path)}, {{{fields}}})"
    raise ValueError("unsupported field source")


def _used_classes(node: FieldSpec) -> set[str]:
    own = {
        "string": "StringField", "bytes": "BytesField", "integer": "IntegerField",
        "boolean": "BooleanField", "nullable": "OptionalField",
        "array": "ArrayField", "object": "ObjectField", "enum": "EnumField",
    }[node.kind]
    found = {own}
    for child in node.fields:
        found.update(_used_classes(child))
    if node.inner is not None:
        found.update(_used_classes(node.inner))
    return found


def render_generated(contract: ProfileContract) -> str:
    """Render immutable, schema-matching Python types and exact tool."""
    root = FieldSpec("arguments", "object", fields=contract.fields)
    nodes = _object_nodes(root, ())
    names = [_class_name(contract, path) for path, _ in nodes]
    if len(names) != len(set(names)):
        raise ValueError("generated nested type names collide")
    imports = {"ExactMcpTool"}
    for field in contract.fields:
        imports.update(_used_classes(field))
    typing_imports = {"TypeVar"}
    if "OptionalField" in imports:
        typing_imports.add("Optional")
    if "EnumField" in imports:
        typing_imports.add("Literal")
    typing_names = ", ".join(sorted(typing_imports))
    lines = [
        '"""Generated by auths-profile; edit profile.toml, then regenerate."""',
        "from __future__ import annotations", "", "from dataclasses import dataclass",
        f"from typing import {typing_names}", "", "from auths.self_hosted import (",
        *(f"    {name}," for name in sorted(imports)), ")", "",
        f'PROFILE_NAME = "{contract.name}"', f"PROFILE_VERSION = {contract.version}",
        f'TOOL_NAME = "{contract.versioned_tool}"', f'SCHEMA_DIGEST = "{_schema_digest(contract)}"', "",
    ]
    for path, node in nodes:
        lines.extend(["", "@dataclass(frozen=True)", f"class {_class_name(contract, path)}:"])
        for child in node.fields:
            annotation = _python_type(contract, child, path + (child.name,))
            suffix = "  # noqa: UP045" if "Optional[" in annotation else ""
            lines.append(f"    {child.name}: {annotation}{suffix}")
        lines.extend(["", ""])
    lines.extend([
        "FIELDS = {",
        *(f'    "{field.name}": {_field_source(contract, field, (field.name,))},' for field in contract.fields),
        "}", "", 'CommandT = TypeVar("CommandT")', "", "",
        "def contract_for(command_type: type[CommandT]) -> ExactMcpTool[CommandT]:",
        "    return ExactMcpTool(", f'        service="{contract.service}",',
        "        name=TOOL_NAME,", "        command_type=command_type,", "        fields=FIELDS,",
        "    )", "", "", f"CONTRACT = contract_for({contract.command})", "",
    ])
    return "\n".join(lines)


def _example(node: FieldSpec) -> object:
    if node.kind == "enum":
        return node.variants[0]
    if node.kind == "nullable":
        return None
    if node.kind == "object":
        return {field.name: _example(field) for field in node.fields}
    if node.kind == "array":
        return [_example(node.inner) for _ in range(node.minimum or 0)] if node.inner is not None else []
    if node.kind == "bytes":
        return base64.urlsafe_b64encode(bytes(node.minimum or 0)).rstrip(b"=").decode("ascii")
    if node.kind == "string":
        return "x" * (node.minimum or 0)
    if node.kind == "integer":
        return node.minimum
    return False


def render_vectors(contract: ProfileContract) -> str:
    valid = {field.name: _example(field) for field in contract.fields}
    return _stable_json({
        "schema": "auths.self-hosted-profile-vectors/2",
        "profile": contract.name,
        "version": contract.version,
        "service": contract.service,
        "tool": contract.versioned_tool,
        "schema_digest": _schema_digest(contract),
        "valid_arguments_json": _stable_json(valid),
    }) + "\n"


def render_lock(contract: ProfileContract) -> str:
    return _stable_json({
        "schema": "auths.self-hosted-profile-lock/1",
        "profile": contract.name,
        "version": contract.version,
        "service": contract.service,
        "tool": contract.versioned_tool,
        "schema_digest": _schema_digest(contract),
        "command_schema": _node_json(FieldSpec("arguments", "object", fields=contract.fields)),
        "generator_format": 2,
    }) + "\n"


def _schema_changes(before: object, after: object, path: str = "arguments") -> list[str]:
    if before == after:
        return []
    if isinstance(before, dict) and isinstance(after, dict):
        before_fields = cast(dict[str, object], before)
        after_fields = cast(dict[str, object], after)
        changes: list[str] = []
        for key in sorted(before_fields.keys() | after_fields.keys()):
            changes.extend(_schema_changes(before_fields.get(key), after_fields.get(key), f"{path}.{key}"))
        return changes
    return [path]


def _schema_at(schema: object, path: str) -> object:
    for component in path.split(".")[1:]:
        if not isinstance(schema, dict):
            return None
        schema = cast(dict[str, object], schema).get(component)
    return schema


def profile_diff(path: Path) -> dict[str, object]:
    """Compare source to the last generated lock without changing either file."""
    contract = parse_contract(_source_at(path))
    target = path.parent / "profile.lock.json"
    current = cast(dict[str, object], json.loads(render_lock(contract)))
    if target.is_symlink():
        raise ValueError("profile lock cannot be a symlink")
    if not target.exists():
        return {"status": "new", "stage": "contract", "code": "profile.contract.new",
                "changed_fields": [], "changes": [], "action_identity_changed": True,
                "next_action": "Run profile generate."}
    try:
        old = cast(object, json.loads(target.read_text(encoding="utf-8")))
    except (OSError, ValueError) as error:
        raise ValueError("profile lock is invalid") from error
    if not isinstance(old, dict):
        raise ValueError("profile lock is invalid")
    old = cast(dict[str, object], old)
    if old.get("schema") != "auths.self-hosted-profile-lock/1":
        raise ValueError("profile lock is invalid")
    changed = _schema_changes(old.get("command_schema"), current["command_schema"])
    details = [
        {"path": item, "before": _schema_at(old.get("command_schema"), item),
         "after": _schema_at(current["command_schema"], item)}
        for item in changed[:64]
    ]
    identity_changed = any(old.get(key) != current[key] for key in ("service", "tool", "version"))
    same_version_drift = old.get("version") == contract.version and old != current
    status = "version-required" if same_version_drift else "changed" if old != current else "current"
    return {
        "status": status, "stage": "contract",
        "code": f"profile.contract.{status}",
        "old_version": old.get("version"), "new_version": contract.version,
        "changed_fields": changed[:64], "changes": details,
        "action_identity_changed": identity_changed or bool(changed),
        "next_action": (
            "Increase profile.version before generation." if same_version_drift
            else "Run profile generate and review new proof identity." if old != current
            else "No version change required."
        ),
    }


def render_adapter(contract: ProfileContract) -> str:
    return (
        '"""Application-owned provider mapping; Auths does not qualify these effects."""\n'
        "from __future__ import annotations\n\n"
        "from auths.execution import Observation, ProviderOutcome\n\n"
        f"from .generated import {contract.command}\n\n\n"
        "class ApplicationAdapter:\n"
        "    def credential(self) -> str:\n"
        "        # Load the app's existing provider token only after Auths claims the attempt.\n"
        '        raise NotImplementedError("supply an application-owned credential")\n\n'
        f"    async def invoke(self, command: {contract.command}, credential: str) -> ProviderOutcome[str]:\n"
        "        # Derive one closed provider write from command. Timeouts are unknown.\n"
        '        raise NotImplementedError("map the exact command to one provider write")\n\n'
        f"    async def observe(self, command: {contract.command}) -> Observation:\n"
        "        # Read-only reconciliation; never repeat invoke here.\n"
        '        raise NotImplementedError("read back the provider effect")\n'
    )


def render_run(contract: ProfileContract) -> str:
    return (
        '"""Exact local execution order: verify, claim, credential, provider."""\n'
        "from __future__ import annotations\n\n"
        "from auths.attempts import AttemptStore\n"
        "from auths.execution import RunResult, run_once\n\n"
        "from .adapter import ApplicationAdapter\n"
        f"from .generated import CONTRACT, {contract.command}\n\n\n"
        "async def execute(\n"
        "    *, proof: bytes, action: bytes, trusted_context: bytes,\n"
        "    attempts: AttemptStore, operation_key: str,\n"
        f"    expected_command: {contract.command}, adapter: ApplicationAdapter,\n"
        f") -> RunResult[{contract.command}, str]:\n"
        "    return await run_once(\n"
        "        contract=CONTRACT, proof=proof, action=action,\n"
        "        trusted_context=trusted_context, attempts=attempts,\n"
        "        operation_key=operation_key, expected_command=expected_command,\n"
        "        adapter=adapter,\n"
        "    )\n"
    )


def render_conformance(contract: ProfileContract) -> str:
    return (
        '"""Wire the real adapter to a synthetic provider, then run local conformance."""\n'
        "from __future__ import annotations\n\n"
        "import json\n"
        "from pathlib import Path\n\n"
        "from auths.testkit import ScriptedProvider, run_self_hosted_adapter_conformance\n\n"
        "from .generated import CONTRACT\n\n\n"
        "def adapter_factory(provider: ScriptedProvider):\n"
        "    # Map provider.write/read to your adapter's application-owned port.\n"
        '    raise NotImplementedError("wire a fake provider to the adapter")\n\n\n'
        "async def run():\n"
        '    vectors = json.loads(Path(__file__).with_name("vectors.json").read_text())\n'
        '    command = CONTRACT.validate_arguments(json.loads(vectors["valid_arguments_json"]))\n'
        "    return await run_self_hosted_adapter_conformance(\n"
        "        contract=CONTRACT, command=command, adapter_factory=adapter_factory,\n"
        "    )\n"
    )


def _source_at(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16_384:
        raise ValueError("profile.toml must be a bounded regular file")
    return path.read_text(encoding="utf-8")


def _lock_state(directory: Path, contract: ProfileContract) -> None:
    target = directory / "profile.lock.json"
    if target.is_symlink():
        raise ValueError("profile lock cannot be a symlink")
    if not target.exists():
        return
    try:
        old = cast(object, json.loads(target.read_text(encoding="utf-8")))
    except (OSError, ValueError) as error:
        raise ValueError("profile lock is invalid") from error
    if not isinstance(old, dict):
        raise ValueError("profile lock is invalid")
    old = cast(dict[str, object], old)
    if old.get("schema") != "auths.self-hosted-profile-lock/1":
        raise ValueError("profile lock is invalid")
    new = cast(dict[str, object], json.loads(render_lock(contract)))
    if old.get("version") == contract.version and old != new:
        raise ValueError("profile identity or schema changed without a version bump")
    old_version = old.get("version")
    if type(old_version) is not int or old_version > contract.version:
        raise ValueError("profile version cannot move backward")


def write_profile(directory: Path, contract: ProfileContract, *, seal: bool = True) -> None:
    if directory.is_symlink():
        raise ValueError("profile directory cannot be a symlink")
    directory.mkdir(parents=True, exist_ok=True)
    if seal:
        _lock_state(directory, contract)
    generated = [
        ("generated.py", render_generated(contract)),
        ("vectors.json", render_vectors(contract)),
    ]
    if seal:
        generated.append(("profile.lock.json", render_lock(contract)))
    for name, contents in generated:
        target = directory / name
        if target.is_symlink():
            raise ValueError("generated profile target cannot be a symlink")
        target.write_text(contents, encoding="utf-8")


def check_profile(path: Path) -> tuple[str, ...]:
    contract = parse_contract(_source_at(path))
    problems: list[str] = []
    for name, expected in (
        ("generated.py", render_generated(contract)),
        ("vectors.json", render_vectors(contract)),
        ("profile.lock.json", render_lock(contract)),
    ):
        target = path.parent / name
        if target.is_symlink() or not target.is_file() or target.read_text(encoding="utf-8") != expected:
            problems.append(f"{name} has drifted")
    return tuple(problems)


def _main_text(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="auths-profile")
    actions = parser.add_subparsers(dest="action", required=True)
    init = actions.add_parser("init")
    init.add_argument("--language", choices=("python",), required=True)
    init.add_argument("--name", required=True)
    init.add_argument("--directory", type=Path, default=Path("."))
    for name in ("generate", "check", "diff", "doctor", "test"):
        action = actions.add_parser(name)
        action.add_argument("profile", type=Path, nargs="?", default=Path("profile.toml"))
        if name == "test":
            action.add_argument("--suite", required=True)
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
            if any((directory / name).exists() or (directory / name).is_symlink() for name in (
                "profile.toml", "generated.py", "vectors.json", "profile.lock.json",
                "adapter.py", "run.py", "conformance.py"
            )):
                raise ValueError("profile files already exist")
            source = (
                "[profile]\n" f'name = "{args.name}"\nversion = 1\n'
                f'service = "{args.name}"\ntool = "invoke"\n\n'
                '[arguments]\ntype = "object"\n\n'
                '[arguments.fields.value]\ntype = "string"\nmin_bytes = 1\nmax_bytes = 256\n'
            )
            contract = parse_contract(source)
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "profile.toml").write_text(source, encoding="utf-8")
            write_profile(directory, contract, seal=False)
            for name, contents in (
                ("adapter.py", render_adapter(contract)),
                ("run.py", render_run(contract)),
                ("conformance.py", render_conformance(contract)),
            ):
                (directory / name).write_text(contents, encoding="utf-8")
            package = directory / "__init__.py"
            if not package.exists():
                package.write_text('"""Application-owned exact Auths operation."""\n', encoding="utf-8")
            print(f"created {directory / 'profile.toml'}; edit schema, then run profile generate; self-hosted, provider behavior unqualified")
        elif args.action == "generate":
            path: Path = args.profile
            write_profile(path.parent, parse_contract(_source_at(path)))
            print(f"generated {path.parent}; self-hosted, provider behavior unqualified")
        elif args.action == "check":
            problems = check_profile(args.profile)
            if problems:
                for problem in problems:
                    print(problem, file=sys.stderr)
                return 1
            print("profile current; self-hosted, provider behavior unqualified")
        elif args.action == "diff":
            result = profile_diff(args.profile)
            print(result["code"])
            changes = result.get("changes")
            if not isinstance(changes, list):
                raise ValueError("profile diff changes are invalid")
            for change in changes:
                if not isinstance(change, dict):
                    raise ValueError("profile diff change is invalid")
                fields = cast(dict[str, object], change)
                print(f"{fields['path']}: {_stable_json(fields['before'])} -> {_stable_json(fields['after'])}")
            if not changes:
                print("no field changes")
            print(f"action identity changed: {str(result['action_identity_changed']).lower()}")
            print(result["next_action"])
        elif args.action == "test":
            import asyncio
            import importlib

            problems = check_profile(args.profile)
            if problems:
                raise ValueError("; ".join(problems))
            module_name, separator, function_name = args.suite.partition(":")
            if not separator or not module_name or not function_name:
                raise ValueError("--suite must name a module:function test entry point")
            package = args.profile.resolve().parent
            source_root = str(package.parent)
            local_suite = module_name.startswith(f"{package.name}.") and (package / "__init__.py").is_file()
            if local_suite:
                sys.path.insert(0, source_root)
            try:
                function = getattr(importlib.import_module(module_name), function_name)
                report = asyncio.run(function())
            finally:
                if local_suite:
                    sys.path.remove(source_root)
            from .testkit import ConformanceReport
            if not isinstance(report, ConformanceReport) or report.metadata.suite != "self-hosted-provider-adapter/1":
                raise ValueError("adapter suite returned an invalid conformance report")
            for case in report.cases:
                print(f"{case.status.upper()} {case.id}")
            print("local adapter tests only; provider behavior remains unqualified")
            return 0 if report.passed else 1
        else:
            problems = check_profile(args.profile)
            if problems:
                raise ValueError("; ".join(problems))
            print("contract: current; provider adapter: application-owned, unqualified")
            if args.production:
                from . import _native

                if not args.signer_adapter or not _IDENTITY.fullmatch(args.signer_adapter):
                    raise ValueError("production needs an explicit custody signer adapter identifier")
                if args.grant_file is None:
                    raise ValueError("production grant-file is missing")
                if args.trust_file is None:
                    raise ValueError("production trust-file is missing")
                for path, maximum in ((args.grant_file, 262_144), (args.trust_file, 262_144)):
                    if path.is_symlink() or not path.is_file() or not 1 <= path.stat().st_size <= maximum:
                        raise ValueError("production authority file is unavailable or outside bounds")
                try:
                    _native.parse_signed("grant", args.grant_file.read_bytes())
                except Exception as error:
                    raise ValueError("production grant is invalid") from error
                try:
                    _native.parse_trusted_context(args.trust_file.read_bytes())
                except Exception as error:
                    raise ValueError("production trusted context is invalid") from error
                if args.grant_file.resolve() == args.trust_file.resolve():
                    raise ValueError("grant and trusted context must use separate files")
                print("production inputs: structurally present; signer connectivity and trust provenance not checked")
            else:
                print("local testkit authority is development-only")
            print("profile doctor does not verify provider credentials or qualify adapter behavior")
    except (OSError, UnicodeError, ValueError, ImportError, AttributeError, TypeError, NotImplementedError) as error:
        print(f"auths-profile: {error}", file=sys.stderr)
        return 1
    return 0


def _diagnostic(action: str, status: int, message: str) -> tuple[str, str, str]:
    if status == 0:
        return ("profile.generated.current" if action == "check" else "profile.operation.ok",
                "generated" if action == "check" else "contract", "No action required.")
    if "without a version bump" in message or "version cannot move backward" in message:
        return "profile.contract.version-required", "contract", "Increase profile.version, then review profile diff."
    if "has drifted" in message:
        return "profile.generated.stale", "generated", "Run profile generate after reviewing the source and version."
    if "No module named" in message or "cannot import name" in message:
        return "profile.provider.suite-import-failed", "provider", "Put the suite in the profile package or install its package, then rerun profile test."
    if "signer" in message:
        return "profile.authority.signer-missing", "authority", "Supply an explicit custody signer adapter."
    if "grant" in message and "trust" not in message:
        return "profile.authority.grant-missing", "authority", "Supply a bounded signed grant file."
    if "trust" in message:
        return "profile.trust.context-missing", "trust", "Supply an independently provisioned trusted context."
    if "suite" in message or "adapter" in message:
        return "profile.provider.adapter-test-failed", "provider", "Wire the adapter to the scripted provider and rerun profile test."
    return "profile.contract.schema-invalid", "contract", "Correct the bounded profile.toml schema."


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if "--json" not in raw:
        return _main_text(raw)
    raw.remove("--json")
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        status = _main_text(raw)
    action = raw[0] if raw else "unknown"
    message = (stderr.getvalue() or stdout.getvalue()).strip()[:2048]
    code, stage, next_action = _diagnostic(action, status, message)
    diff = None
    if status == 0 and action == "diff":
        at = raw[1] if len(raw) > 1 else "profile.toml"
        diff = profile_diff(Path(at))
        values = (diff["code"], diff["stage"], diff["next_action"])
        if not all(isinstance(value, str) for value in values):
            raise ValueError("profile diff diagnostic is invalid")
        code, stage, next_action = str(values[0]), str(values[1]), str(values[2])
    print(_stable_json({
        "schema": "auths.profile-diagnostic/1", "ok": status == 0,
        "action": action, "diagnostic": {
            "code": code, "stage": stage, "message": message,
            "next_action": next_action,
        }, "diff": diff,
    }))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
