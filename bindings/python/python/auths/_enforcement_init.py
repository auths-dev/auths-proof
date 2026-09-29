"""``auths init <recipe>``: write a development enforcement point for one
recipe, wired to an installed ``auths-gateway``.

The project is a set of thin commands over the gateway CLI and this SDK; its
templates ship in this package, so nothing is fetched. Every check runs
before anything is written, and the project is rendered beside its
directory and renamed into place, so a failure leaves nothing behind.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Dict, List, NoReturn, Optional, Sequence, Tuple, cast

from .gateway import _MAX_SOCKET_PATH_BYTES

RECIPES: Tuple[str, ...] = ("stripe-refund-approval",)
_TEMPLATES = Path(__file__).resolve().parent / "_templates"
_MANAGER = re.compile(r"[a-z][a-z0-9-]{0,31}")
_CURRENCY = re.compile(r"[a-z]{3}")
_ACCOUNT = re.compile(r"acct_[A-Za-z0-9]{1,64}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
# Names the project already gives the root's and the agent's keys.
_RESERVED = frozenset({"root", "agent"})
_MAX_MANAGERS = 16
_MAX_CURRENCIES = 8
_MAX_PARAMETER = 2**32 - 1
# The counting double's platform and connected accounts.
_DOUBLE_ACCOUNTS = ("acct_1AuthsPlatform0", "acct_1AuthsConnected")
_BUILD = (
    "cargo install --locked --path product/runtime/auths-gateway "
    "--features loopback-provider"
)
# Every socket the project binds, all under run/: the gateway's application
# and admin sockets, and the self-test's relay. The admin and relay names
# are the longest.
_SOCKETS = ("app.sock", "admin.sock", "relay.sock")
_NON_CLAIMS = (
    "development deployment: one OS user, a file attempt store, and a software observer key",
    "development custody: the root, the managers, and the agent sign with key files on this host",
    "cannot establish credential isolation: every role runs as the same OS user",
)
# (project path, template path, mode): byte-for-byte copies.
_COPIES = (
    ("recipe/recipe.json", "recipe/recipe.json", 0o644),
    ("recipe/profile.toml", "recipe/profile.toml", 0o644),
    ("recipe/profile.lock.json", "recipe/profile.lock.json", 0o644),
    ("recipe/generated.py", "recipe/generated.py.tmpl", 0o644),
    ("app/refund_client.py", "app/refund_client.py.tmpl", 0o644),
    ("dev/stripe_double.py", "dev/stripe_double.py.tmpl", 0o644),
    ("dev/gateway_witness.py", "dev/gateway_witness.py.tmpl", 0o644),
    ("lib/common.py", "lib/common.py.tmpl", 0o644),
    ("lib/operate.py", "lib/operate.py.tmpl", 0o644),
    ("lib/approve.py", "lib/approve.py.tmpl", 0o644),
    ("lib/selftest.py", "lib/selftest.py.tmpl", 0o644),
)
# bin/NAME runs SCRIPT's ACTION.
_WRAPPERS = (
    ("setup", "lib/operate.py", "setup"),
    ("install-gateway", "lib/operate.py", "install-gateway"),
    ("start", "lib/operate.py", "start"),
    ("stop", "lib/operate.py", "stop"),
    ("request", "app/refund_client.py", "request"),
    ("approve", "lib/approve.py", "answer"),
    ("submit", "app/refund_client.py", "submit"),
    ("export", "app/refund_client.py", "export"),
    ("audit", "lib/operate.py", "audit"),
    ("selftest", "lib/selftest.py", "run"),
)
_FOLDERS = ("recipe", "bin", "app", "dev", "lib")


class InitFailed(Exception):
    """A refusal with a stable code, printed as the command's one JSON
    object. Details hold only paths, names, and numbers, never a secret."""

    def __init__(self, code: str, **details: object) -> None:
        super().__init__(code)
        self.code = code
        self.details = details


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise InitFailed("auths.init.usage", message=message)


@dataclass(frozen=True)
class _Parameters:
    managers: Tuple[str, ...]
    approvals: int
    ceiling: int
    max_count: int
    window_seconds: int
    days: int
    sum_limit: int
    currencies: Tuple[str, ...]
    platform_account: str
    connect_account: str

    def to_json(self) -> Dict[str, object]:
        return {
            "managers": list(self.managers),
            "approvals": self.approvals,
            "ceiling": self.ceiling,
            "max_count": self.max_count,
            "window_seconds": self.window_seconds,
            "days": self.days,
            "sum_limit": self.sum_limit,
            "currencies": list(self.currencies),
            "platform_account": self.platform_account,
            "connect_account": self.connect_account,
        }


@dataclass(frozen=True)
class _Gateway:
    path: Path
    sha256: str
    recipe_digest: str


def _parser() -> _Parser:
    parser = _Parser(
        prog="auths init",
        description=(
            "Write a development enforcement point for RECIPE: keys, trust, the "
            "gateway wiring, the agent's client, the audit, and a self-test."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("recipe", help="one of: " + ", ".join(RECIPES))
    parser.add_argument("--directory", type=Path, help="default: ./auths-RECIPE")
    parser.add_argument("--gateway", default="auths-gateway", help="default: auths-gateway on PATH")
    parser.add_argument("--provider", choices=("double", "stripe-test"), default="double")
    parser.add_argument("--managers", default="manager-a,manager-b,manager-c")
    parser.add_argument(
        "--approvals",
        type=int,
        default=3,
        help="distinct approvals the gateway requires, counting the agent once",
    )
    parser.add_argument("--ceiling", type=int, default=5_000, help="largest refund, in cents")
    parser.add_argument("--max-count", type=int, default=2, help="refunds per window")
    parser.add_argument("--window-seconds", type=int, default=86_400)
    parser.add_argument("--days", type=int, default=30, help="validity of the trust and the grant")
    parser.add_argument(
        "--sum-limit", type=int, default=6_000, help="refund sum per currency per window, in cents"
    )
    parser.add_argument("--currencies", default="eur,usd")
    parser.add_argument("--platform-account", help="stripe-test only: your platform account")
    parser.add_argument("--connect-account", help="stripe-test only: the connected account in scope")
    # The profile scaffold's options, accepted only to refuse them here.
    parser.add_argument("--language", help=argparse.SUPPRESS)
    parser.add_argument("--name", help=argparse.SUPPRESS)
    return parser


def _names(value: str, pattern: "re.Pattern[str]", label: str, limit: int) -> Tuple[str, ...]:
    names = tuple(value.split(","))
    if (
        not 1 <= len(names) <= limit
        or len(set(names)) != len(names)
        or any(pattern.fullmatch(name) is None for name in names)
    ):
        raise InitFailed(f"auths.init.invalid-{label}", value=value)
    return names


def _parameters(args: argparse.Namespace) -> _Parameters:
    managers = _names(str(args.managers), _MANAGER, "managers", _MAX_MANAGERS)
    if _RESERVED & set(managers):
        raise InitFailed("auths.init.invalid-managers", reserved=sorted(_RESERVED & set(managers)))
    approvals = int(args.approvals)
    if not 2 <= approvals <= 1 + len(managers):
        raise InitFailed(
            "auths.init.invalid-approvals", approvals=approvals, minimum=2, maximum=1 + len(managers)
        )
    for option in ("ceiling", "max_count", "window_seconds", "days", "sum_limit"):
        value = int(getattr(args, option))
        if not 1 <= value <= _MAX_PARAMETER:
            raise InitFailed(
                "auths.init.invalid-" + option.replace("_", "-"), value=value, maximum=_MAX_PARAMETER
            )
    currencies = tuple(sorted(_names(str(args.currencies), _CURRENCY, "currencies", _MAX_CURRENCIES)))
    platform, connect = args.platform_account, args.connect_account
    if args.provider == "double":
        if platform is not None or connect is not None:
            raise InitFailed(
                "auths.init.usage",
                message="--platform-account and --connect-account apply to --provider stripe-test; "
                "the double has its own accounts",
            )
        platform, connect = _DOUBLE_ACCOUNTS
    elif not all(isinstance(value, str) and _ACCOUNT.fullmatch(value) for value in (platform, connect)):
        raise InitFailed(
            "auths.init.stripe-test-accounts",
            message="--provider stripe-test needs --platform-account acct_... and --connect-account acct_...",
        )
    return _Parameters(
        managers,
        approvals,
        int(args.ceiling),
        int(args.max_count),
        int(args.window_seconds),
        int(args.days),
        int(args.sum_limit),
        currencies,
        str(platform),
        str(connect),
    )


def _plain(path: Path, label: str) -> str:
    """``path`` as text every generated file can carry: UTF-8 without
    control characters."""
    text = str(path)
    try:
        text.encode("utf-8")
    except UnicodeError:
        raise InitFailed(f"auths.init.invalid-{label}-path", path=repr(text)) from None
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise InitFailed(f"auths.init.invalid-{label}-path", path=repr(text))
    return text


def _socket_limit() -> int:
    """The longest Unix socket path the platform binds: ``sun_path`` less
    its terminating NUL."""
    if sys.platform == "darwin":
        return 103
    if sys.platform.startswith("linux"):
        return 107
    raise InitFailed("auths.init.platform-unsupported", platform=sys.platform, supported=["darwin", "linux"])


def _directory(raw: Optional[Path], recipe: str) -> Path:
    """The canonical absolute project directory, as ``pwd -P`` prints it: absent
    or empty, not a link, in an existing directory."""
    target = raw if raw is not None else Path(f"auths-{recipe}")
    if target.is_symlink():
        raise InitFailed("auths.init.directory-is-link", directory=str(target))
    canonical = target.resolve()
    _plain(canonical, "directory")
    if canonical.exists():
        if not canonical.is_dir():
            raise InitFailed("auths.init.directory-not-directory", directory=str(canonical))
        if any(canonical.iterdir()):
            raise InitFailed("auths.init.directory-not-empty", directory=str(canonical))
    elif not canonical.parent.is_dir():
        raise InitFailed("auths.init.parent-missing", parent=str(canonical.parent))
    if canonical == canonical.parent:
        raise InitFailed("auths.init.directory-not-empty", directory=str(canonical))
    return canonical


def _check_sockets(directory: Path) -> None:
    """Refuses a directory under which a socket the project binds would not
    fit. The application socket and the relay are reached through the SDK's
    endpoint, so they also meet its limit."""
    platform = _socket_limit()
    for name in _SOCKETS:
        path = directory / "run" / name
        size = len(os.fsencode(path))
        maximum = platform if name == "admin.sock" else min(platform, _MAX_SOCKET_PATH_BYTES)
        if size > maximum:
            raise InitFailed(
                "auths.init.socket-path-too-long",
                socket=str(path),
                bytes=size,
                maximum=maximum,
                advice="choose a shorter --directory",
            )


def _run(command: Sequence[str]) -> "subprocess.CompletedProcess[str]":
    try:
        return subprocess.run(
            list(command),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise InitFailed("auths.init.gateway-failed", gateway=command[0], cause=type(error).__name__) from None


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _gateway(name: str, provider: str, recipe: str) -> _Gateway:
    found = name if os.sep in name else shutil.which(name)
    if found is None:
        raise InitFailed("auths.init.gateway-not-found", gateway=name)
    path = Path(found).resolve()
    _plain(path, "gateway")
    if not path.is_file() or not os.access(path, os.X_OK):
        raise InitFailed("auths.init.gateway-not-executable", gateway=str(path))
    if provider == "double":
        helped = _run([str(path), "serve", "--help"])
        if helped.returncode != 0 or "--loopback-provider" not in helped.stdout:
            raise InitFailed(
                "auths.init.gateway-without-loopback-provider",
                gateway=str(path),
                build=_BUILD,
                message="--provider double needs a gateway built with --features loopback-provider",
            )
    templates = _TEMPLATES / recipe / "recipe"
    reviewed = _run(
        [
            str(path),
            "review",
            "--recipe",
            str(templates / "recipe.json"),
            "--profile-lock",
            str(templates / "profile.lock.json"),
        ]
    )
    lines = [line for line in reviewed.stderr.splitlines() if line.strip()]
    if reviewed.returncode != 0:
        raise InitFailed(
            "auths.init.gateway-review-failed",
            gateway=str(path),
            gateway_code=lines[-1].split()[0] if lines else None,
        )
    try:
        review: object = json.loads(reviewed.stdout)
    except ValueError:
        review = None
    fields = cast(Dict[str, object], review) if isinstance(review, dict) else {}
    digest = fields.get("recipe_digest")
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise InitFailed("auths.init.gateway-review-failed", gateway=str(path), gateway_code=None)
    return _Gateway(path, _file_sha256(path), digest)


def _interpreter() -> Tuple[Path, Path]:
    """The interpreter running this command, and the ``auths`` command
    installed beside it. Neither is resolved, so a virtual environment's
    interpreter stays the one its packages belong to."""
    python = Path(os.path.abspath(sys.executable))
    _plain(python, "python")
    cli = python.parent / "auths"
    if not cli.is_file() or not os.access(cli, os.X_OK):
        raise InitFailed(
            "auths.init.cli-missing",
            expected=str(cli),
            message="install auths into the environment of the interpreter that runs auths init",
        )
    return python, cli


def _sdk_version() -> str:
    try:
        return metadata.version("auths")
    except metadata.PackageNotFoundError:
        return "source-tree"


def _substitute(text: str, values: Dict[str, str]) -> str:
    for key, value in values.items():
        text = text.replace(f"@@{key}@@", value)
    if "@@" in text:
        raise InitFailed("auths.init.template-invalid")
    return text


def _write(path: Path, data: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
    os.chmod(path, mode)


def _config(
    directory: Path,
    recipe: str,
    python: Path,
    cli: Path,
    gateway: _Gateway,
    provider: str,
    parameters: _Parameters,
) -> str:
    """``enforcement.toml``: tables, and ``key = value`` lines whose values
    are JSON literals, which TOML reads the same way. No secret."""

    def line(key: str, value: object) -> str:
        return f"{key} = {json.dumps(value)}\n"

    return "".join(
        [
            "# Written by `auths init`. It holds no secret; every command reads it.\n",
            line("directory", str(directory)),
            line("recipe", recipe),
            line("recipe_digest", gateway.recipe_digest),
            line("sdk_version", _sdk_version()),
            line("python", str(python)),
            line("auths_cli", str(cli)),
            line("provider", provider),
            "\n[gateway]\n",
            line("path", str(gateway.path)),
            line("sha256", gateway.sha256),
            "\n[parameters]\n",
            *(line(key, value) for key, value in parameters.to_json().items()),
        ]
    )


def _parameter_table(parameters: _Parameters, provider: str) -> str:
    rows = [
        ("provider", "the counting Stripe double on 127.0.0.1" if provider == "double" else "Stripe test mode"),
        ("managers", ", ".join(parameters.managers)),
        ("approvals", f"{parameters.approvals} distinct approvals, counting the agent once"),
        ("ceiling", f"{parameters.ceiling} cents per refund"),
        ("max-count", f"{parameters.max_count} refunds per window"),
        ("sum-limit", f"{parameters.sum_limit} cents per currency per window"),
        ("window-seconds", f"{parameters.window_seconds} (fixed windows aligned to the epoch)"),
        ("currencies", ", ".join(parameters.currencies)),
        ("platform-account", parameters.platform_account),
        ("connect-account", parameters.connect_account),
        ("days", f"{parameters.days} days of validity for the trust and the grant"),
    ]
    return "\n".join(
        ["| Parameter | Value |", "| --- | --- |", *(f"| `{name}` | {value} |" for name, value in rows)]
    )


def _render(
    staging: Path,
    directory: Path,
    recipe: str,
    python: Path,
    cli: Path,
    gateway: _Gateway,
    provider: str,
    parameters: _Parameters,
) -> None:
    templates = _TEMPLATES / recipe
    for folder in _FOLDERS:
        (staging / folder).mkdir(mode=0o700)
        os.chmod(staging / folder, 0o700)
    for target, source, mode in _COPIES:
        _write(staging / target, (templates / source).read_bytes(), mode)
    wrapper = (templates / "bin.sh.tmpl").read_text(encoding="utf-8")
    for name, script, action in _WRAPPERS:
        text = _substitute(
            wrapper,
            {
                "COMMAND": name,
                "DIR": shlex.quote(str(directory)),
                "PYTHON": shlex.quote(str(python)),
                "SCRIPT": script,
                "ACTION": action,
            },
        )
        _write(staging / "bin" / name, text.encode("utf-8"), 0o755)
    readme = _substitute(
        (templates / "README.md.tmpl").read_text(encoding="utf-8"),
        {
            "DIR": shlex.quote(str(directory)),
            "PARAMETERS": _parameter_table(parameters, provider),
            "APPROVERS": ",".join(parameters.managers[: parameters.approvals - 1]),
            "FIRST_MANAGER": parameters.managers[0],
        },
    )
    _write(staging / "README.md", readme.encode("utf-8"), 0o644)
    config = _config(directory, recipe, python, cli, gateway, provider, parameters)
    _write(staging / "enforcement.toml", config.encode("utf-8"), 0o644)


def _init(argv: List[str]) -> Dict[str, object]:
    args = _parser().parse_args(argv)
    if args.language is not None or args.name is not None:
        raise InitFailed(
            "auths.init.usage",
            message="--language and --name belong to the profile scaffold, `auths init --language ... --name ...`; "
            "a recipe takes neither",
        )
    recipe = str(args.recipe)
    if recipe not in RECIPES:
        raise InitFailed("auths.init.unknown-recipe", recipe=recipe, known=list(RECIPES))
    provider = str(args.provider)
    parameters = _parameters(args)
    _socket_limit()
    directory = _directory(args.directory, recipe)
    _check_sockets(directory)
    gateway = _gateway(str(args.gateway), provider, recipe)
    python, cli = _interpreter()
    try:
        staging = Path(tempfile.mkdtemp(prefix=f".{directory.name}.", dir=directory.parent))
    except OSError as error:
        raise InitFailed("auths.init.write-failed", directory=str(directory.parent), cause=error.strerror) from None
    try:
        _render(staging, directory, recipe, python, cli, gateway, provider, parameters)
        os.chmod(staging, 0o700)
        # Replaces an empty directory, and fails if anything appeared in it.
        os.rename(staging, directory)
    except OSError as error:
        shutil.rmtree(staging, ignore_errors=True)
        raise InitFailed("auths.init.write-failed", directory=str(directory), cause=error.strerror) from None
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    quoted = shlex.quote(str(directory))
    steps = [f"cd {quoted}", "bin/setup", "bin/install-gateway < KEY_FILE", "bin/start"]
    if provider == "double":
        steps.append("AUTHS_SELFTEST_KEY_FILE=KEY_FILE bin/selftest")
    steps.append("bin/stop")
    return {
        "project": str(directory),
        "recipe": recipe,
        "recipe_digest": gateway.recipe_digest,
        "provider": provider,
        "gateway": {"path": str(gateway.path), "sha256": gateway.sha256},
        "python": str(python),
        "auths_cli": str(cli),
        "parameters": parameters.to_json(),
        "next": steps,
        "readme": str(directory / "README.md"),
        "deployment": list(_NON_CLAIMS),
    }


def init_enforcement_main(argv: Sequence[str]) -> int:
    """Runs ``auths init <recipe> [options]`` and prints one JSON object: the
    project and its next commands, or ``{"error": code, ...}`` with a
    non-zero exit."""
    try:
        summary = _init(list(argv))
    except InitFailed as failure:
        print(json.dumps({"error": failure.code, **failure.details}, sort_keys=True))
        return 2 if failure.code == "auths.init.usage" else 1
    print(json.dumps(summary, sort_keys=True))
    return 0
