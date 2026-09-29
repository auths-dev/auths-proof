"""`auths init <recipe>` writes a development enforcement point that keeps the
key on stdin, the decision at the gateway, and the audit's verdict intact.

A stand-in for `auths-gateway` records every call it receives, so these tests
need no gateway build; the hosted job runs the real one end to end."""

from __future__ import annotations

import hashlib
import json
import os
import pty
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List

import pytest

from auths import _enforcement_init
from auths._profile_cli import main

pytestmark = pytest.mark.skipif(
    sys.platform != "darwin" and not sys.platform.startswith("linux"),
    reason="auths init supports macOS and Linux only",
)

EXAMPLE = Path(__file__).resolve().parents[3] / "examples" / "stripe-refund-approval"
TEMPLATES = Path(_enforcement_init.__file__).resolve().parent / "_templates" / "stripe-refund-approval"
LIMIT = 103 if sys.platform == "darwin" else 107
KEY_PATTERN = re.compile(rb"(sk|rk)_(test|live)_[A-Za-z0-9]{8,}")
DIGEST = "ab" * 32
NON_CLAIMS = list(_enforcement_init._NON_CLAIMS)
# What `auths init` writes, with modes; directories are 0700 at every level.
WRITTEN = {
    "enforcement.toml": 0o644,
    "README.md": 0o644,
    "recipe/recipe.json": 0o644,
    "recipe/profile.toml": 0o644,
    "recipe/profile.lock.json": 0o644,
    "recipe/generated.py": 0o644,
    "app/refund_client.py": 0o644,
    "dev/stripe_double.py": 0o644,
    "dev/gateway_witness.py": 0o644,
    "lib/common.py": 0o644,
    "lib/operate.py": 0o644,
    "lib/approve.py": 0o644,
    "lib/selftest.py": 0o644,
    **{
        f"bin/{name}": 0o755
        for name in (
            "setup",
            "install-gateway",
            "start",
            "stop",
            "request",
            "approve",
            "submit",
            "export",
            "audit",
            "selftest",
        )
    },
}
FOLDERS = {"recipe", "bin", "app", "dev", "lib"}

# The stand-in gateway: it logs its arguments and standard input and answers
# as the real one does for the calls the project makes.
STAND_IN = """
import json
import os
import socket
import sys
import time
from pathlib import Path

RECORD = Path(__RECORD__)
arguments = sys.argv[1:]
with (RECORD / "argv.jsonl").open("a") as log:
    log.write(json.dumps(arguments) + "\\n")


def option(name):
    return arguments[arguments.index(name) + 1] if name in arguments else None


command = arguments[0] if arguments else ""
if command == "serve" and "--help" in arguments:
    print("Usage: auths-gateway serve [OPTIONS] --state-dir <STATE_DIR> --app-socket <APP_SOCKET>")
    if __LOOPBACK__:
        print("      --loopback-provider <LOOPBACK_PROVIDER>")
elif command == "review":
    print(json.dumps({"recipe_digest": __DIGEST__, "service": "stripe-refunds", "tool": "create_refund"}))
elif command == "install":
    data = sys.stdin.buffer.read()
    (RECORD / "stdin.bin").write_bytes(data)
    state = Path(option("--state-dir"))
    if (state / "installation.json").exists():
        print("gateway.install.already-installed", file=sys.stderr)
        sys.exit(1)
    (state / "installation.json").write_text("{}")
    print("installed recipe " + __DIGEST__ + " with separate gateway credential custody")
elif command == "observer-init":
    print(json.dumps({"observer_anchor": {"principal": "key:sha256:stand-in"}}))
elif command == "serve":
    sockets = []
    for path in (option("--admin-socket"), option("--app-socket")):
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(path)
        listener.listen(1)
        sockets.append(listener)
    print("app socket ready; exact recipe " + __DIGEST__, flush=True)
    while True:
        time.sleep(1)
elif command == "audit":
    bundle = Path(option("--bundle")).read_text()
    if "pin-mismatch" in bundle:
        print("audit.trust-pin-mismatch", file=sys.stderr)
        sys.exit(1)
    print(json.dumps({"entries": [], "unverified": 1}, indent=2))
    if "--allow-unverified-refusals" not in arguments:
        print("audit.unverified", file=sys.stderr)
        sys.exit(1)
else:
    print("gateway.stand-in.unsupported", file=sys.stderr)
    sys.exit(1)
"""


@pytest.fixture
def short_root() -> Iterator[Path]:
    """A short canonical directory: socket paths under it must fit."""
    root = Path(tempfile.mkdtemp(prefix="ai", dir="/tmp")).resolve()
    try:
        yield root
    finally:
        stop_everything(root)
        shutil.rmtree(root, ignore_errors=True)


def stop_everything(root: Path) -> None:
    for pid_file in root.glob("**/run/*.pid"):
        try:
            os.kill(int(pid_file.read_text()), signal.SIGKILL)
        except (OSError, ValueError):
            pass


def stand_in(root: Path, loopback: bool = True) -> Path:
    record = root / "record"
    record.mkdir(exist_ok=True)
    script = root / "gateway.py"
    script.write_text(
        STAND_IN.replace("__RECORD__", repr(str(record)))
        .replace("__LOOPBACK__", repr(loopback))
        .replace("__DIGEST__", repr(DIGEST))
    )
    gateway = root / "auths-gateway"
    gateway.write_text(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(script))} \"$@\"\n")
    gateway.chmod(0o755)
    return gateway


def calls(root: Path) -> List[List[str]]:
    log = root / "record" / "argv.jsonl"
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


def init(capsys: pytest.CaptureFixture[str], *arguments: str) -> tuple[int, Dict[str, Any]]:
    status = main(["init", *arguments])
    output = capsys.readouterr().out
    return status, json.loads(output)


def project(
    capsys: pytest.CaptureFixture[str], root: Path, *arguments: str, loopback: bool = True
) -> tuple[Path, Dict[str, Any]]:
    gateway = stand_in(root, loopback)
    directory = root / "p"
    status, summary = init(
        capsys, "stripe-refund-approval", "--directory", str(directory), "--gateway", str(gateway), *arguments
    )
    assert status == 0, summary
    return directory, summary


def run(directory: Path, command: str, *arguments: str, stdin: bytes = b"") -> tuple[int, Dict[str, Any], str]:
    completed = subprocess.run(
        [str(directory / "bin" / command), *arguments], input=stdin, capture_output=True, cwd="/"
    )
    value = json.loads(completed.stdout)
    assert isinstance(value, dict)
    return completed.returncode, value, completed.stderr.decode()


def pretend_setup(directory: Path) -> None:
    """The files `bin/setup` leaves for install; the real setup needs a real gateway."""
    for folder in ("operator", "operator/trust", "audit"):
        (directory / folder).mkdir(mode=0o700)
    (directory / "operator" / "setup.json").write_text(json.dumps({"recipe_digest": DIGEST}))
    (directory / "operator" / "trust" / "gateway.context.cbor").write_bytes(b"\x00")
    (directory / "audit" / "pins.json").write_text(json.dumps({"trusted_context_sha256": "00" * 32, "observer": None}))


def tree(directory: Path) -> Dict[str, int]:
    return {
        str(path.relative_to(directory)): stat.S_IMODE(path.lstat().st_mode) for path in sorted(directory.rglob("*"))
    }


def test_writes_exactly_the_layout_with_modes_and_defaults(
    capsys: pytest.CaptureFixture[str], short_root: Path
) -> None:
    for existing in (False, True):
        directory = short_root / f"p{int(existing)}"
        if existing:
            directory.mkdir()
        status, summary = init(
            capsys,
            "stripe-refund-approval",
            "--directory",
            str(directory),
            "--gateway",
            str(stand_in(short_root)),
        )
        assert status == 0, summary
        assert tree(directory) == {**WRITTEN, **{folder: 0o700 for folder in FOLDERS}}
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        config = (directory / "enforcement.toml").read_text()
        values: Dict[str, Any] = {}
        for line in config.splitlines():
            key, separator, value = line.partition("=")
            if separator and not line.startswith("#"):
                values[key.strip()] = json.loads(value)
        assert values["directory"] == str(directory) == summary["project"]
        assert values["python"] == os.path.abspath(sys.executable)
        assert values["auths_cli"] == str(Path(os.path.abspath(sys.executable)).parent / "auths")
        assert values["provider"] == "double"
        assert values["recipe_digest"] == DIGEST
        assert values["sha256"] == hashlib.sha256((short_root / "auths-gateway").read_bytes()).hexdigest()
        assert {key: values[key] for key in summary["parameters"]} == summary["parameters"] == {
            "managers": ["manager-a", "manager-b", "manager-c"],
            "approvals": 3,
            "ceiling": 5_000,
            "max_count": 2,
            "window_seconds": 86_400,
            "days": 30,
            "sum_limit": 6_000,
            "currencies": ["eur", "usd"],
            "platform_account": "acct_1AuthsPlatform0",
            "connect_account": "acct_1AuthsConnected",
        }
        key = shlex.quote(f"{directory}.key")
        assert summary["next"] == [
            f"cd {shlex.quote(str(directory))}",
            "bin/setup",
            "( umask 077; printf 'rk_test_%s\\n' \"$(od -An -tx1 -N12 /dev/urandom | tr -d ' \\n')\" "
            f"> {key} )",
            f"bin/install-gateway < {key}",
            "bin/start",
            f"AUTHS_SELFTEST_KEY_FILE={key} bin/selftest",
            "bin/stop",
        ]
        # The README's quick start is the same sequence.
        readme = (directory / "README.md").read_text()
        assert "\n".join(summary["next"]) in readme
        assert summary["deployment"] == NON_CLAIMS


def test_refuses_a_non_empty_or_linked_directory_and_leaves_it_unchanged(
    capsys: pytest.CaptureFixture[str], short_root: Path
) -> None:
    gateway = stand_in(short_root)
    directory = short_root / "p"
    directory.mkdir()
    (directory / "notes.txt").write_text("mine\n")
    status, refused = init(capsys, "stripe-refund-approval", "--directory", str(directory), "--gateway", str(gateway))
    assert status != 0 and refused["error"] == "auths.init.directory-not-empty"
    assert tree(directory) == {"notes.txt": stat.S_IMODE((directory / "notes.txt").stat().st_mode)}
    empty = short_root / "empty"
    empty.mkdir()
    link = short_root / "link"
    link.symlink_to(empty)
    status, refused = init(capsys, "stripe-refund-approval", "--directory", str(link), "--gateway", str(gateway))
    assert status != 0 and refused["error"] == "auths.init.directory-is-link"
    assert list(empty.iterdir()) == []
    assert sorted(path.name for path in short_root.iterdir()) == [
        "auths-gateway",
        "empty",
        "gateway.py",
        "link",
        "p",
        "record",
    ]


def test_socket_paths_are_checked_at_the_byte_boundary(
    capsys: pytest.CaptureFixture[str], short_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gateway = stand_in(short_root)
    # run/admin.sock is the longest socket path; run/relay.sock has its length.
    padding = LIMIT - len(os.fsencode(short_root)) - len("/run/admin.sock") - 1
    fits = short_root / ("d" * padding)
    assert len(os.fsencode(fits / "run" / "admin.sock")) == LIMIT
    status, summary = init(capsys, "stripe-refund-approval", "--directory", str(fits), "--gateway", str(gateway))
    assert status == 0, summary
    over = short_root / ("e" * (padding + 1))
    status, refused = init(capsys, "stripe-refund-approval", "--directory", str(over), "--gateway", str(gateway))
    assert status != 0
    assert refused["error"] == "auths.init.socket-path-too-long"
    assert (refused["bytes"], refused["maximum"]) == (LIMIT + 1, LIMIT)
    assert refused["advice"] == "choose a shorter --directory"
    assert not over.exists()
    # The application socket follows whatever the SDK's endpoint accepts.
    short = short_root / "f"
    app = short / "run" / "app.sock"
    monkeypatch.setattr(_enforcement_init, "_MAX_SOCKET_PATH_BYTES", len(os.fsencode(app)) - 1)
    status, refused = init(capsys, "stripe-refund-approval", "--directory", str(short), "--gateway", str(gateway))
    assert status != 0 and refused["error"] == "auths.init.socket-path-too-long"
    assert (refused["socket"], refused["maximum"]) == (str(app), len(os.fsencode(app)) - 1)
    assert not short.exists()
    assert not [path for path in short_root.iterdir() if path.name.startswith(".")]


@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        (["stripe-refunds"], "auths.init.unknown-recipe"),
        (["stripe-refund-approval", "--approvals", "1"], "auths.init.invalid-approvals"),
        (["stripe-refund-approval", "--approvals", "5"], "auths.init.invalid-approvals"),
        (["stripe-refund-approval", "--ceiling", "0"], "auths.init.invalid-ceiling"),
        (["stripe-refund-approval", "--ceiling", "-5"], "auths.init.invalid-ceiling"),
        (["stripe-refund-approval", "--days", "0"], "auths.init.invalid-days"),
        (["stripe-refund-approval", "--managers", "agent,manager-b"], "auths.init.invalid-managers"),
        (["stripe-refund-approval", "--provider", "stripe-test"], "auths.init.stripe-test-accounts"),
    ],
)
def test_invalid_options_exit_non_zero_and_write_nothing(
    capsys: pytest.CaptureFixture[str], short_root: Path, arguments: List[str], code: str
) -> None:
    gateway = stand_in(short_root)
    directory = short_root / "p"
    status, refused = init(capsys, *arguments, "--directory", str(directory), "--gateway", str(gateway))
    assert status != 0 and refused["error"] == code
    if code == "auths.init.unknown-recipe":
        assert refused["known"] == ["stripe-refund-approval"]
    assert not directory.exists()
    assert calls(short_root) == []


def test_a_recipe_with_profile_options_is_a_usage_error(
    capsys: pytest.CaptureFixture[str], short_root: Path
) -> None:
    for option in ("--language", "--name"):
        status, refused = init(capsys, "stripe-refund-approval", option, "python", "--directory", str(short_root / "p"))
        assert status == 2 and refused["error"] == "auths.init.usage"
    assert not (short_root / "p").exists()


def test_the_profile_init_help_names_the_recipes(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exited:
        main(["init", "--help"])
    assert exited.value.code == 0
    assert "Recipes: stripe-refund-approval." in " ".join(capsys.readouterr().out.split())


def test_a_gateway_without_the_loopback_provider_is_refused_for_the_double(
    capsys: pytest.CaptureFixture[str], short_root: Path
) -> None:
    gateway = stand_in(short_root, loopback=False)
    status, refused = init(
        capsys, "stripe-refund-approval", "--directory", str(short_root / "p"), "--gateway", str(gateway)
    )
    assert status != 0 and refused["error"] == "auths.init.gateway-without-loopback-provider"
    assert "--features loopback-provider" in refused["build"]
    assert not (short_root / "p").exists()


def test_wrappers_run_the_recorded_python_and_hold_no_key_or_link(
    capsys: pytest.CaptureFixture[str], short_root: Path
) -> None:
    directory, _ = project(capsys, short_root)
    python = shlex.quote(os.path.abspath(sys.executable))
    for name in (path.name for path in (directory / "bin").iterdir()):
        wrapper = directory / "bin" / name
        assert subprocess.run(["sh", "-n", str(wrapper)]).returncode == 0
        text = wrapper.read_text()
        assert f"\nDIR={shlex.quote(str(directory))}\n" in text
        assert f"\nPYTHON={python}\n" in text
        assert 'exec "$PYTHON" -B "$DIR/' in text
    for path in directory.rglob("*"):
        assert not path.is_symlink()
        if path.is_file():
            assert KEY_PATTERN.search(path.read_bytes()) is None, path
            assert b"separate gateway credential custody" not in path.read_bytes(), path
    readme = (directory / "README.md").read_text()
    assert "cannot establish credential isolation" in readme
    assert "--allow-unverified-refusals" in readme and "admitted: false" in readme


def test_templates_match_the_example_byte_for_byte() -> None:
    pairs = {
        "recipe/recipe.json": "recipe.json",
        "recipe/profile.toml": "profile.toml",
        "recipe/profile.lock.json": "profile.lock.json",
        "recipe/generated.py.tmpl": "generated.py",
        "dev/stripe_double.py.tmpl": "mock_stripe.py",
        "dev/gateway_witness.py.tmpl": "gateway_witness.py",
    }
    for template, example in pairs.items():
        assert (TEMPLATES / template).read_bytes() == (EXAMPLE / example).read_bytes(), template


def test_the_agent_client_reads_no_other_role_key() -> None:
    client = (TEMPLATES / "app" / "refund_client.py.tmpl").read_text()
    assert re.search(r'/\s*"managers"', client) is None and "signing.seed" not in client
    assert re.findall(r'"operator"\s*/\s*"([^"]+)"', client) == ["setup.json"]


def test_install_refuses_a_terminal_before_the_gateway_runs(
    capsys: pytest.CaptureFixture[str], short_root: Path
) -> None:
    directory, _ = project(capsys, short_root)
    pretend_setup(directory)
    before = len(calls(short_root))
    leader, follower = pty.openpty()
    try:
        completed = subprocess.run(
            [str(directory / "bin" / "install-gateway")], stdin=follower, capture_output=True, timeout=60
        )
    finally:
        os.close(follower)
        os.close(leader)
    assert completed.returncode != 0
    assert json.loads(completed.stdout)["error"] == "auths.install.stdin-is-terminal"
    assert len(calls(short_root)) == before
    assert not (directory / "run" / "double.token.sha256").exists()


def test_double_mode_hands_the_key_on_unchanged_and_writes_only_its_digest(
    capsys: pytest.CaptureFixture[str], short_root: Path
) -> None:
    directory, _ = project(capsys, short_root)
    pretend_setup(directory)
    piped = b"rk_test_mock_abc\n"
    status, installed, stderr = run(directory, "install-gateway", stdin=piped)
    try:
        assert status == 0, (installed, stderr)
        assert (short_root / "record" / "stdin.bin").read_bytes() == piped
        digest = (directory / "run" / "double.token.sha256").read_text().strip()
        assert digest == hashlib.sha256(b"rk_test_mock_abc").hexdigest()
        assert installed["observer"] == "key:sha256:stand-in" and installed["deployment"] == NON_CLAIMS
        assert json.loads((directory / "audit" / "pins.json").read_text())["observer"] == "key:sha256:stand-in"
        install = next(call for call in calls(short_root) if call[0] == "install")
        paths = {option: install[install.index(option) + 1] for option in ("--state-dir", "--recipe", "--profile-lock", "--trusted-context")}
        assert all(Path(value).is_absolute() and Path(value).is_relative_to(directory) for value in paths.values())
        assert "--loopback-provider" in install
        for path in directory.rglob("*"):
            if path.is_file() and not path.is_relative_to(directory / "enforcement"):
                assert b"rk_test_mock_abc" not in path.read_bytes(), path
        # A second install surfaces the gateway's refusal and keeps the digest.
        status, second, _ = run(directory, "install-gateway", stdin=b"not-a-provider-key\n")
        assert status != 0 and second["error"] == "gateway.install.already-installed"
        assert (directory / "run" / "double.token.sha256").read_text().strip() == digest
        # The gateway serves with absolute paths under the project and the double's port.
        status, started, _ = run(directory, "start")
        assert status == 0 and started["deployment"] == NON_CLAIMS
        serve = next(call for call in calls(short_root) if call[0] == "serve" and "--help" not in call)
        for option in ("--state-dir", "--app-socket", "--admin-socket"):
            value = Path(serve[serve.index(option) + 1])
            assert value.is_absolute() and value.is_relative_to(directory)
        assert serve[serve.index("--loopback-provider") + 1] == str(started["double_port"])
    finally:
        status, stopped, _ = run(directory, "stop")
    assert status == 0 and set(stopped["stopped"]) == {"gateway", "double"}
    time.sleep(0.2)
    for pid in stopped["stopped"].values():
        with pytest.raises(OSError):
            os.kill(pid, 0)
    assert not [path for path in (directory / "run").iterdir() if path.is_socket()]
    status, again, _ = run(directory, "stop")
    assert (status, again) == (0, {"stopped": {}})


def test_stripe_test_mode_never_reads_the_key_and_serves_without_the_double(
    capsys: pytest.CaptureFixture[str], short_root: Path
) -> None:
    directory, summary = project(
        capsys,
        short_root,
        "--provider",
        "stripe-test",
        "--platform-account",
        "acct_platform123",
        "--connect-account",
        "acct_connected456",
        loopback=False,
    )
    assert not [step for step in summary["next"] if "bin/selftest" in step or "rk_test_" in step]
    pretend_setup(directory)
    piped = b"rk_test_mock_xyz\n" + bytes(range(256)) + b"trailing bytes"
    status, installed, stderr = run(directory, "install-gateway", stdin=piped)
    try:
        assert status == 0, (installed, stderr)
        assert (short_root / "record" / "stdin.bin").read_bytes() == piped
        assert not (directory / "run" / "double.token.sha256").exists()
        install = next(call for call in calls(short_root) if call[0] == "install")
        assert "--loopback-provider" not in install
        assert install[install.index("--account-label") + 1] == "acct_platform123"
        status, started, _ = run(directory, "start")
        assert status == 0 and started["double_port"] is None
        serve = next(call for call in calls(short_root) if call[0] == "serve" and "--help" not in call)
        assert "--loopback-provider" not in serve
    finally:
        run(directory, "stop")


def test_audit_passes_the_gateway_verdict_through_and_adds_no_option(
    capsys: pytest.CaptureFixture[str], short_root: Path
) -> None:
    directory, _ = project(capsys, short_root)
    pretend_setup(directory)
    pins = {"trusted_context_sha256": "00" * 32, "observer": "key:sha256:stand-in"}
    (directory / "audit" / "pins.json").write_text(json.dumps(pins))
    (directory / "audit" / "bundle.json").write_text("{}")
    status, report, stderr = run(directory, "audit")
    assert (status, report, stderr.strip()) == (1, {"entries": [], "unverified": 1}, "audit.unverified")
    audit = [call for call in calls(short_root) if call[0] == "audit"][-1]
    assert "--allow-unverified-refusals" not in audit
    assert audit[audit.index("--trusted-context-sha256") + 1] == "00" * 32
    status, report, _ = run(directory, "audit", "--allow-unverified-refusals")
    assert status == 0 and report == {"entries": [], "unverified": 1}
    (directory / "audit" / "bundle.json").write_text('{"pin-mismatch": true}')
    status, refused, stderr = run(directory, "audit")
    assert (status, refused, stderr.strip()) == (1, {"error": "audit.trust-pin-mismatch"}, "audit.trust-pin-mismatch")
    status, refused, _ = run(directory, "audit", "--bundle", "/etc/hosts")
    assert status != 0 and refused["error"] == "auths.project.path-outside"


def test_commands_refuse_a_moved_project_a_changed_gateway_and_a_second_setup(
    capsys: pytest.CaptureFixture[str], short_root: Path
) -> None:
    directory, _ = project(capsys, short_root)
    pretend_setup(directory)
    status, refused, _ = run(directory, "setup")
    assert status != 0 and refused["error"] == "auths.setup.already-done"
    copy = short_root / "copy"
    shutil.copytree(directory, copy, symlinks=True)
    status, refused, stderr = run(copy, "stop")
    assert status != 0 and refused == {"error": "auths.project.moved"} and str(directory) in stderr
    with (short_root / "auths-gateway").open("a") as gateway:
        gateway.write("# changed\n")
    status, refused, _ = run(directory, "setup")
    assert status != 0 and refused["error"] == "auths.gateway.changed"


def test_the_installed_command_routes_a_recipe_to_the_enforcement_scaffold(short_root: Path) -> None:
    command = Path(os.path.abspath(sys.executable)).parent / "auths"
    completed = subprocess.run(
        [str(command), "init", "no-such-recipe", "--directory", str(short_root / "p")],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 1
    assert json.loads(completed.stdout) == {
        "error": "auths.init.unknown-recipe",
        "known": ["stripe-refund-approval"],
        "recipe": "no-such-recipe",
    }
