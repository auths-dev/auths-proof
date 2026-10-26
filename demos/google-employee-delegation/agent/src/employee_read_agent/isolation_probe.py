"""Installed-agent check for the AP-071 container boundary.

The probe runs inside the same agent image and namespaces as ``serve-release``.
It reports only access verdicts and never reads a credential or provider body.
"""

from __future__ import annotations

import json
import os
import stat
import argparse
import errno
import socket
from pathlib import Path


def _private_owned_directory(path: Path) -> bool:
    try:
        details = path.stat()
    except OSError:
        return False
    return (not path.is_symlink() and stat.S_ISDIR(details.st_mode)
            and details.st_uid == os.geteuid()
            and stat.S_IMODE(details.st_mode) == 0o700)


def _inaccessible(path: Path) -> bool:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return True
    os.close(descriptor)
    return False


def _write_denied(directory: Path) -> bool:
    probe = directory / f".ap071-agent-write-probe-{os.getpid()}"
    try:
        descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        return error.errno in {errno.EPERM, errno.EACCES}
    os.close(descriptor)
    probe.unlink()
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--macos-agent-dir", type=Path)
    parser.add_argument("--macos-channel-dir", type=Path)
    parser.add_argument("--macos-run-root", type=Path)
    parser.add_argument("--macos-gateway-state", type=Path)
    parser.add_argument("--macos-operator-private", type=Path)
    parser.add_argument("--macos-credential-file", type=Path)
    args = parser.parse_args()
    macos = args.macos_agent_dir is not None
    if macos:
        if any(value is None for value in (
                args.macos_channel_dir, args.macos_run_root,
                args.macos_gateway_state,
                args.macos_operator_private, args.macos_credential_file)):
            parser.error("macOS isolation paths must be supplied together")
        inaccessible = {
            "gateway_state": _inaccessible(args.macos_gateway_state),
            "operator_private": _inaccessible(args.macos_operator_private),
            "credential_file": _inaccessible(args.macos_credential_file),
        }
        sock = socket.socket()
        try:
            sock.settimeout(1)
            sock.connect(("127.0.0.1", 9))
        except OSError as error:
            network_isolated = error.errno in {errno.EPERM, errno.EACCES}
        else:
            network_isolated = False
        finally:
            sock.close()
        result = {
            "schema": "auths.ap071-agent-isolation-probe/2",
            "agent_private": _private_owned_directory(args.macos_agent_dir),
            "channel_private": _private_owned_directory(args.macos_channel_dir),
            "inaccessible": inaccessible,
            "network_isolated": network_isolated,
            "outside_write_denied": _write_denied(args.macos_run_root),
        }
        result["passed"] = (result["agent_private"]
                            and result["channel_private"]
                            and all(inaccessible.values())
                            and result["network_isolated"]
                            and result["outside_write_denied"])
        print(json.dumps(result, sort_keys=True))
        if not result["passed"]:
            raise SystemExit(1)
        return
    channel = Path("/channel")
    agent = Path("/agent")
    inaccessible = {
        "gateway_state": _inaccessible(Path("/gateway-state")),
        "operator_private": _inaccessible(Path("/operator")),
        "docker_socket": _inaccessible(Path("/var/run/docker.sock")),
    }
    try:
        interfaces = sorted(path.name for path in Path("/sys/class/net").iterdir())
    except OSError:
        interfaces = []
    result = {
        "schema": "auths.ap071-agent-isolation-probe/1",
        "agent_private": _private_owned_directory(agent),
        "channel_private": _private_owned_directory(channel),
        "inaccessible": inaccessible,
        "network_interfaces": interfaces,
        "network_isolated": interfaces == ["lo"],
    }
    result["passed"] = (result["agent_private"] and result["channel_private"]
                        and all(inaccessible.values()) and result["network_isolated"])
    print(json.dumps(result, sort_keys=True))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
