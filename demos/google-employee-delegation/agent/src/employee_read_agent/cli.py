"""Separate agent process entry point; no broker database or Google credential access."""

from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path

from auths.identity.authoring import create_raw_key_ed25519_identity
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from .run import AgentKey, HttpBroker, OpenAIModel, run_task
from .write import sign_write


def _bounded_json(path: Path, maximum: int) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("agent input file is unavailable or outside bounds")
    value = json.loads(path.read_bytes())
    if type(value) is not dict:
        raise ValueError("agent input must be a JSON object")
    return value


def _private_output(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init-key")
    init.add_argument("--key-file", type=Path, required=True)
    sign = commands.add_parser("sign-preimage")
    sign.add_argument("--key-file", type=Path, required=True)
    sign.add_argument("--preimage-file", type=Path, required=True)
    run = commands.add_parser("run")
    run.add_argument("--key-file", type=Path, required=True)
    run.add_argument("--package-file", type=Path, required=True)
    run.add_argument("--broker-origin", required=True)
    run.add_argument("--model", required=True)
    run.add_argument("--model-base-url")
    run.add_argument("--model-api-key-file", type=Path)
    write = commands.add_parser("sign-write")
    write.add_argument("--key-file", type=Path, required=True)
    write.add_argument("--package-file", type=Path, required=True)
    write.add_argument("--arguments-file", type=Path, required=True)
    write.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "init-key":
        seed = Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        descriptor = os.open(args.key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(descriptor, seed)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        key = AgentKey(seed)
        identity = create_raw_key_ed25519_identity(
            key.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        import base64
        print(json.dumps({"agent_principal": key.principal,
                          "identity_packet": base64.urlsafe_b64encode(identity.to_bytes()).decode()},
                         sort_keys=True))
        return
    key = AgentKey.load(args.key_file)
    if args.command == "sign-preimage":
        raw = args.preimage_file.read_bytes()
        if not 1 <= len(raw) <= 65_536:
            parser.error("signing preimage is outside bounds")
        import base64
        print(base64.urlsafe_b64encode(key.private.sign(raw)).decode("ascii"))
        return
    if args.command == "sign-write":
        if (args.out_dir.is_symlink() or not args.out_dir.is_dir()
                or stat.S_IMODE(args.out_dir.stat().st_mode) & 0o077):
            parser.error("agent output directory must be private")
        package = _bounded_json(args.package_file, 1_000_000)
        arguments = _bounded_json(args.arguments_file, 65_536)
        proof, action = sign_write(package, arguments, key)
        proof_path = args.out_dir / "agent.proof"
        action_path = args.out_dir / "agent.action"
        if proof_path.exists() or action_path.exists():
            parser.error("agent proof or action already exists")
        _private_output(proof_path, proof)
        try:
            _private_output(action_path, action)
        except BaseException:
            proof_path.unlink(missing_ok=True)
            raise
        print(json.dumps({"status": "signed", "proof": str(proof_path),
                          "action": str(action_path)}, sort_keys=True))
        return
    if args.package_file.stat().st_size > 1_000_000:
        parser.error("agent package exceeds bounds")
    package = json.loads(args.package_file.read_bytes())
    model_key = None
    if args.model_api_key_file is not None:
        key_file = args.model_api_key_file
        if (key_file.is_symlink() or not key_file.is_file()
                or key_file.stat().st_size > 4096):
            parser.error("model API key file is invalid")
        model_key = key_file.read_text(encoding="utf-8").strip()
        if not model_key or "\n" in model_key or "\r" in model_key:
            parser.error("model API key is invalid")
    result = run_task(package, key, HttpBroker(args.broker_origin),
                      OpenAIModel(args.model, args.model_base_url, model_key))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
