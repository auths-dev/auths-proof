"""Separate agent process entry point; no broker database or Google credential access."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from auths.identity.authoring import create_raw_key_ed25519_identity
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from .run import AgentKey, HttpBroker, OpenAIModel, run_task


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
