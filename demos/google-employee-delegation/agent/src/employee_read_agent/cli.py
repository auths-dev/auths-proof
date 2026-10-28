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
from .release_channel import serve_one_release
from .draft import author_signed_draft
from .planned_populate import planned_populate_arguments
from .write import sign_read, sign_write


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


def _private_source(path: Path, maximum: int) -> bytes:
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("agent source file must be private and bounded")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if (not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or not 1 <= metadata.st_size <= maximum):
            raise ValueError("agent source file must be private and bounded")
        content = source.read(maximum + 1)
    if not 1 <= len(content) <= maximum:
        raise ValueError("agent source file must be private and bounded")
    return content


def _model_key(path: Path | None) -> str | None:
    if path is None:
        return None
    if (path.is_symlink() or not path.is_file()
            or path.stat().st_size > 4096):
        raise ValueError("model API key file is invalid")
    value = path.read_text(encoding="utf-8").strip()
    if not value or "\n" in value or "\r" in value:
        raise ValueError("model API key is invalid")
    return value


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
    read = commands.add_parser("sign-read")
    read.add_argument("--key-file", type=Path, required=True)
    read.add_argument("--package-file", type=Path, required=True)
    read.add_argument("--arguments-file", type=Path, required=True)
    read.add_argument("--out-dir", type=Path, required=True)
    release = commands.add_parser("serve-release")
    release.add_argument("--key-file", type=Path, required=True)
    release.add_argument("--socket", type=Path, required=True)
    release.add_argument("--output", type=Path, required=True)
    release.add_argument("--task-id", required=True)
    release.add_argument("--task-commitment", required=True)
    release.add_argument("--operation-id", required=True)
    release.add_argument("--resource-handle", required=True)
    release.add_argument("--channel-name", required=True)
    release.add_argument("--enrollment-commitment", required=True)
    release.add_argument("--partition-generation", type=int, required=True)
    release.add_argument("--instance-generation", type=int, required=True)
    draft = commands.add_parser("author-draft")
    draft.add_argument("--key-file", type=Path, required=True)
    draft.add_argument("--read-package-file", type=Path, required=True)
    draft.add_argument("--source-file", type=Path, required=True)
    draft.add_argument("--source-resource-handle", required=True)
    draft.add_argument("--read-operation-id", required=True)
    draft.add_argument("--purpose", required=True)
    draft.add_argument("--out-dir", type=Path, required=True)
    draft.add_argument("--model", required=True)
    draft.add_argument("--model-base-url")
    draft.add_argument("--model-api-key-file", type=Path)
    populate = commands.add_parser("sign-planned-populate")
    populate.add_argument("--key-file", type=Path, required=True)
    populate.add_argument("--package-file", type=Path, required=True)
    populate.add_argument("--plan-file", type=Path, required=True)
    populate.add_argument("--preflight-file", type=Path, required=True)
    populate.add_argument("--draft-file", type=Path, required=True)
    populate.add_argument("--recipe-file", type=Path, required=True)
    populate.add_argument("--out-dir", type=Path, required=True)
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
    if args.command == "serve-release":
        result = serve_one_release(
            socket_path=args.socket, output_path=args.output, key=key,
            task_id=args.task_id, task_commitment=args.task_commitment,
            operation_id=args.operation_id, resource_handle=args.resource_handle,
            channel_name=args.channel_name, enrollment_commitment=args.enrollment_commitment,
            partition_generation=args.partition_generation, instance_generation=args.instance_generation,
        )
        print(json.dumps(result, sort_keys=True))
        return
    if args.command == "sign-preimage":
        raw = args.preimage_file.read_bytes()
        if not 1 <= len(raw) <= 65_536:
            parser.error("signing preimage is outside bounds")
        import base64
        print(base64.urlsafe_b64encode(key.private.sign(raw)).decode("ascii"))
        return
    if args.command == "author-draft":
        if (args.out_dir.is_symlink() or not args.out_dir.is_dir()
                or stat.S_IMODE(args.out_dir.stat().st_mode) & 0o077):
            parser.error("agent output directory must be private")
        package = _bounded_json(args.read_package_file, 1_000_000)
        if (package.get("schema") != "auths.ap071-agent-read-package/1"
                or package.get("agent_principal") != key.principal):
            parser.error("agent read package differs from its registered key")
        envelope = author_signed_draft(
            source=_private_source(args.source_file, 16_384),
            source_resource_handle=args.source_resource_handle,
            read_operation_id=args.read_operation_id,
            task_id=package.get("task_id"),
            task_commitment=package.get("task_commitment"),
            agent_principal=key.principal,
            purpose=args.purpose,
            model=OpenAIModel(args.model, args.model_base_url,
                              _model_key(args.model_api_key_file)),
            key=key.private,
        )
        output = args.out_dir / "agent-draft.json"
        _private_output(output, envelope)
        print(json.dumps({"status": "agent-draft-signed", "output": str(output)},
                         sort_keys=True))
        return
    if args.command == "sign-planned-populate":
        if (args.out_dir.is_symlink() or not args.out_dir.is_dir()
                or stat.S_IMODE(args.out_dir.stat().st_mode) & 0o077):
            parser.error("agent output directory must be private")
        package = _bounded_json(args.package_file, 1_000_000)
        arguments = planned_populate_arguments(
            package=package, plan=_bounded_json(args.plan_file, 4096),
            preflight=_bounded_json(args.preflight_file, 8192),
            draft=_bounded_json(args.draft_file, 4096),
            recipe=_bounded_json(args.recipe_file, 65_536), key=key,
        )
        proof, action = sign_write(package, arguments, key)
        proof_path = args.out_dir / "populate.proof"
        action_path = args.out_dir / "populate.action"
        if proof_path.exists() or action_path.exists():
            parser.error("agent proof or action already exists")
        _private_output(proof_path, proof)
        try:
            _private_output(action_path, action)
        except BaseException:
            proof_path.unlink(missing_ok=True)
            raise
        print(json.dumps({"status": "planned-populate-signed",
                          "proof": str(proof_path), "action": str(action_path)},
                         sort_keys=True))
        return
    if args.command in ("sign-write", "sign-read"):
        if (args.out_dir.is_symlink() or not args.out_dir.is_dir()
                or stat.S_IMODE(args.out_dir.stat().st_mode) & 0o077):
            parser.error("agent output directory must be private")
        package = _bounded_json(args.package_file, 1_000_000)
        arguments = _bounded_json(args.arguments_file, 65_536)
        if args.command == "sign-read":
            proof, action = sign_read(package, arguments, key)
            prefix = "read"
        else:
            proof, action = sign_write(package, arguments, key)
            prefix = "agent"
        proof_path = args.out_dir / f"{prefix}.proof"
        action_path = args.out_dir / f"{prefix}.action"
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
    model_key = _model_key(args.model_api_key_file)
    result = run_task(package, key, HttpBroker(args.broker_origin),
                      OpenAIModel(args.model, args.model_base_url, model_key))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
