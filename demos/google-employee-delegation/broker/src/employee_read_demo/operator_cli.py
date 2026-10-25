"""Offline company root setup and employee-grant issuance for the demo."""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sqlite3
import stat
import time
from dataclasses import asdict
from pathlib import Path

from .demo_co_contract import prepare_operator_pins
from .enrollment import EmployeeBinding
from .operator_authority import EmployeeAuthorityStore, OperatorRoot
from .token_store import TokenVault


def _private_write(path: Path, content: bytes) -> None:
    if stat.S_IMODE(path.parent.stat().st_mode) & 0o077:
        raise PermissionError("operator output directory must be private")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _private_read(path: Path, limit: int) -> bytes:
    if (path.is_symlink() or not path.is_file()
            or path.stat().st_size > limit
            or stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise PermissionError("operator input file must be private and bounded")
    return path.read_bytes()


def _template(root: OperatorRoot, service: str, start: int, end: int) -> bytes:
    from auths import _native

    audience = f"mcp://{service}"
    resource = f"{audience}/tools/google_drive_document_read"
    assurance = _native.AssurancePolicy("raw-key-baseline", [
        ("root", "every", "self-certifying-identifier", None),
        ("actor", "every", "self-certifying-identifier", None),
        ("actor", "every", "offline-verifiable", None),
    ])
    anchor = _native.TrustAnchor(
        root.principal, _native.Principal(root.principal),
        ["raw-key-v1"], [("auths.mcp", 2)],
        [("tools/call", resource)], [audience], [audience],
        start, end, None, 2, "raw-key-baseline", None,
    )
    compiled = _native.compile_trusted_context(
        _native.self_contained_configuration(), None, 1, 1, 1,
        [anchor], assurance, None, None, "none-v1", ["raw-key-v1"], [],
    )
    return bytes(_native.inspect_trusted_context(compiled))


def init_root(seed_file: Path, trust_file: Path, *, company: str,
              service: str, now: int | None = None) -> dict:
    if not company or not service or seed_file == trust_file:
        raise ValueError("company, service and separate output paths are required")
    if seed_file.exists() or trust_file.exists():
        raise FileExistsError("operator root already exists")
    now = int(time.time()) if now is None else now
    seed = secrets.token_bytes(32)
    root = OperatorRoot(seed)
    from auths import _native

    document = {
        "contract": "auths.google-read-root/v1",
        "company_id": company,
        "service": service,
        "root_principal": root.principal,
        "configuration_id": bytes(_native.self_contained_configuration()).hex(),
        "not_before": now,
        "expires_at": now + 86400,
        "trusted_template": base64.urlsafe_b64encode(
            _template(root, service, now, now + 86400),
        ).decode("ascii"),
    }
    _private_write(seed_file, seed)
    _private_write(trust_file, json.dumps(document, sort_keys=True).encode("utf-8"))
    return {key: document[key] for key in ("company_id", "service", "root_principal", "expires_at")}


def issue_employee(seed_file: Path, trust_file: Path, state_db: Path,
                   binding_ref: str, *, now: int | None = None) -> dict:
    if not 1 <= len(binding_ref) <= 256:
        raise ValueError("employee binding reference is invalid")
    now = int(time.time()) if now is None else now
    manifest = json.loads(_private_read(trust_file, 262_144))
    root = OperatorRoot(_private_read(seed_file, 32))
    from auths import _native

    if (manifest.get("contract") != "auths.google-read-root/v1"
            or manifest.get("root_principal") != root.principal
            or manifest.get("configuration_id") != bytes(_native.self_contained_configuration()).hex()
            or not manifest.get("not_before", 0) <= now < manifest.get("expires_at", 0)):
        raise ValueError("operator trust pin is unavailable")
    with sqlite3.connect(state_db) as db:
        row = db.execute("""SELECT company,person,issuer,subject,principal,identity_packet
            FROM employee_bindings WHERE binding_ref=? AND status='active'""", (
                binding_ref,
            )).fetchone()
    if row is None or row[0] != manifest["company_id"]:
        raise ValueError("employee enrollment is unavailable")
    binding = EmployeeBinding(row[0], row[1], row[2], row[3], row[4], binding_ref)
    grant = root.issue_employee(binding=binding, identity_packet=row[5],
                                service=manifest["service"], now=now,
                                lifetime=min(3600, manifest["expires_at"] - now))
    EmployeeAuthorityStore(state_db).save(grant, binding)
    return {"employee_binding_ref": binding_ref, "employee_principal": binding.principal,
            "root_principal": root.principal, "expires_at": grant.expires_at}


def offboard_employee(state_db: Path, binding_ref: str, company: str,
                      oauth_config: Path, fernet_key: Path) -> dict:
    """Close broker authority and sessions without a provider-network request."""
    if not company or not 1 <= len(binding_ref) <= 256:
        raise ValueError("company and employee binding reference are required")
    from .google_oauth import GoogleOAuthConfig

    config = GoogleOAuthConfig(**json.loads(_private_read(oauth_config, 4096)))
    config.validate()
    vault = TokenVault(state_db, encryption_key=_private_read(fernet_key, 128).strip(),
                       client_id=config.client_id)
    vault.offboard(binding_ref, company=company)
    return {"company_id": company, "employee_binding_ref": binding_ref,
            "status": "offboarded"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage AP-SPEC-070 company root custody")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init-root")
    init.add_argument("--seed-file", type=Path, required=True)
    init.add_argument("--trust-file", type=Path, required=True)
    init.add_argument("--company", required=True)
    init.add_argument("--service", default="atlas-drive")
    issue = commands.add_parser("issue-employee")
    issue.add_argument("--seed-file", type=Path, required=True)
    issue.add_argument("--trust-file", type=Path, required=True)
    issue.add_argument("--state-db", type=Path, required=True)
    issue.add_argument("--binding-ref", required=True)
    offboard = commands.add_parser("offboard-employee")
    offboard.add_argument("--state-db", type=Path, required=True)
    offboard.add_argument("--binding-ref", required=True)
    offboard.add_argument("--company", required=True)
    offboard.add_argument("--oauth-config", type=Path, required=True)
    offboard.add_argument("--fernet-key", type=Path, required=True)
    receipt = commands.add_parser("init-receipt-key")
    receipt.add_argument("--key-file", type=Path, required=True)
    propose = commands.add_parser("propose-pins", help="write a private export pin candidate for operator review")
    propose.add_argument("--connections", type=Path, required=True)
    propose.add_argument("--access-expectations", type=Path, required=True)
    propose.add_argument("--google-verification", type=Path)
    propose.add_argument("--scenario-dir", type=Path)
    propose.add_argument("--company", required=True)
    propose.add_argument("--instance", required=True)
    propose.add_argument("--definition-hash", required=True)
    propose.add_argument("--dataset-version", required=True)
    propose.add_argument("--google-customer-id", required=True)
    propose.add_argument("--google-primary-domain", required=True)
    propose.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "init-root":
        result = init_root(args.seed_file, args.trust_file,
                           company=args.company, service=args.service)
    elif args.command == "issue-employee":
        result = issue_employee(args.seed_file, args.trust_file,
                                args.state_db, args.binding_ref)
    elif args.command == "offboard-employee":
        result = offboard_employee(args.state_db, args.binding_ref, args.company,
                                   args.oauth_config, args.fernet_key)
    elif args.command == "propose-pins":
        scenario_results = ()
        if args.scenario_dir is not None:
            if args.scenario_dir.is_symlink() or not args.scenario_dir.is_dir():
                parser.error("scenario directory is unavailable")
            scenario_results = tuple(sorted(args.scenario_dir.glob("scenario-result-*.json")))
        pins, accepted = prepare_operator_pins(
            args.connections, args.access_expectations,
            company_id=args.company, instance_id=args.instance,
            definition_hash=args.definition_hash, dataset_version=args.dataset_version,
            google_customer_id=args.google_customer_id,
            google_primary_domain=args.google_primary_domain,
            scenario_results=scenario_results,
            google_verification=args.google_verification,
        )
        _private_write(args.out, (json.dumps(asdict(pins), sort_keys=True, indent=2) + "\n").encode("utf-8"))
        result = {"status": "review_required", "company_id": args.company,
                  "instance_id": args.instance,
                  "bundle_generation": accepted.bundle["bundle_generation"],
                  "google": accepted.status.google,
                  "pin_file": str(args.out)}
    else:
        seed = secrets.token_bytes(32)
        _private_write(args.key_file, seed)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw,
        )
        result = {"receipt_public_key": base64.urlsafe_b64encode(public).decode("ascii")}
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
