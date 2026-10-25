"""Private operator issuance for AP-071 native task and write authority.

This is a development handoff. It reads the existing company root seed and
enrolled human identity, then writes an owner-only package for the task broker
and gateway installer. It never reads a Google token or signs for the human.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sqlite3
import stat
import time
from pathlib import Path

from .enrollment import EmployeeBinding
from .operator_authority import OperatorRoot
from .operator_cli import _private_read, _private_write
from .task_write_authority import issue_task_write_authority


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def issue_task_package(
    *,
    root_seed: Path,
    root_trust: Path,
    state_db: Path,
    binding_ref: str,
    company: str,
    provider_service: str,
    provider_tool: str,
    recipe_digest: str,
    output: Path,
    now: int | None = None,
) -> dict:
    """Write a private, one-hour authority package for one enrolled human.

    The operator must take the provider profile and digest from the reviewed
    gateway recipe. The gateway later checks the installed digest itself.
    This package contains no provider credential, human key or agent key.
    """
    if (not isinstance(binding_ref, str) or not 1 <= len(binding_ref) <= 256
            or not isinstance(company, str) or not 1 <= len(company) <= 128
            or not isinstance(recipe_digest, str)
            or _DIGEST.fullmatch(recipe_digest) is None
            or root_seed == output or root_trust == output or state_db == output
            or state_db.is_symlink() or not state_db.is_file()
            or stat.S_IMODE(state_db.stat().st_mode) & 0o077):
        raise ValueError("operator task authority inputs are invalid")
    now = int(time.time()) if now is None else now
    root = OperatorRoot(_private_read(root_seed, 32))
    from auths import _native

    manifest = json.loads(_private_read(root_trust, 262_144))
    if (type(manifest) is not dict
            or manifest.get("contract") != "auths.google-read-root/v1"
            or manifest.get("company_id") != company
            or manifest.get("root_principal") != root.principal
            or manifest.get("configuration_id")
            != bytes(_native.self_contained_configuration()).hex()
            or type(manifest.get("not_before")) is not int
            or type(manifest.get("expires_at")) is not int
            or not manifest["not_before"] <= now < manifest["expires_at"]
            or manifest["expires_at"] - now < 60):
        raise ValueError("company root trust is unavailable")
    with sqlite3.connect(state_db.as_uri() + "?mode=ro", uri=True) as db:
        row = db.execute("""SELECT company,person,issuer,subject,principal,identity_packet
            FROM employee_bindings WHERE binding_ref=? AND status='active'""", (
                binding_ref,
            )).fetchone()
    if row is None or row[0] != company:
        raise ValueError("enrolled employee is unavailable")
    binding = EmployeeBinding(row[0], row[1], row[2], row[3], row[4], binding_ref)
    authority = issue_task_write_authority(
        root, binding, row[5], provider_service=provider_service,
        provider_tool=provider_tool, now=now,
        lifetime=min(3600, manifest["expires_at"] - now),
    )
    encode = lambda value: base64.urlsafe_b64encode(value).decode("ascii")
    package = {
        "schema": "auths.ap071-task-authority/1",
        "company_id": company,
        "binding_ref": binding_ref,
        "root_principal": authority.root_principal,
        "human_principal": authority.human_principal,
        "provider_service": authority.provider_service,
        "provider_tool": authority.provider_tool,
        "recipe_digest": recipe_digest,
        "not_before": authority.not_before,
        "expires_at": authority.expires_at,
        "trusted_template_b64": encode(authority.trusted_template),
        "approval_grant_b64": encode(authority.approval_grant.signed_grant),
        "confirmation_grant_b64": encode(authority.confirmation_grant.signed_grant),
        "write_parent_grant_b64": encode(authority.write_parent_grant.signed_grant),
        "root_evidence_b64": encode(authority.approval_grant.root_evidence),
        "human_evidence_b64": encode(authority.approval_grant.employee_evidence),
    }
    _private_write(output, json.dumps(package, sort_keys=True,
                                      separators=(",", ":")).encode("utf-8"))
    return {
        "status": "authority_issued",
        "company_id": company,
        "human_principal": authority.human_principal,
        "root_principal": authority.root_principal,
        "provider_service": provider_service,
        "provider_tool": provider_tool,
        "recipe_digest": recipe_digest,
        "expires_at": authority.expires_at,
        "package": str(output),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Issue private AP-071 task authority")
    parser.add_argument("--root-seed", type=Path, required=True)
    parser.add_argument("--root-trust", type=Path, required=True)
    parser.add_argument("--state-db", type=Path, required=True)
    parser.add_argument("--binding-ref", required=True)
    parser.add_argument("--company", required=True)
    parser.add_argument("--provider-service", required=True)
    parser.add_argument("--provider-tool", required=True)
    parser.add_argument("--recipe-digest", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = issue_task_package(
        root_seed=args.root_seed, root_trust=args.root_trust, state_db=args.state_db,
        binding_ref=args.binding_ref, company=args.company,
        provider_service=args.provider_service, provider_tool=args.provider_tool,
        recipe_digest=args.recipe_digest, output=args.out,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
