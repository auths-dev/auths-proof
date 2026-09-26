"""``auths approve``: the reference approval surface.

It prints only the review native code returned for the exact request, asks
before signing, and never approves by default.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import importlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence, cast

from . import _native
from .adapters.custody import (
    CustodyDescriptor,
    CustodyKeyState,
    CustodyKind,
    CustodyLifecycle,
    CustodySignatureDescriptor,
    CustodySigned,
    CustodySigner,
    PublicControlEvidence,
    SigningRequest,
    SigningResponse,
)
from .authoring import (
    ApprovalRefused,
    ApprovalReview,
    AuthoringUnsuccessful,
    GrantEvidence,
    approve,
    decline,
    open_approval_request,
)

_SIGNER_SCHEMA = "auths.approval-signer/1"
_REQUEST_PREFIX = "auths-ar1-"
_MAX_INPUT_BYTES = 131_072
_MAX_CONFIG_BYTES = 1_048_576


class _DevelopmentSigner:
    """Development custody over a local Ed25519 seed file."""

    def __init__(self, seed: bytes) -> None:
        self._key = _native.DevelopmentEd25519Key.from_seed(seed)
        self.descriptor = CustodyDescriptor(
            "signer-custody/2",
            CustodyKind.WORKLOAD,
            "auths.development-ed25519",
            self._key.principal,
            CustodySignatureDescriptor(
                self._key.principal_method, self._key.verification_method, self._key.suite
            ),
            "development-1",
            CustodyKeyState.ACTIVE_CURRENT,
            CustodyLifecycle.EPHEMERAL,
        )

    async def sign(self, request: SigningRequest) -> CustodySigned:
        return CustodySigned(
            "signed",
            SigningResponse(
                request.request_id,
                request.object_id,
                self.descriptor.principal,
                self.descriptor.signature,
                self.descriptor.key_version,
                request.transaction_digest,
                bytes(self._key.sign(request.signing_preimage)),
                (
                    PublicControlEvidence(
                        self._key.evidence_type, self._key.media_type, bytes(self._key.evidence)
                    ),
                ),
            ),
        )

    async def aclose(self) -> None:
        return None


def _b64(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError("signer configuration base64 values must be strings")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("signer configuration entries must be objects")
    return cast(dict[str, object], value)


def _items(value: object, limit: int) -> list[object]:
    if not isinstance(value, list) or len(cast(list[object], value)) > limit:
        raise ValueError(f"signer configuration lists hold at most {limit} entries")
    return cast(list[object], value)


def _grant(value: object) -> GrantEvidence:
    grant = _mapping(value)
    return GrantEvidence(
        _b64(grant.get("signed_grant_b64")),
        tuple(
            PublicControlEvidence(
                str(item.get("evidence_type")), str(item.get("media_type")), _b64(item.get("bytes_b64"))
            )
            for item in map(_mapping, _items(grant.get("evidence", []), 32))
        ),
    )


def _signer(path: Path) -> tuple[CustodySigner, tuple[GrantEvidence, ...], bool]:
    """Returns the signer, its grant chain, and whether it is development custody."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_CONFIG_BYTES:
        raise ValueError("signer configuration is unavailable or outside bounds")
    config = _mapping(json.loads(path.read_text(encoding="utf-8")))
    if config.get("schema") != _SIGNER_SCHEMA:
        raise ValueError(f"signer configuration must declare schema {_SIGNER_SCHEMA}")
    grants = tuple(_grant(item) for item in _items(config.get("grants", []), 16))
    custody = config.get("custody")
    if custody == "development-ed25519":
        seed_file = config.get("seed_file")
        if not isinstance(seed_file, str):
            raise ValueError("development custody needs seed_file")
        seed = (path.parent / seed_file).resolve().read_bytes()
        if len(seed) != 32:
            raise ValueError("development seed must contain 32 bytes")
        return _DevelopmentSigner(seed), grants, True
    if custody == "module":
        target = config.get("python")
        if not isinstance(target, str) or ":" not in target:
            raise ValueError("module custody needs python = 'package.module:factory'")
        module_name, _, factory_name = target.partition(":")
        factory: Callable[[dict[str, object]], CustodySigner] = getattr(
            importlib.import_module(module_name), factory_name
        )
        signer = factory(config)
        if signer.descriptor.contract != "signer-custody/2":
            raise ValueError("module custody factory did not return a custody signer")
        return signer, grants, False
    raise ValueError("signer custody must be development-ed25519 or module")


def _moment(seconds: int) -> str:
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _render(review: ApprovalReview) -> str:
    lines = [review.title]
    lines.extend(f"  {label}: {value}" for label, value in review.fields)
    lines.append(f"Display digest: {review.display_digest_hex}")
    lines.append(f"Requested by: {review.requester}")
    lines.append(f"Approvals required: {review.required} of {len(review.approvers)}")
    lines.extend(
        f"  {approver}{' (you)' if approver == review.approver else ''}"
        for approver in review.approvers
    )
    lines.append(
        f"Window: {_moment(review.valid_from)} to {_moment(review.valid_until)}"
        f" ({review.valid_from}..{review.valid_until})"
    )
    lines.append(f"Request: {review.request_id.hex()}")
    return "\n".join(lines)


def _read_request(value: str) -> bytes:
    if value.startswith(_REQUEST_PREFIX):
        return value.encode("utf-8")
    path = Path(value)
    if not path.is_file() or path.stat().st_size > _MAX_INPUT_BYTES:
        raise ValueError("request file is unavailable or outside bounds")
    return path.read_bytes()


async def _run(args: argparse.Namespace, interactive: bool) -> int:
    signer, grants, development = _signer(args.signer)
    try:
        return await _answer(args, interactive, signer, grants, development)
    finally:
        await signer.aclose()


async def _answer(
    args: argparse.Namespace,
    interactive: bool,
    signer: CustodySigner,
    grants: tuple[GrantEvidence, ...],
    development: bool,
) -> int:
    try:
        review = open_approval_request(_read_request(args.request))
    except ApprovalRefused as refused:
        print(f"auths: request refused: {refused.code}; nothing was signed", file=sys.stderr)
        return 1
    print(_render(review), file=sys.stderr)
    if development:
        print("Signer: development custody (a local key file)", file=sys.stderr)
    question = "Decline this action? [y/N] " if args.decline else "Approve this action? [y/N] "
    if args.yes:
        confirmed = True
    elif not interactive:
        print(
            "auths: no terminal to confirm on; pass --yes to answer without a prompt."
            " Nothing was signed.",
            file=sys.stderr,
        )
        return 2
    else:
        print(question, end="", file=sys.stderr, flush=True)
        confirmed = sys.stdin.readline().strip().lower() in ("y", "yes")
    if not confirmed:
        print("Not answered; nothing was signed.", file=sys.stderr)
        return 1
    try:
        if args.decline:
            response = await decline(review, signer, grants=grants)
        else:
            response = await approve(review, signer, grants=grants)
    except ApprovalRefused as refused:
        print(f"auths: refused: {refused.code}; nothing was signed", file=sys.stderr)
        return 1
    except AuthoringUnsuccessful as unsuccessful:
        print(f"auths: custody {unsuccessful.kind}: {unsuccessful.code}", file=sys.stderr)
        return 1
    if args.out is None:
        print(response.text)
    else:
        args.out.write_text(response.text + "\n", encoding="utf-8")
        print(f"{'Declined' if args.decline else 'Approved'}; wrote {args.out}", file=sys.stderr)
    return 0


def approve_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="auths approve",
        description="Review one approval request and answer it with your own custody.",
    )
    parser.add_argument("request", help="request file, or the auths-ar1- text itself")
    parser.add_argument("--signer", type=Path, required=True, help="custody configuration file")
    parser.add_argument("--decline", action="store_true", help="sign a decline instead")
    parser.add_argument("--yes", action="store_true", help="answer without a prompt")
    parser.add_argument("--out", type=Path, help="write the response here instead of stdout")
    args = parser.parse_args(list(argv))
    try:
        return asyncio.run(_run(args, sys.stdin.isatty()))
    except (OSError, UnicodeError, ValueError, KeyError, ImportError, AttributeError, TypeError) as error:
        print(f"auths: {error}", file=sys.stderr)
        return 1
