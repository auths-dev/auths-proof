"""``auths approve``: the reference approval surface.

It prints only the review native code returned for the exact request, asks
before signing, and never approves by default.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from ._operator import load_signer_file
from .adapters.custody import CustodySigner
from .authoring import (
    ApprovalRefused,
    ApprovalReview,
    AuthoringUnsuccessful,
    GrantEvidence,
    approve,
    decline,
    open_approval_request,
)

_REQUEST_PREFIX = "auths-ar1-"
_MAX_INPUT_BYTES = 131_072


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
    loaded = load_signer_file(args.signer)
    try:
        return await _answer(args, interactive, loaded.signer, loaded.grants, loaded.development)
    finally:
        await loaded.signer.aclose()


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
