"""AP-SPEC-071 producer handoff until demo_co publishes a write contract.

This module deliberately cannot activate a write. The producer owns the
versioned fixture and independent probe schema; inventing either here would
turn a local placeholder into false provider evidence.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path


class WriteHandoffPending(RuntimeError):
    """No reviewed producer export can authorize the Google write vertical."""


@dataclass(frozen=True)
class WriteHandoffStatus:
    contract: str
    status: str
    reason: str

    @property
    def ready(self) -> bool:
        return False

    def require_ready(self) -> None:
        raise WriteHandoffPending(self.reason)


def inspect_write_handoff(export: Path | None = None) -> WriteHandoffStatus:
    """Report the unimplemented producer contract without trusting local files.

    Even a supplied file is not evidence until its versioned schema, operator
    pins and independent provider probes have been reviewed and implemented.
    Avoid reading it: it may contain private data and has no accepted format.
    """
    if export is None:
        reason = "demo_co has not published a versioned Google write handoff"
    else:
        reason = "a local file is not a reviewed Google write handoff"
    return WriteHandoffStatus(
        contract="auths.demo-co-google-write-handoff-status/v0",
        status="write_not_configured",
        reason=reason,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect AP-SPEC-071 producer write readiness")
    parser.add_argument("--export", type=Path)
    args = parser.parse_args()
    print(json.dumps(asdict(inspect_write_handoff(args.export)), sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
