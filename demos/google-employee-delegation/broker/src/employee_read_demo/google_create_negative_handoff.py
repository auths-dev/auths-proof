"""Fail-closed handoff for demo_co's pending recovery-refusal evidence.

demo_co owns disposable scratch fixtures and their independent provider
observations. This module remains deliberately non-authoritative until a
forward-only negative-case schema and producer rule are frozen and pinned.
It must never be used to infer child authority from an Auths search alone.
"""

from pathlib import Path

from .demo_co_contract import ContractRejected


def validate_create_recovery_negative_observation(
    _observation_path: Path,
    *,
    _run_id: str,
    _expected_case: str,
) -> None:
    """Refuse a recovery-negative evidence claim until its contract is installed."""
    raise ContractRejected("demo_co recovery-negative producer contract is not ready")
