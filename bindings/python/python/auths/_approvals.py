"""Approval policy values and provider ports."""

from __future__ import annotations

import asyncio
from typing import Sequence

from ._native import ApprovalPolicyReference, approval_policy_reference
from ._errors import ProviderOperationError
from ._workflow import (
    Approval,
    ApprovalConfiguration,
    ApprovalDecision,
    ApprovalMode,
    ApprovalPolicy,
    ApprovalProvider,
    ApprovalRequest,
    ApprovalResponse,
)


class ThresholdApprovalProvider:
    def __init__(
        self, providers: Sequence[ApprovalProvider], *, threshold: int
    ) -> None:
        values = tuple(providers)
        if (
            type(threshold) is not int
            or threshold < 1
            or threshold > len(values)
            or len(values) > 16
            or len({id(value) for value in values}) != len(values)
        ):
            raise ValueError("invalid threshold approval configuration")
        self._providers = values
        self._threshold = threshold

    async def approve(self, request: ApprovalRequest) -> ApprovalResponse:
        results = await asyncio.gather(
            *(provider.approve(request) for provider in self._providers),
            return_exceptions=True,
        )
        approved = 0
        for result in results:
            if isinstance(result, BaseException):
                continue
            if type(result) is not ApprovalResponse:
                raise ProviderOperationError("rejected")
            if (
                result.request_id != request.request_id
                or result.transaction_digest != request.transaction_digest
                or not result.policy.matches(request.policy)
            ):
                raise ProviderOperationError("rejected")
            if result.decision == "approved":
                approved += 1
        return ApprovalResponse(
            request.request_id,
            request.transaction_digest,
            request.policy,
            "approved" if approved >= self._threshold else "rejected",
        )


def threshold_approval(
    providers: Sequence[ApprovalProvider], *, threshold: int
) -> ApprovalProvider:
    return ThresholdApprovalProvider(providers, threshold=threshold)


__all__ = [
    "Approval",
    "ApprovalConfiguration",
    "ApprovalDecision",
    "ApprovalMode",
    "ApprovalPolicy",
    "ApprovalPolicyReference",
    "ApprovalProvider",
    "ApprovalRequest",
    "ApprovalResponse",
    "ThresholdApprovalProvider",
    "approval_policy_reference",
    "threshold_approval",
]
