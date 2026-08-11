from __future__ import annotations

import time
from typing import Tuple

from . import _native as native
from .errors import AuthsWorkflowError, ProviderOperationError
from .workflow import (
    ApprovalConfiguration,
    ApprovalProvider,
    ApprovalRequest,
    ApprovalResponse,
    ReviewField,
)


class _PlanMemberApproval:
    def __init__(
        self, session: PlanApprovalSession, index: int, member_commitment: bytes
    ) -> None:
        self._session = session
        self._index = index
        self._member_commitment = member_commitment

    async def approve(self, request: ApprovalRequest) -> ApprovalResponse:
        return await self._session.approve_member(
            self._index, self._member_commitment, request
        )


class PlanApprovalSession:
    def __init__(
        self,
        *,
        plan_approval: bytes,
        member_commitments: Tuple[bytes, ...],
        approval: ApprovalConfiguration,
        provider: ApprovalProvider,
        expires_at: int,
        display: Tuple[ReviewField, ...],
    ) -> None:
        self._plan_approval = bytearray(plan_approval)
        self._member_commitments = tuple(
            bytearray(value) for value in member_commitments
        )
        self._approval = approval
        self._provider = provider
        self._expires_at = expires_at
        self._display = display
        self._uses = 0
        self._approved = False
        self._disposed = False

    def provider_for(self, index: int, member_commitment: bytes) -> ApprovalProvider:
        if self._disposed:
            raise AuthsWorkflowError(
                "approval-cancelled", "plan approval session is disposed"
            )
        if (
            type(index) is not int
            or index < 0
            or index >= len(self._member_commitments)
            or len(member_commitment) != 32
            or not native.commitments_equal_v1(
                bytes(self._member_commitments[index]), member_commitment
            )
        ):
            raise AuthsWorkflowError(
                "approval-response-mismatch",
                "approval plan member commitment mismatch",
            )
        return _PlanMemberApproval(self, index, bytes(member_commitment))

    async def approve_member(
        self, index: int, member_commitment: bytes, request: ApprovalRequest
    ) -> ApprovalResponse:
        now = int(time.time())
        if self._disposed:
            raise ProviderOperationError("cancelled")
        if now > self._expires_at or now > request.expires_at:
            raise ProviderOperationError("timeout")
        if self._uses >= self._approval.policy.max_uses or index != self._uses:
            raise ProviderOperationError("rejected")
        if not native.commitments_equal_v1(
            bytes(self._member_commitments[index]), member_commitment
        ):
            raise ProviderOperationError("rejected")
        if not request.policy.matches(self._approval.policy.reference):
            raise ProviderOperationError("rejected")
        if not self._approved:
            response = await self._provider.approve(
                ApprovalRequest(
                    request_id=request.request_id,
                    object_kind=request.object_kind,
                    transaction_digest=request.transaction_digest,
                    policy=request.policy,
                    expires_at=request.expires_at,
                    display=(
                        self._display
                        + (
                            ReviewField(
                                "Plan commitment", bytes(self._plan_approval).hex()
                            ),
                            ReviewField(
                                "Plan member",
                                f"{index + 1}/{len(self._member_commitments)}",
                            ),
                            ReviewField("Member commitment", member_commitment.hex()),
                        )
                        + request.display
                    ),
                )
            )
            if type(response) is not ApprovalResponse:
                raise ProviderOperationError("rejected")
            if response.decision != "approved":
                return response
            if (
                response.request_id != request.request_id
                or not native.commitments_equal_v1(
                    response.transaction_digest, request.transaction_digest
                )
                or not response.policy.matches(request.policy)
            ):
                raise ProviderOperationError("rejected")
            self._approved = True
        self._uses += 1
        return ApprovalResponse(
            request.request_id,
            request.transaction_digest,
            request.policy,
            "approved",
        )

    def dispose(self) -> None:
        self._disposed = True
        for index in range(len(self._plan_approval)):
            self._plan_approval[index] = 0
        for member in self._member_commitments:
            for index in range(len(member)):
                member[index] = 0
