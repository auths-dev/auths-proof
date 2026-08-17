"""Qualified Auths effect verticals."""

from dataclasses import dataclass
from typing import Literal, Union

from ._mcp import (
    DevelopmentMcpProvider,
    McpAction,
    McpClosedProvider,
    McpCompleted,
    McpExecutionCheckpointEvent,
    McpExecutionCheckpointStage,
    McpExecutionObserver,
    McpHandlerOutcome,
    McpPlan,
    McpPlanCompleted,
    McpPlanRecoveryResult,
    McpRecoverable,
    McpToolAuthority,
    McpToolContext,
    mcp,
)

ServiceProfileId = Union[
    Literal["auths.opentofu.saved-plan-apply/1"],
    Literal["auths.postgresql.bounded-update/1"],
    Literal["auths.github.issue-address/1"],
]


@dataclass(frozen=True)
class ServiceProfile:
    id: ServiceProfileId


def opentofu_saved_plan_apply() -> ServiceProfile:
    return ServiceProfile("auths.opentofu.saved-plan-apply/1")


def postgresql_bounded_update() -> ServiceProfile:
    return ServiceProfile("auths.postgresql.bounded-update/1")


def github_issue_address() -> ServiceProfile:
    return ServiceProfile("auths.github.issue-address/1")

__all__ = [
    "DevelopmentMcpProvider",
    "McpAction",
    "McpClosedProvider",
    "McpCompleted",
    "McpExecutionCheckpointEvent",
    "McpExecutionCheckpointStage",
    "McpExecutionObserver",
    "McpHandlerOutcome",
    "McpPlan",
    "McpPlanCompleted",
    "McpPlanRecoveryResult",
    "McpRecoverable",
    "McpToolAuthority",
    "McpToolContext",
    "mcp",
    "ServiceProfile",
    "ServiceProfileId",
    "github_issue_address",
    "opentofu_saved_plan_apply",
    "postgresql_bounded_update",
]
