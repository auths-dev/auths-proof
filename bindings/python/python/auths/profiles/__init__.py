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

ProductionProfileId = Union[
    Literal["auths.opentofu.saved-plan-apply/1"],
    Literal["auths.postgresql.bounded-update/1"],
    Literal["auths.github.issue-address/1"],
]


@dataclass(frozen=True)
class ProductionProfile:
    id: ProductionProfileId


def opentofu_saved_plan_apply() -> ProductionProfile:
    return ProductionProfile("auths.opentofu.saved-plan-apply/1")


def postgresql_bounded_update() -> ProductionProfile:
    return ProductionProfile("auths.postgresql.bounded-update/1")


def github_issue_address() -> ProductionProfile:
    return ProductionProfile("auths.github.issue-address/1")

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
    "ProductionProfile",
    "ProductionProfileId",
    "github_issue_address",
    "opentofu_saved_plan_apply",
    "postgresql_bounded_update",
]
