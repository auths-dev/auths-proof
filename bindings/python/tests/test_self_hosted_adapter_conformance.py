"""Public adapter testkit exercises exact verification and local one-use order."""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from auths.execution import Observation, ProviderOutcome
from auths.self_hosted import ExactMcpTool, StringField
from auths.testkit import ScriptedProvider, run_self_hosted_adapter_conformance


@dataclass(frozen=True)
class Command:
    value: str


class Adapter:
    def __init__(self, provider: ScriptedProvider) -> None:
        self.provider = provider

    def credential(self) -> str:
        return "synthetic-token"

    async def invoke(self, command: Command, credential: str) -> ProviderOutcome[str]:
        return await self.provider.write(command, credential)

    async def observe(self, command: Command) -> Observation:
        return await self.provider.read(command)


@pytest.mark.asyncio
async def test_adapter_conformance_exercises_all_mandatory_cases() -> None:
    contract = ExactMcpTool(
        service="example-service", name="set_value_v1", command_type=Command,
        fields={"value": StringField(1, 32)},
    )
    report = await run_self_hosted_adapter_conformance(
        contract=contract, command=Command("approved"), adapter_factory=Adapter,
    )
    assert report.passed, report.cases
    assert len(report.cases) == 10
    assert report.metadata.assurance == "test-results-only-not-security-certification"
