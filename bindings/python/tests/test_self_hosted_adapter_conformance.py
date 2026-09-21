"""Public adapter testkit exercises exact verification and local one-use order."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest
from auths.execution import Observation, ProviderOutcome, ProviderRejected
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
    assert len(report.cases) == 14
    manifest = json.loads((Path(__file__).parents[2] / "fixtures" / "self-hosted-profile" /
                           "adapter-scenarios-v1.json").read_text())
    assert [case.id for case in report.cases] == manifest["mandatoryCaseIds"]
    assert {
        "claim-failure-before-credential",
        "finish-failure-after-provider-entry",
        "replay-after-restart",
        "post-entry-interruption-unknown",
    }.issubset({case.id for case in report.cases})
    assert report.metadata.assurance == "test-results-only-not-security-certification"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("defect", "failed_case"),
    [
        ("credential-before-claim", "denied-before-credential"),
        ("duplicate-write", "authorized-one-write-and-replay"),
        ("retry-on-timeout", "timeout-no-blind-retry"),
        ("false-definite-rejection", "authorized-one-write-and-replay"),
        ("write-during-reconcile", "unknown-no-blind-retry"),
    ],
)
async def test_broken_adapters_fail_mandatory_case(defect: str, failed_case: str) -> None:
    contract = ExactMcpTool(
        service="example-service", name="set_value_v1", command_type=Command,
        fields={"value": StringField(1, 32)},
    )

    class BrokenAdapter(Adapter):
        async def invoke(self, command: Command, credential: str) -> ProviderOutcome[str]:
            if defect == "duplicate-write":
                await self.provider.write(command, credential)
            if defect == "retry-on-timeout":
                try:
                    return await self.provider.write(command, credential)
                except TimeoutError:
                    return await self.provider.write(command, credential)
            result = await self.provider.write(command, credential)
            if defect == "false-definite-rejection":
                return ProviderRejected("claimed-no-effect")
            return result

        async def observe(self, command: Command) -> Observation:
            if defect == "write-during-reconcile" and self.provider.scenario == "unknown":
                await self.provider.write(command, "synthetic-token")
            return await self.provider.read(command)

    def factory(provider: ScriptedProvider) -> BrokenAdapter:
        if defect == "credential-before-claim":
            provider.trace.append("credential")
        return BrokenAdapter(provider)

    report = await run_self_hosted_adapter_conformance(
        contract=contract, command=Command("approved"), adapter_factory=factory,
    )
    assert not report.passed
    case = next(case for case in report.cases if case.id == failed_case)
    assert case.status == "failed"
    assert case.detail_code == "contract-mismatch"
