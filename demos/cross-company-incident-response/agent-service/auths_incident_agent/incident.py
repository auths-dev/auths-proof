from __future__ import annotations

import time
from typing import Any, Literal

from auths import Approval, AuthsClient, Signer, Validity, prepare_raw_key_authority
from auths.approvals import threshold_approval
from auths.profile_kit import (
    ApplicationGatewayOptions,
    ApplicationPlanAuthorized,
)
from auths.profiles import DomainProfileOptions, EdgeActionInput, load_domain_profiles
from auths.receipts import ReceiptAttestor

from .approval_adapters import (
    EdgeShieldSignedApproval,
    GrantBootstrapApproval,
    NorthstarOidcApproval,
)
from .execution import (
    IncidentCredentials,
    IncidentProvider,
    SqliteExecutionStore,
    application_receipt_json,
    canonical_result,
)


async def execute_incident_plan(
    *,
    store: SqliteExecutionStore,
    northstar_url: str,
    edgeshield_url: str,
    service_token: str,
    certificate_fingerprint: str,
    root_signer: Signer,
    agent_signer: Signer,
    receipt_attestor: ReceiptAttestor,
    provider_fault: Literal["none", "unknown-after-firewall"] = "none",
) -> dict[str, Any]:
    profile = load_domain_profiles().edge(
        DomainProfileOptions("incident://northstar-edge", "edge://northstar")
    )
    plan = profile.plan(
        (
            profile.action(
                EdgeActionInput(
                    "northstar",
                    "firewall-eu-west-2",
                    "apply-config",
                    185,
                    "184".zfill(64),
                )
            ),
            profile.action(
                EdgeActionInput(
                    "northstar",
                    "cache-eu-west-2",
                    "execute",
                    992,
                    "991".zfill(64),
                )
            ),
        )
    )
    threshold = threshold_approval(
        (
            NorthstarOidcApproval(northstar_url),
            EdgeShieldSignedApproval(edgeshield_url, certificate_fingerprint),
        ),
        threshold=2,
    )
    approval = Approval.plan_once(
        "auths-incident-demo.cross-company-2-of-2",
        GrantBootstrapApproval(threshold),
        max_uses=2,
        expires_in_seconds=600,
        requirements=(
            "northstar:incident-commander",
            "edgeshield:on-call",
        ),
    )
    now = int(time.time())
    prepared = await prepare_raw_key_authority(
        authority_id="auths-incident-demo.edgeshield-root",
        root_signer=root_signer,
        subject=await agent_signer.public_identity(),
        profile=profile,
        permissions=plan.authority.permissions,
        resource_namespaces=plan.authority.resource_namespaces,
        validity=Validity(now - 5, now + 600),
        audiences=plan.authority.audiences,
        remaining_depth=0,
        approval=approval,
    )
    client = AuthsClient(
        signer=agent_signer, trusted_authority=prepared.trusted_authority
    )
    await client.open()
    try:
        agent = await client.attach_agent(
            name="edgeshield-remediation-agent",
            profile=profile,
            authority=prepared.authority,
            approval=approval,
        )
        authorization = await agent.authorize_plan(plan)
        if not isinstance(authorization, ApplicationPlanAuthorized):
            failed = authorization.result
            return {
                "kind": authorization.kind,
                "code": failed.code,
                "stage": failed.stage,
                "credentialAcquisitions": 0,
                "providerCalls": 0,
            }
        provider = IncidentProvider(
            store,
            northstar_url=northstar_url,
            edgeshield_url=edgeshield_url,
            fault=provider_fault,
        )
        gateway = profile.gateway(
            ApplicationGatewayOptions(
                store,
                IncidentCredentials(
                    store,
                    service_token=service_token,
                    certificate_fingerprint=certificate_fingerprint,
                ),
                receipt_attestor,
                provider.execute,
                canonical_result,
            )
        )
        results, receipts = await gateway.execute_plan(
            authorization.command,
            idempotency_key="INC-2026-0811:remediation:v1",
        )
        return {
            "kind": "executed",
            "planCommitment": plan.commitment.hex(),
            "authorization": [
                {
                    "kind": value.kind,
                    "code": value.code,
                    "stage": value.stage,
                    "result": value.result_cbor.hex(),
                }
                for value in authorization.results
            ],
            "results": list(results),
            "receipts": [application_receipt_json(value) for value in receipts],
        }
    finally:
        await client.aclose()
        await root_signer.aclose()


__all__ = ["execute_incident_plan"]
