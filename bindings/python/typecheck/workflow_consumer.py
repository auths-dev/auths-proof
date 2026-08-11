from auths import (
    Approval,
    ApprovalProvider,
    AttachedAgent,
    AuthsClient,
    BudgetCeiling,
    DelegatedAuthority,
    Permission,
    Profile,
    SignedGrantInput,
    Signer,
    SnapshotRequired,
    TrustedAuthority,
    Validity,
)


async def attach_and_delegate(
    *,
    parent_signer: Signer,
    child_signer: Signer,
    approval_provider: ApprovalProvider,
    trusted_authority: TrustedAuthority,
    root_grant: SignedGrantInput,
) -> AttachedAgent:
    approval = Approval.grant_only("approval.default", approval_provider)
    client = AuthsClient(
        signer=parent_signer,
        trusted_authority=trusted_authority,
    )
    await client.open()
    parent = await client.attach_agent(
        name="research-agent",
        profile=Profile("auths.mcp", 1),
        authority=root_grant,
        approval=approval,
    )
    return await parent.delegate(
        name="records-child",
        authority=DelegatedAuthority(
            permissions=(Permission("tools/call", "mcp://records/tools/update"),),
            validity=Validity(20, 80),
            audiences=("mcp://records",),
            remaining_depth=0,
            budget=BudgetCeiling("numeric-ceiling-v1", 1),
            status=SnapshotRequired("status.local-v1", 30),
        ),
        signer=child_signer,
    )
