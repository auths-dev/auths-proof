# Ambitious Auths Demo Prompts

These prompts are designed for an implementation agent with no prior knowledge of Auths. Each prompt is standalone and asks for a complete, runnable product demonstration rather than a scripted mock.

| Prompt | Best proof | Primary audience |
| --- | --- | --- |
| [Cross-company incident response](01_CROSS_COMPANY_INCIDENT_RESPONSE.md) | The broadest end-to-end Auths demonstration | Platform and security leaders |
| [Autonomous software release federation](02_AUTONOMOUS_SOFTWARE_RELEASE_FEDERATION.md) | Human and agent authority over exact artifacts | Developers and infrastructure teams |
| [International shipment chain of custody](03_INTERNATIONAL_SHIPMENT_CHAIN_OF_CUSTODY.md) | Portable identity across intermittent transports | Supply-chain and IoT teams |
| [M&A confidential data clean room](04_MA_CONFIDENTIAL_DATA_CLEAN_ROOM.md) | Cross-company collaboration without shared accounts | Enterprise buyers |
| [Federated AI compute and data marketplace](05_FEDERATED_AI_COMPUTE_MARKETPLACE.md) | Independent owners safely composing agentic work | AI platform builders |
| [Agent-driven multi-cloud cluster lifecycle](06_AGENT_DRIVEN_MULTI_CLOUD_CLUSTER_LIFECYCLE.md) | Safe agent control over expensive, destructive infrastructure | AI and hyperscale infrastructure teams |

## Shared proof standard

Every completed demo must visibly establish that:

- Authentication, Auths identity, signing suite, transport, storage, profiles, authority, approvals, and execution are separate choices.
- At least two organizations operate as genuinely separate trust and persistence domains.
- Humans and agents participate in the same workflow without being treated as the same kind of actor.
- Rust remains the owner of Auths semantics; TypeScript and Python do not reproduce protocol meaning.
- A valid transport delivery does not imply authorization.
- Delegated authority can narrow but cannot expand.
- Approval binds an exact action or plan, not a vague intention.
- Rotation, expiry, compromise, revocation, withdrawal, replay, and partial execution have visible outcomes.
- Python and TypeScript agree when they inspect or verify the same portable artifacts.
- Successful and failed operations produce useful diagnostics, telemetry, and receipts.

The strongest general flagship is the cross-company incident-response demo. The software-release demo is the most immediately legible to developers. The cluster-lifecycle demo is the strongest proof for AI infrastructure, cloud platform, and hyperscale operations teams.
