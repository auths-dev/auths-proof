# Prompt: Build an Agent-Driven Multi-Cloud Cluster Lifecycle Control Plane

You are working in the `auths-dev/auths-proof` repository with no assumed prior knowledge of the project. Build an ambitious, production-shaped demonstration in which humans and autonomous agents safely provision, update, drain, recover, and decommission compute clusters across AWS, GCP, and an on-premises datacenter simulator.

This is not a cluster scheduler or another Terraform wrapper. It must prove that Auths can act as the portable authorization and accountability layer above cloud IAM, Kubernetes RBAC, OpenTofu, and workflow orchestration.

Work autonomously. Make reasonable product and engineering decisions rather than waiting for routine clarification.

## First: understand the repository

Before changing code:

1. Read `AGENTS.md` and every instruction it references.
2. Read the repository README, target-state architecture, TypeScript and Python elite SDK specifications, and the existing Kubernetes and OpenTofu integrations.
3. Inspect the Rust semantic core, public SDK surfaces, profiles, runtime ports, receipts, lifecycle model, differential fixtures, existing demos, and semantic-freeze machinery.
4. Identify the intended seams between identity providers, signing suites, cloud IAM, Kubernetes RBAC, transports, stores, profiles, approvals, orchestration, and effect execution.
5. Write a short implementation plan and execute it fully.

Do not reproduce Auths verification, authority, attenuation, approval, lifecycle, plan, command, or receipt semantics in application code. If the demo reveals a genuine missing SDK capability, add the smallest reusable Rust-owned operation and bind it consistently into the required SDKs.

## Product story

Build **Horizon Compute**, an AI company operating three independent compute environments:

- An AWS account and region simulator.
- A GCP project and region simulator.
- An on-premises datacenter and network simulator operated by a separate infrastructure partner.

Horizon employees authenticate through a local OAuth/OIDC provider and use P-256 Auths identities. On-premises operators authenticate through client certificates and use Ed25519 Auths identities. Provisioning, security, health, drain, recovery, and decommissioning agents each have distinct workload identities and narrowly bounded authority.

Authentication, Auths identity, signing suite, cloud account, Kubernetes principal, transport, and execution adapter must remain independent choices. Do not create one omnipotent service account behind the agents.

## Required actors

- Capacity-planning agent.
- Security-review agent.
- Cluster-provisioning agent.
- Cluster-health agent.
- Drain-and-recovery agent.
- Decommissioning agent.
- Infrastructure capacity owner.
- Security approver.
- On-call incident commander.
- On-premises datacenter operator.
- A compromised or malicious agent used by the attack lab.

Give each actor a visible identity, organization, signing suite, lifecycle state, current authority, and recent receipt history.

## Required cluster model

Each cluster request must bind at least:

- Provider, account or project, and region.
- Environment and cluster identifier.
- Control-plane and worker-node shape.
- Minimum, desired, and maximum node counts.
- Accelerator type and quantity.
- Cost or capacity ceiling.
- Network and private-connectivity profile.
- Kubernetes version and bootstrap configuration.
- CNI, network-policy, service-mesh, and mTLS posture.
- Node and container hardening profile.
- Approved image and provenance digests.
- OpenTofu plan digest.
- Validity window, required approvals, idempotency key, and rollback bounds.

Represent these as parsed, typed application-profile inputs. Do not pass an unstructured policy dictionary through the system.

## Required lifecycle workflow

1. Generate a research capacity request that requires new GPU capacity in all three environments.
2. Have the capacity agent propose cluster shapes, regions, budgets, and delivery deadlines without granting it execution authority.
3. Generate real OpenTofu plans against deterministic local provider simulators.
4. Have the security agent review Kubernetes admission policy, workload identity, network policy, image provenance, and node-hardening evidence.
5. Construct an exact Auths plan binding every provider plan, cluster profile, budget, image digest, and security artifact.
6. Require threshold approval from the capacity owner and security approver. Require the on-premises operator for the datacenter portion.
7. Issue profile-bound, one-use commands to independently scoped provisioning agents.
8. Execute the workflow through a real orchestration adapter such as Temporal or Argo Workflows while keeping Auths decisions outside the orchestration engine.
9. Bootstrap Kubernetes resources and show the resulting provider, cluster, network, and security state.
10. Simulate a host or availability-zone failure.
11. Let the health agent produce evidence and delegate only the authority required to drain and replace affected nodes.
12. Recover capacity without allowing the recovery agent to resize the fleet, change regions, alter networking, or deploy a different image.
13. Rotate one workload key and compromise another while work is active.
14. Require a separate, destructive threshold approval for cluster decommissioning.
15. Produce independently verifiable receipts for planning, approval, provisioning, draining, recovery, reconciliation, and decommissioning.
16. Verify selected portable artifacts in both Python and TypeScript and prove equivalent outcomes.

## Attack and failure lab

The product must let a user run each case and see the exact failed invariant:

- Change an OpenTofu plan after approval.
- Increase the node, accelerator, or cost ceiling.
- Move a cluster into a different account, project, or region.
- Expand a staging delegation into production.
- Let a child agent request broader authority than its parent.
- Substitute an unapproved node or container image.
- Ask the security-review agent to provision infrastructure.
- Replay a provisioning, drain, recovery, or decommission command.
- Execute after expiry, revocation, compromise, or approval withdrawal.
- Rotate a key during a multi-step lifecycle operation.
- Deliver an unauthorized command successfully over HTTPS or Iroh.
- Fail OpenTofu before apply, after a partial apply, and after success with the response lost.
- Lose the status service or network during incident response.
- Attempt decommissioning without destructive threshold approval.
- Reuse drain authority to modify networking or capacity.

Do not model these as frontend-only error messages. Exercise real SDK paths and show typed errors, status observations, completed plan members, unresolved effects, reconciliation requirements, and receipts.

## UX

Build a polished TypeScript operations console with an overview resembling:

```text
+--------------------------------------------------------------------------------+
| Horizon Compute · Global Cluster Lifecycle                                     |
| Capacity: 78%   Incidents: 1   Pending approvals: 2   Unknown outcomes: 0      |
+----------------------+----------------------+----------------------------------+
| AWS                  | GCP                  | On-premises                      |
| us-east · 32 nodes   | us-central · 24     | dc-lon-3 · 16 nodes             |
| Healthy              | Recovering           | Awaiting capacity               |
+----------------------+----------------------+----------------------------------+
| Active plan                                                                    |
| [Review evidence] -> [Approve exact plan] -> [Provision] -> [Verify receipts] |
+--------------------------------------------------------------------------------+
| Attack lab: [Mutate plan] [Expand authority] [Replay] [Partial apply]          |
+--------------------------------------------------------------------------------+
```

Include:

- Global fleet and capacity views.
- Separate cloud and datacenter trust-domain views.
- Human and agent identity inspectors.
- A readable authority and delegation graph.
- Exact OpenTofu plan and cluster-profile review.
- Security evidence and image-provenance inspection.
- Clearly separate review, approval, orchestration, and execution stages.
- Live workflow, node-drain, failure, recovery, and reconciliation timelines.
- Receipt inspection and side-by-side Python/TypeScript verification.
- An attack-lab panel with one control for every required failure case.

## Architecture

Use this separation as the minimum boundary:

```text
+--------------------+       +----------------------+       +-------------------+
| TypeScript console | ----> | Python control API   | ----> | Workflow engine   |
+--------------------+       +----------------------+       +-------------------+
          |                           |                              |
          | inspect/verify            | Auths plans and commands     | effects only
          v                           v                              v
+--------------------+       +----------------------+       +-------------------+
| Auths TS SDK       |       | Auths Python SDK     |       | Provider adapters |
+--------------------+       +----------------------+       +-------------------+
                                     |                       | AWS · GCP · DC    |
                                     v                       | OpenTofu · K8s    |
                              +----------------------+       +-------------------+
                              | Rust-owned semantics |
                              +----------------------+
```

Required constraints:

- Run AWS, GCP, and on-premises as separate services, configurations, stores, signing material, and trust domains.
- Use the repository's OpenTofu and Kubernetes integrations where they fit; improve reusable boundaries rather than duplicating them inside the demo.
- Keep provider, IdP, workload-identity, signing, transport, persistence, orchestration, Kubernetes, and profile adapters replaceable.
- Cloud IAM and Kubernetes RBAC remain local enforcement layers; Auths authorizes exact cross-system intent above them.
- A successful network delivery, workflow transition, Terraform apply, or Kubernetes API response never implies authorization.
- Review is not approval, approval is not execution, and execution is not proof of a known outcome.
- Preserve opaque native-owned verified authority and one-use command boundaries in both SDKs.
- Model retries, idempotency, partial application, cancellation, and outcome-unknown reconciliation explicitly.
- Prefer type-driven design, parse-don't-validate boundaries, DRY components, and minimal comments.
- Do not add prelaunch compatibility shims, aliases, deprecated entry points, or speculative frameworks.

## APIs and profiles

Implement application profiles through the maintained profile-kit surface for at least:

- `cluster.provision/1`
- `cluster.update/1`
- `cluster.drain/1`
- `cluster.recover/1`
- `cluster.decommission/1`

Every profile must define typed canonical inputs, permissions, resource namespaces, budgets, human-readable review fields, exact commitments, execution receipts, and failure meanings.

Expose a small application API covering:

- Capacity requests and cluster specifications.
- Plan generation and evidence attachment.
- Review and approval submission.
- Command issuance and execution.
- Lifecycle and identity status changes.
- Workflow cancellation and reconciliation.
- Cluster, actor, authority, and receipt inspection.
- Attack-lab scenario execution and deterministic reset.

The APIs may use HTTP for the product surface, but at least one agent-to-agent exchange must use Iroh through the transport abstraction. Keep transport bytes bounded and independent from authorization semantics.

## Deliverables

Place the implementation under `demos/agent-driven-cluster-lifecycle/` and provide:

- A one-command local launcher with deterministic seed state.
- A TypeScript operations console and Python control/agent services.
- Separate provider and datacenter simulators with independent state.
- Real OpenTofu plan generation and a local Kubernetes execution target.
- A real workflow-orchestration adapter with deterministic test doubles.
- All Auths application profiles, provider adapters, fixtures, and tests.
- A concise README with a ten-minute guided walkthrough.
- Architecture, trust-boundary, authority-flow, and lifecycle diagrams.
- A threat model tied directly to the attack lab.
- A table mapping every Auths feature to the screen, artifact, and test that proves it.
- Unit, integration, browser, cross-SDK, orchestration, lifecycle, replay, partial-apply, reconciliation, and adversarial tests.
- CI coverage using repository policies, owner commands, and pinned toolchains.

The local demo must run without paid cloud credentials. Optional hosted deployment must use clearly named disposable demo resources and must not weaken the separate trust domains.

## Definition of done

The demo is complete only when a new developer can launch it, request capacity, inspect exact plans, approve and provision three clusters, trigger a failure, drain and recover nodes, rotate and compromise identities, reconcile a partial apply, decommission a cluster, run every attack case, inspect receipts, and see Python and TypeScript agree on the same portable artifacts.

Run targeted validation locally. Update generated artifacts only through their owner commands. Leave the branch ready for authoritative hosted CI, and record genuinely external promotion gates without claiming they passed.
