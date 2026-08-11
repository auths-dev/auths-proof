# `@auths-dev/sdk`

The Auths SDK for browser and Node. It provides local verification and the
typed attach, delegate, authorize, inspect, and closed-gateway workflow. Exact
release capability and assurance labels belong to repository release evidence;
this README does not upgrade those claims.

Publication, promotion, and independent-review status is recorded separately
from repository-local implementation capability in `sdk-capability.json`.

- Implementation tier: `full-workflow-sdk`
- Evidence status: `repository-local-complete`
- Promoted tier: `verifier-binding`
- Publication status: `blocked`
- Promotion status: `blocked`

```ts
const auths = await loadAuths({ signer, trustedAuthority });
const agent = await auths.attachAgent({ name: "worker", profile, authority, approval });
const result = await agent.authorize(profile.action(proposedChange));

if (result.kind === "authorized") await gateway.execute(result.command);
else report(result.kind, result.code);
```

The published package contains precompiled WebAssembly. Consumer machines do
not need Rust, C, a daemon, or network access during verification.

Teams that only need identity exchange should import `@auths-dev/sdk/identity`.
That subpath exposes decoded, validated, and authenticated states backed by the
packaged Rust/WASM identity protocol; it does not initialize grants,
capabilities, approvals, policy, profiles, or lifecycle workflows. Authority,
approvals, and profiles are separate `@auths-dev/sdk/authority`,
`@auths-dev/sdk/approvals`, and `@auths-dev/sdk/profiles` entry points. The
package root remains the integrated authorization workflow.

The broader typed surface is split by responsibility:

- `@auths-dev/sdk/trust` compiles typed roots, accepted registries, assurance,
  lifecycle snapshots, and verifier limits through Rust into a sealed context
  source. It does not accept context CBOR as configuration.
- `@auths-dev/sdk/lifecycle` authors principal and grant status through exact
  signer transactions and produces Rust-parsed status snapshots.
- `@auths-dev/sdk/authority` provides opaque proof references plus native
  `proof`, `all-of`, `any-of`, and `threshold` authorization plans.
- `@auths-dev/sdk/profiles` exposes the maintained HTTP, Git, deployment,
  supply-chain, and edge profile families. Each retains a distinct action,
  command, and gateway type.
- `@auths-dev/sdk/runtime` defines optional challenge, replay, budget, receipt,
  and closed-executor ports. These effects are not part of verification and
  run only after the matching gateway parses an authorized command.
- `@auths-dev/sdk/custody` publishes the provider-neutral signer contract. The
  conformance harness and development-only custody remain under
  `@auths-dev/sdk/testkit`; no production vendor is bundled or implied.

The complete [local quickstart](examples/quickstart/index.ts) shows a bounded
root grant, narrower child delegation, visible approval, exact authorization,
deterministic disposal, and a closed MCP gateway. Its ephemeral signers are
explicitly development-only.

Application workflows can compose an immutable, authority-summarized plan and
receive a sealed command only after every exact action authorizes:

```ts
const actionPlan = await profile.plan([
  profile.action(createBranch),
  profile.action(modifyFile),
  profile.action(openPullRequest),
]);

const result = await agent.authorizePlan(actionPlan);
if (result.kind === "authorized") {
  await gateway.executePlan(result.command);
}
```

`approvalPolicy` creates typed configuration commitments, the separate
`@auths-dev/sdk/testkit` export provides unmistakably non-production ephemeral
signers and profile mutation fixtures. Raw verification, safe inspection, and
caller-supplied engines have deliberately separate entry points.

## Local verification

Applications that already possess canonical proof, action, and trusted-context
bytes can use the effect-free verifier from `@auths-dev/sdk/verify`:

```ts
import { loadVerifier } from "@auths-dev/sdk/verify";

const verifier = await loadVerifier();
const result = verifier.verify(proofBytes, canonicalActionBytes, contextBytes);
```

An authorized raw verifier result is evidence, not a profile command accepted
by a closed gateway.

`loadVerifier` accepts no module URL, WASM input, or engine: it resolves
only the reviewed WASM subject packaged with this SDK. To run an explicitly
supplied engine — a differential test harness, or an engine under analysis —
use `createDiagnosticVerifier` from `@auths-dev/sdk/diagnostics`. Its result
reports the verdict but never carries a `VerifiedAction`, whatever bytes the
engine returns. Safe commitments and decision projections live in
`@auths-dev/sdk/inspection`.

Local/headless applications can bootstrap an explicit Ed25519 raw-key root
without hand-authoring a grant or verifier context:

```ts
const prepared = await prepareRawKeyAuthority({
  authorityId: "local.owner",
  rootSigner,
  subjectPrincipal: agentPrincipal,
  profile,
  permissions,
  resourceNamespaces: ["mcp://records"],
  validity: { notBefore, expiresAt },
  audiences: ["mcp://records"],
  remainingDepth: 1,
  approval,
});

const auths = await loadAuths({
  signer: agentSigner,
  trustedAuthority: prepared.trustedAuthority,
});
```

The root signer receives an exact transaction-bound signing request and must
return typed public control evidence; its private key never enters the SDK.
Deployment-specific identity methods continue to use explicit authority and
trusted-context providers.

The normal workflow uses the package-owned WASM subject and
does not accept a caller-selected module or engine:

```ts
import {
  loadAuths,
  signedGrantSource,
  trustedContextSource,
} from "@auths-dev/sdk";
import { mcp } from "@auths-dev/sdk/mcp";

const profile = mcp.profile({ service: "records" });
const auths = await loadAuths({
  signer,
  trustedAuthority: {
    ...trustedAuthority,
    context: trustedContextSource({
      sourceId: "local-trust",
      provider: trustedContextStore,
    }),
  },
});
try {
  const agent = await auths.attachAgent({
    name: "research-agent",
    profile,
    authority: signedGrantSource({
      sourceId: "local-root-grant",
      provider: grantStore,
    }),
    approval,
  });
  console.log(agent.authority.permissions);
  const result = await agent.authorize(
    profile.call("update_demo_record", { value: "reviewed" }),
  );
  report(result.kind, result.explanation);
  await agent.dispose();
} finally {
  await auths.dispose();
}
```

`Signer` and `ApprovalProvider` are provider-neutral ports. The base package
ships no production custody provider and never asks either port to export a
private key. Exact signing requests are prepared by Rust/WASM and bound to a
configuration commitment, approval policy, principal descriptor, object,
transaction digest, provider call, expiry, and one terminal lifecycle.

`signedGrantSource` seals the normal authority-source boundary: its provider
returns the canonical signed grant plus typed public control evidence.
`attachAgent`
does not accept caller-supplied protocol bytes. Rust/WASM decodes the exact
canonical signed grant and binds its parentlessness, root issuer, agent
subject, and profile before the SDK exposes an effective-authority summary.
That summary deliberately reports `pending-authorization`; attach does not
claim that signature, status, assurance, or live authorization checks passed.

`trustedContextSource` supplies the immutable trust anchors, accepted
registries, status snapshots, assurance policy, and limits. The SDK validates
its root and packaged-verifier commitment during load. MCP authorization then
uses Rust to canonicalize the exact call, prepare its signing transaction,
derive addressed evidence and control bindings, assemble the grant chain and
proof, bind a fresh challenge and evaluation time, and preserve
`authorized`/`denied`/`indeterminate` as distinct local results. Only a
successful package-owned verification path produces the profile command
accepted by a matching closed gateway.

Applications with their own closed action vocabulary can use
`@auths-dev/sdk/profile-kit`. The application owns canonicalization and
approval display; Rust/WASM owns protocol construction and verification. This
does not register a generic executor or let an agent choose action semantics.
`profile.authorityFor(action)` exposes a copied, read-only grant-input summary
so setup code does not duplicate the profile's capability, resource namespace,
audience, or budget derivation.

An attached agent can delegate through structured authority fields without
constructing a grant or CBOR payload:

```ts
const child = await agent.delegate({
  name: "records-child",
  signer: childSigner,
  authority: {
    permissions: [
      { capability: "tools/call", resource: "mcp://reports/read" },
    ],
    validity: { notBefore: 20n, expiresAt: 80n },
    audiences: ["mcp://reports"],
    actionConstraint: { kind: "inherit" },
    budget: {
      kind: "ceiling",
      algebra: "numeric-ceiling-v1",
      value: 10n,
    },
    remainingDepth: 0,
    status: { kind: "inherit" },
  },
});

console.log(child.delegation.diff, child.delegation.warnings);
```

Rust derives the issuer and parent link and rejects widening before approval
or signing. The selected profile and exact critical extensions are inherited
from the parent and are not caller-selectable. Approval receives the native
semantic diff and warning projection; the parent signer signs the exact native
plan, while the child signer supplies only the child identity and is retained
for that child's later actions.

The maintained API contract, architecture guide, and security boundary are
documented under [`docs/`](docs/). Application code must not treat a result
from a caller-supplied engine or module as an effect-capable command.

Start with the [support matrix](docs/support-matrix.md), then use the
[production integration recipe](docs/production-integration.md),
[error and recovery guide](docs/errors-and-recovery.md), and
[adapter qualification guide](docs/adapter-authoring.md). The
[lifecycle recipes](docs/lifecycle-recipes.md) cover withdrawal, rotation,
compromise, and clean prelaunch policy/profile replacement.
