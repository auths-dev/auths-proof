# `@auths-dev/sdk`

Auths lets software prove exactly what it may do, execute through a closed
action family, and leave a signed receipt. Rust owns the security meaning;
TypeScript provides typed, asynchronous application I/O.

The beginner journey introduces five security nouns progressively:

| Term | Meaning |
| --- | --- |
| Identity | Who or what is presenting a credential. |
| Authority | The bounded things that identity may do. |
| Action | The exact inert operation being proposed. |
| Approval | Optional confirmation of one exact transaction. |
| Receipt | Signed evidence of a decision or observed effect. |

Authentication proves control of identity material. It grants no permission.
Approval confirms a transaction. It does not create authority.

```ts
import { development } from "@auths-dev/sdk/integrations";
import { mcp } from "@auths-dev/sdk/profiles";

const provider = mcp.developmentProvider({ tools: { publish_report: publishReport } });
await using auths = await development.createAuths({
  authority: mcp.allowTools(["publish_report"]),
});
const result = await auths.execute({
  action: mcp.callTool({ name: "publish_report", arguments: report }),
  provider,
});
```

Identity and effect-free verification remain independently usable. Installed
consumers receive precompiled WebAssembly and do not need a Rust toolchain.
The [product glossary](../../docs/product/GLOSSARY.md) defines the progressive
language used by the SDK and recipes.

<!-- auths-beginner-end -->

Publication, promotion, production readiness, and independent review remain
separate evidence gates recorded in `sdk-capability.json`.

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
