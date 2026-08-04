# `@auths-dev/sdk`

The embedded Auths SDK for browser and Node. Its supported public surface wraps
the bounded Auths Proof Protocol V1 verifier. Repository-local builds also
contain the pre-review principal, trusted-authority, signer, and approval ports
being assembled into the Full Workflow SDK.

**Current capability tier:** Verifier Binding. The Full Workflow SDK is a
pre-review implementation target governed by
[`AP-SPEC-027`](../../docs/specs/0027-product-grade-typescript-sdk.md). It must
not be represented as shipped, published, independently reviewed, or
production-ready until that specification's exit gate passes.

```ts
import { loadPortableAuths } from "@auths-dev/sdk";

const auths = await loadPortableAuths();
const result = auths.verify(proofBytes, canonicalActionBytes, contextBytes);

if (result.kind === "authorized") {
  await execute(profile.decodeVerified(result.action));
} else {
  report(result.explanation.code, result.explanation.message);
}
```

The published package contains precompiled WebAssembly. Consumer machines do
not need Rust, C, a daemon, or network access during verification.

The repository-local workflow preview uses the package-owned WASM subject and
does not accept a caller-selected module or engine:

```ts
import { loadAuths, signedGrantSource } from "@auths-dev/sdk";

const auths = await loadAuths({ signer, trustedAuthority });
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

`signedGrantSource` seals the normal authority-source boundary: `attachAgent`
does not accept caller-supplied protocol bytes. Rust/WASM decodes the exact
canonical signed grant and binds its parentlessness, root issuer, agent
subject, and profile before the SDK exposes an effective-authority summary.
That summary deliberately reports `pending-authorization`; attach does not
claim that signature, status, assurance, or live authorization checks passed.

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

The frozen target API and security boundary are documented in
[`FULL_WORKFLOW_API_CONTRACT.md`](FULL_WORKFLOW_API_CONTRACT.md) and
[`THREAT_MODEL.md`](THREAT_MODEL.md). `loadPortableAuths` remains the temporary
raw verifier loader pending the explicit advanced-surface split in AP27-PR8;
application code must not treat a result from a caller-supplied engine or
module as an effect-capable command.
