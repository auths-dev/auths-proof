# `@auths-dev/sdk`

The embedded Auths SDK for browser and Node. Its current public surface wraps
the bounded Auths Proof Protocol V1 verifier.

**Current capability tier:** Verifier Binding. The Full Workflow SDK is a
pre-review implementation target governed by
[`AP-SPEC-027`](../../docs/specs/0027-product-grade-typescript-sdk.md). It must
not be represented as shipped, published, independently reviewed, or
production-ready until that specification's exit gate passes.

```ts
import { loadAuths } from "@auths-dev/sdk";

const auths = await loadAuths();
const result = auths.verify(proofBytes, canonicalActionBytes, contextBytes);

if (result.kind === "authorized") {
  await execute(profile.decodeVerified(result.action));
} else {
  report(result.explanation.code, result.explanation.message);
}
```

The published package contains precompiled WebAssembly. Consumer machines do
not need Rust, C, a daemon, or network access during verification.

The frozen target API and security boundary are documented in
[`FULL_WORKFLOW_API_CONTRACT.md`](FULL_WORKFLOW_API_CONTRACT.md) and
[`THREAT_MODEL.md`](THREAT_MODEL.md). The existing raw verifier remains the
advanced surface; application code must not treat a result from a
caller-supplied engine or module as an effect-capable command.
