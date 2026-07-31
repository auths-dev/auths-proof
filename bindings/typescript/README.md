# `@auths-dev/sdk`

The embedded Auths SDK for browser and Node. Its current public surface wraps
the bounded Auths Proof Protocol V1 verifier.

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
