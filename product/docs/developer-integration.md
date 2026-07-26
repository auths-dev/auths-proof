# Developer integration

Auths adds an in-process authorization boundary to one existing service. It
does not replace authentication, principal control, key custody, transports,
or the service's executor.

## The basic path

Every language calls the same deterministic operation:

```text
verify(proof_cbor, canonical_action_cbor, trusted_context_cbor)
```

The operation performs no I/O. `Authorized`, `Denied`, and `Indeterminate`
are distinct outcomes. Only `Authorized` contains a sealed verified action;
application code must decode and execute a command from that value rather
than reuse the original request.

### Rust service integration

Install `auths-sdk` and `auths-enforcement`. Configure immutable trust once,
then supply audience, challenge, and evaluation time explicitly per request:

```rust
let context = TrustedContextBuilder::new(trust_anchors, assurance_policy)?
    .with_limits(VerifierLimits::default())
    .build()?;
let auths = Enforcement::new(
    Verifier::self_contained(context)?,
    McpProfile,
);

let request = RequestContext::new(
    "mcp://deployment-tools",
    challenge_bytes,
    unix_seconds,
)?;
let decision = auths.verify(&proof_cbor, &actual_tool_call_json, &request)?;
let outcome = decision.execute(&tool_executor)?;
```

`CommandExecutor` accepts only the profile command decoded from
`VerifiedAction`. The internal-deployment package adds atomic replay and
blast-radius budget ports before it calls the deployment executor. The MCP
runtime supplies the same invariant with challenge exchange, receipts, and
transport bindings.

Safe grant planning and external key custody are available from the same
package as `auths_sdk::authority` and `auths_sdk::custody`. The planner rejects
delegation widening before any signing provider is invoked.

### TypeScript

Install `@auths-dev/proof`. Published packages include compiled JavaScript,
declarations, and precompiled WASM:

```typescript
import { loadAuths } from "@auths-dev/proof";

const auths = await loadAuths();
const result = auths.verify(proof, canonicalAction, trustedContext);
if (result.kind === "authorized") {
  await execute(profile.decodeVerified(result.action.canonicalBytes()));
} else {
  console.warn(result.explanation.code, result.explanation.message);
}
```

### Python

Install the `auths-proof` wheel:

```python
from auths_proof import verify

result = verify(proof_cbor, canonical_action_cbor, trusted_context_cbor)
if result.kind == "authorized":
    execute(profile.decode_verified(result.action.canonical_bytes))
else:
    logger.warning("%s: %s", result.code, result.explanation.message)
```

Release wheels use the stable Python ABI and include the Rust verifier. A
consumer machine does not build Rust or C.

### Go

Import the pure-Go module:

```go
result := auths.Verify(proofCBOR, canonicalActionCBOR, trustedContextCBOR)
switch result.Decision {
case auths.Authorized:
    return executor.Execute(profile.DecodeVerified(result.Action))
case auths.Denied:
    return forbidden(result.Explanation())
case auths.Indeterminate:
    return unavailable(result.Explanation())
}
```

The Go verifier is independent: it does not link Rust, C, or WASM. Its native
test suite runs all shared semantic corpus cases.

## Profile development

Implement `ActionProfile` so one type owns all four mappings:

1. untrusted request → unique canonical action;
2. canonical action → capability, resource, and budget;
3. canonical action → human approval display;
4. sealed verified action → executor-safe command.

`auths-profile-kit` checks repeatable canonicalization, approval-display
digest binding, emits cross-language fixtures, and supplies bounded hostile
input mutations. Profiles cannot select roots or construct a verifier
verdict.

## CI

Run the native package test and the shared corpus in the service repository:

```sh
# Rust
cargo test -p auths-enforcement -p auths-deployment

# TypeScript
npm test

# Python (after installing a wheel)
pytest

# Go
go test ./...
```

Treat corpus disagreement, an unknown critical identifier, or an unavailable
replay/budget store as a fail-closed release blocker.

This repository's GitHub workflows also check out the private
`auths-dev/auths-proof` and `auths-dev/auths-proof-exchange` repositories.
Configure an `AUTHS_READ_TOKEN` Actions secret with read-only Contents access
to those sibling repositories to enable the cross-repository jobs. Until that
credential exists, a visible preflight succeeds and those jobs are explicitly
skipped; they are never reported as having run.
