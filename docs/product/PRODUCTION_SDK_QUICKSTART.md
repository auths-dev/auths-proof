# Production SDK quickstart

TypeScript and Python expose the same five product verbs over the same
Rust-owned contract. The SDK selects one maintained effect profile; the
operator runtime owns authorization, durable lifecycle state, provider entry,
reconciliation, and signed receipts.

## TypeScript

```ts
import { createAuths } from "@auths-dev/sdk";
import { githubIssueAddress } from "@auths-dev/sdk/profiles";

const auths = createAuths({
  endpoint: "https://auths.example.com",
  identity: publicIdentityBytes,
  profile: githubIssueAddress(),
});
const created = await auths.create(authorityRequestBytes);
if (created.kind !== "authority") throw new Error(created.code);
const delegated = await auths.delegate(created, agentIdentityBytes, attenuationBytes);
if (delegated.kind !== "authority") throw new Error(delegated.code);
const result = await auths.execute(delegated, githubIssueActionBytes);
if (result.kind === "recoverable") await auths.resume(result.reference);
```

## Python

```python
from auths import create_auths
from auths.profiles import github_issue_address

auths = create_auths(
    endpoint="https://auths.example.com",
    identity=public_identity_bytes,
    profile=github_issue_address(),
)
created = await auths.create(authority_request_bytes)
if created.kind != "authority":
    raise RuntimeError(created.code)
delegated = await auths.delegate(created, agent_identity_bytes, attenuation_bytes)
if delegated.kind != "authority":
    raise RuntimeError(delegated.code)
result = await auths.execute(delegated, github_issue_action_bytes)
if result.kind == "recoverable":
    await auths.resume(result.reference)
```

## What runs locally

- The SDK applies strict endpoint, timeout, redirect, content-type, and response
  size rules.
- Packaged Rust code encodes requests and parses finite response variants.
- Packaged Rust verification remains available offline.
- Opaque authority, receipt, and recovery values cannot be forged through the
  public SDK.

## What contacts the runtime

`create`, `delegate`, `execute`, and `resume` contact the configured HTTPS
runtime. `verify` uses the same versioned endpoint when the configured profile
requires runtime-owned status or lifecycle evidence. The runtime—not HTTP
success—decides whether an effect is authorized.

The default client refuses redirects, non-HTTPS origins, unexpected media
types, oversized responses, and unknown contract outcomes. It never returns raw
provider errors or credential material.

## Finite outcomes

- `completed`: the protected effect reached a definite successful outcome and
  carries a signed receipt;
- `denied`: the request definitely lacks authority and must not be retried;
- `indeterminate`: the runtime could not safely decide; use its retry class;
- `recoverable`: use only the returned opaque reference with `resume`;
- `verified`: the supplied authority satisfies the runtime's trusted context,
  or the receipt is canonical and authentic under that runtime's receipt key;
  and
- `rejected`: verification definitely failed.

See [production failures and recovery](recipes/06_PRODUCTION_FAILURES.md) for
the fail-closed paths.
