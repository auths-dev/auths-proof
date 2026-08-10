# Auths adoption layers

Auths is a set of composable security layers, not a requirement to adopt the entire authority
product. Start at the lowest layer that solves the problem and add higher layers only when the
application needs them.

| Level | Purpose | Rust | TypeScript | Does not initialize |
| --- | --- | --- | --- | --- |
| 0 | Bounded opaque data movement | `auths-byte-channel` plus an explicitly selected adapter | application-owned byte channel | identity, cryptography, authority, approval |
| 1 | Canonical identity data and exchange | `auths-identity`; optional `auths-identity-raw-key` | `@auths-dev/sdk/identity` | grants, capabilities, approval, policy, lifecycle |
| 2 | Authenticated application messages | `auths-identity` plus an explicitly selected suite such as `auths-signature-ed25519` | explicit authentication loader from `@auths-dev/sdk/identity` | delegated authority and execution |
| 3 | Delegated authority verification | `auths-kernel-runtime`, or the integrated `auths-sdk` | `@auths-dev/sdk/authority` | approval providers, gateways, execution effects |
| 4 | Human or automated review gates | `auths-author` and product composition | `@auths-dev/sdk/approvals` | application profile or gateway selection |
| 5 | Profiles, execution, receipts, and lifecycle | `auths-runtime`, `auths-profile-*`, and selected effect adapters | `@auths-dev/sdk/profiles` or the compatibility root | deployment-specific providers unless explicitly configured |

Lower levels do not depend on higher ones. In particular, exchanging a public identity or
authenticating application bytes creates no authority. Promoting a validated identity into a
principal is a separate, explicit bridge supplied by `auths-identity-authority`.

## Minimal identity example

```ts
import { loadIdentity, loadRawKeyIdentityAdapter } from "@auths-dev/sdk/identity";

const identity = await loadIdentity();
const rawKey = await loadRawKeyIdentityAdapter();
const alice = rawKey.create("example-pq-v1", publicKey);

await channel.send(alice.packet);
const decoded = identity.decodePublicIdentity(await channel.receive());
// Decoding is deliberately not trust. Select and run the matching method adapter next.
```

The same representation can later enter the authority stack through an explicit bridge. The
identity packet is not rewritten and the bridge does not silently create a grant.

## Language status

- Rust exposes every layer as a direct crate coordinate; concrete methods, suites, and transports
  are separate dependencies.
- TypeScript exposes independently snapshotted subpaths for identity, authority, approvals, and
  profiles. The package root remains the full compatibility workflow.
- WASM owns the canonical identity bytes used by TypeScript and exposes structural decode,
  explicit raw-key validation, external-custody signing preimages, and explicit Ed25519
  authentication as separate operations.
- Python currently exposes the Level 3 deterministic verifier. It does not pretend to offer the
  lower identity API; Python applications may add it through the native Rust coordinates or a
  future thin binding without changing the semantic layers.
