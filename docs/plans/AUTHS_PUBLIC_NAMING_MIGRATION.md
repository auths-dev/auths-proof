# Auths public naming migration

## Status

Execution plan and human-readable interpretation of
[AP-SPEC-034](../specs/0034-auths-public-naming-consolidation.md). The sole
machine-readable naming authority is
[`release/public-naming.toml`](../../release/public-naming.toml).

This plan does not authorize publication, package deletion or yanking, owner
changes, an RC tag, a repository rename or archive, deployment, or DNS work.

## Outcome

Users should encounter one product:

```text
Auths
├── Rust core: auths
│   └── proof component: auths-proof
├── Rust SDK: auths-sdk
├── JavaScript/TypeScript SDK: @auths-dev/sdk
├── Python SDK: auths
├── website: auths.dev
└── first RC: auths-v1.0.0-rc.1
```

“Proof” remains useful vocabulary. It describes the portable proof format,
deterministic verifier boundary, proof exchange, and their implementation
packages. It no longer competes with Auths as the product name.

## Registry snapshot

The registry snapshot was taken on 2026-07-31 from the official crates.io,
npm, and PyPI APIs.

- The crates.io owner index for user ID `345389` contains 33 `auths` or
  `auths-*` packages attributable to `auths-dev/auths`, including
  repository-less `auths-utils`.
- Every one of those crates lists `bordumb` as its named owner.
- `auths`, `auths-sdk`, and `auths-verifier` are already owned coordinates at
  version `0.1.16`.
- `@auths-dev/sdk` exists on npm at version `0.1.16` and points to the
  predecessor repository. `@auths-dev/proof` returns 404.
- `auths` exists on PyPI at version `0.1.16` and points to the predecessor
  repository. `auths-proof` returns 404.
- All visible reverse dependencies of the predecessor crates are other
  predecessor `auths-*` packages. No non-predecessor registry reverse
  dependency was observed.

That last observation narrows migration risk; it does not prove there are no
external users. Registry download totals are nonzero and can include CI,
mirrors, dependency builds, and direct downloads. Git, path, vendored, copied,
or unpublished use is not visible in the reverse-dependency API.

## Disposition summary

| Disposition | Count | Coordinates |
| --- | ---: | --- |
| Continue | 4 | `auths`, `auths-sdk`, `auths-verifier`, `auths-receipts` |
| Replace | 10 | `auths-core`, `auths-crypto`, `auths-evidence`, `auths-id`, `auths-index`, `auths-keri`, `auths-mcp-core`, `auths-policy`, `auths-rp`, `auths-storage` |
| Retire | 19 | All other predecessor coordinates in the authoritative inventory |
| Delete and reclaim | 0 | None |

Continue does not mean source compatibility. Each continued coordinate crosses
from the experimental `0.1.x` predecessor to the current architecture through
an intentional `1.0.0-rc` major transition.

Replace means the old package encoded a boundary the current architecture
intentionally split. Examples include:

- `auths-crypto` becoming suite and adapter boundaries such as
  `auths-signature`, `auths-multikey`, and `auths-raw-key`;
- `auths-id` becoming identity-method adapters and custody boundaries;
- `auths-keri` becoming the optional `auths-did-keri` adapter;
- `auths-policy` becoming the pure authority/composition packages plus the
  separately bounded policy layer; and
- `auths-storage` becoming custody and explicitly stateful store boundaries.

Retire means no first-RC package adopts the old coordinate. It does not release
the name or authorize a deprecation upload.

## Why deletion is off the table

Every predecessor coordinate has published bytes. The official Cargo
publishing documentation states that publication is permanent: versions
cannot be overwritten and code cannot be deleted. Yanking only prevents new
resolution in some circumstances; it does not delete the archive or free the
crate name.

The safe policy is therefore to retain custody. There is no deletion/reclaim
sequence to approve, and issue 54 authorizes no yank.

## New Rust publication order

The new core facade increases the expected crates.io closure from 27 to 28
packages. The inventory records nine topological tiers:

1. leaf model/algebra/multikey/exchange-model packages;
2. assurance, codec, composition, ports, and exchange port;
3. authority, identity adapters, raw key, receipts, registries, and signature;
4. author and verifier;
5. custody, proof component, and base profile API;
6. configuration and composed profiles;
7. operations;
8. runtime; and
9. the public `auths` and `auths-sdk` roots.

Hosted CI must derive the edges from the candidate manifests. The checked-in
tiers are a contract, not a substitute for dependency validation. An edge from
a lower-numbered tier to a higher-numbered tier is a terminal error.

## Migration sequence

| Unit | Repository effect | External effect |
| --- | --- | --- |
| `AP34-PR1` | Naming authority, registry evidence, spec and governing amendments | None |
| `AP34-PR2` | `auths` facade, `auths-sdk`, Cargo graph and Rust examples | None |
| `AP34-PR3` | npm/Python metadata, imports, current docs and canonical links | None |
| `AP34-PR4` | Release identity, semantic freeze and adversarial stale-name CI | None |
| `AP34-PR5` | Accurate predecessor notice and migration/deferral ledger | No archive, rename, yank, or publication |
| `AP34-PR6` | Align the repository that owns `auths.dev` content | No DNS or deployment without separate approval |

AP-SPEC-032 release-evidence work resumes only after all six units and their
hosted gates are complete. Its preserved draft must be rebased onto the new
package catalogue and must regenerate every artifact identity rather than
editing previously generated evidence by hand.

## Remaining external facts

The following are real gates, not repository-local checkboxes:

- `auths.dev` currently contains predecessor-era package and GitHub links. Its
  content owner must adopt this inventory before the site can be release
  evidence for the current implementation.
- The old repository needs an accurate notice. Calling it wholly unpublished
  would be false because its `0.1.x` registry packages exist.
- Registry publication permission for the target `1.0.0-rc` packages is not
  granted. Custody evidence is not publication authorization.
- Repository rename and archive decisions remain open and must not be smuggled
  into naming cleanup.

Until those facts change with evidence, the first-RC naming gate remains
closed.
