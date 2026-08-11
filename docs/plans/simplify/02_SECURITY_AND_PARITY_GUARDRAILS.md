# 02 — Security and parity guardrails

**Status:** implemented
**Milestone:** A — Evidence foundation
**Design dependencies:** [01 — Current complexity baseline](01_CURRENT_COMPLEXITY_BASELINE.md)

## Current issue

Convenience work is dangerous in a capability system. A wrapper that accepts
serialized commands, reorders reservation and credentials, turns an unknown
outcome into a retry, or reconstructs meaning in TypeScript/Python can make the
SDK easier to call while destroying the properties that distinguish Auths.

The repository already tests these boundaries in several places. The missing
piece is one simplification contract that every new facade, package layout, and
reference adapter must satisfy.

## Components of the problem

- security invariants are distributed across Rust, WASM, native Python,
  TypeScript, package, and demo tests;
- ordinary product APIs and framework APIs do not share one explicit safety
  checklist;
- parity can be mistaken for matching method names rather than matching
  meaning;
- a short facade may be tempted to expose or serialize native command handles;
- development defaults may be mistaken for production-safe custody or state;
- error simplification may collapse denied, indeterminate, failed, cancelled,
  and outcome-unknown states.

## Non-negotiable product contract

```text
+------------------+       +-----------------------+
| Product facade   | ----> | Profile I/O driver    |
| short and clear  |       | no semantic invention |
+------------------+       +-----------+-----------+
                                     |
                                     v
                         +-------------------------+
                         | Rust-owned profile      |
                         | session / step handles  |
                         +------------+------------+
                                      |
                 reserve durable state first
                                      |
                                      v
                         +-------------------------+
                         | credentials + provider  |
                         +-------------------------+
```

The following must remain true:

- Rust is the only owner of canonical bytes, identifiers, commitments,
  attenuation, authorization decisions, lifecycle transitions, and receipt
  meaning.
- TypeScript and Python cannot construct, clone, pickle/serialize, subclass,
  reflect into, or replay an effect-capable command.
- The product facade never returns a raw command to ordinary application code.
- A profile-owned Rust session accepts every bounded I/O result and determines
  whether the next side-effect step is available.
- Durable reservation succeeds before credential acquisition or provider I/O.
- Provider execution receives the exact canonical bytes retained by the native
  handle.
- Denied and indeterminate authorization never enter state or provider ports.
- Cancellation before provider entry is distinct from cancellation after
  provider entry.
- An ambiguous remote effect remains `outcome-unknown`, blocks blind retry, and
  requires reconciliation.
- HTTPS, Iroh, queues, files, and RPC carry bytes but never grant authority.
- Identity exchange and authentication remain usable without grants,
  capabilities, approval, lifecycle, or effect runtime setup.
- Approval is optional and never substitutes for authority.
- TypeScript and Python accept the same semantic inputs and produce the same
  decisions, transitions, receipt bytes, and stable failure identities.

## Required guardrail suite

Create one Rust-owned manifest of invariant case identifiers and expose it to
both SDK testkits. At minimum include:

- forged command construction;
- command serialization, copying, pickling, subclassing, and prototype grafting;
- canonical action substitution;
- proof, context, profile, audience, or plan-member substitution;
- delegation widening across every authority dimension;
- replay, concurrent reservation, wrong order, and exhausted budget;
- credential acquisition before reservation;
- provider entry after denial or indeterminate;
- cancellation before and after provider entry;
- not-applied failure, applied failure, and ambiguous outcome;
- unauthorized transport delivery;
- mutated or wrongly linked decision/execution receipts;
- cross-language fixture disagreement;
- development configuration accepted as production configuration.

## Implementation steps

- [x] Add a versioned `simplified-product-waist` conformance manifest owned by
  Rust and included in semantic freeze.
- [x] Map every invariant to existing evidence or add the missing Rust,
  TypeScript, Python, package, and live-effect test.
- [x] Add product-facade conformance runners to TypeScript and Python testkits.
- [x] Generate shared canonical inputs, decisions, transitions, error identities,
  receipt bytes, and signing preimages from Rust.
- [x] Add negative compile/type tests proving framework-only ports are absent
  from root imports.
- [x] Add consumer tests proving identity and verification imports do not load
  workflow, approval, custody, or gateway code.
- [x] Make this suite mandatory before deleting an old API or landing a new
  convenience facade.

## Parity definition

Parity requires agreement on:

- semantic operation availability;
- accepted and rejected shapes;
- canonical bytes and commitments;
- decision kind, stage, and stable code;
- state transition and retry classification;
- provider-entry timing;
- receipt identifiers, bytes, links, and verification;
- bounded diagnostic fields.

Parity does not require identical casing, context-manager syntax, cancellation
syntax, collection types, or module mechanics.

## Acceptance criteria

- Both SDKs execute every manifest case and report the same case IDs.
- No product-level happy path exposes a native command or canonical protocol
  constructor.
- A hostile adapter cannot cause provider entry before reservation.
- A simulated lost response produces `outcome-unknown` in both SDKs and zero
  provider re-entry on retry.
- Identity-only and verification-only packed consumers operate without loading
  effect workflow code.
- The guardrail suite is referenced by all later specifications and runs in
  authoritative CI.

## Non-goals

- Preventing framework authors from inspecting bounded review or diagnostic
  projections.
- Making TypeScript and Python source code structurally identical.
- Treating development adapters as production security controls.
