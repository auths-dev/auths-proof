# ADR 0008: Reset the Prelaunch V1 Contract In Place

**Status:** Proposed

**Date:** 25 July 2026

## Context

Auths is prelaunch with zero users.

The current repository calls its prototype protocol V1 and contains V1 CDDL,
domain strings, fixtures, Rust types, and local companion integrations. None
of these have been released as a supported external contract. There are no
deployed users, durable third-party grants, audit receipts, or compatibility
commitments.

The target architecture changes security-bearing semantics throughout the
grant, action, proof, status, assurance, and execution model. Introducing V2
would create two protocol implementations solely to preserve an internal
prototype that nobody depends on.

## Decision

The target architecture is **Auths Proof Protocol V1**.

The current prelaunch V1 contract is replaced in place:

- `spec/v1` is rewritten to describe the complete target;
- `fixtures/v1` is replaced with the target canonical and negative corpus;
- current model, codec, verifier, authoring, CLI, exchange, and profile APIs
  may change incompatibly;
- existing domain strings and identifier rules may be replaced;
- obsolete prototype types, paths, features, and tests may be removed.

There is no:

- V2 namespace;
- dual V1/V2 decoder;
- compatibility feature;
- legacy verifier;
- proof translation;
- re-signing migration guide;
- deprecation period for prototype APIs.

Git history retains the experiment. Product code does not.

## Target V1 protocol rule

The target V1 domain separation binds:

```text
"AUTHS" ||
protocol_major ||
object_type ||
profile_id ||
profile_version ||
canonical_object
```

The exact byte layout and integer identifiers are fixed by the rewritten
language-neutral V1 specification, never by Rust enum layout.

Grant and action identifiers are derived from canonical statement bytes.
Signature representation is excluded from a statement identifier unless the
specification separately defines a signed-object digest.

All target V1 decoders:

- accept only protocol major 1;
- reject non-canonical encodings;
- reject unknown critical identifiers;
- select suites, methods, status types, profiles, and extensions exactly;
- never retry another parser or adapter after failure.

## Implementation rule

The reset is specification-first:

1. rewrite V1 prose, CDDL, registries, domains, identifiers, limits, and reason
   codes;
2. create hand-reviewed target V1 vectors;
3. implement the model and codec against those vectors;
4. implement the verifier and adapters;
5. implement exchange, profiles, runtime, and receipts;
6. delete any remaining prototype-only code that does not serve the target.

The first implementation commit may break all current fixtures and APIs. That
is expected and does not require compatibility scaffolding.

## Package versioning

Package versions remain pre-1.0 during implementation. Protocol major and
package semantic version are distinct:

- protocol major remains V1;
- crate/package versions may advance normally while prelaunch;
- the first production launch receives the product version selected by the
  release process;
- after launch, changes to signed meaning require a registered
  semantics-preserving extension or a new protocol major.

## Consequences

### Positive

- Only one protocol and one verifier need to be implemented and reviewed.
- The target can use clean required fields instead of compatibility options.
- The trusted computing base contains no obsolete decoder or translation
  path.
- Fixtures describe the intended product rather than preserving experiments.
- Repository and crate restructuring can happen directly.

### Negative

- Current local fixtures and example proofs stop verifying.
- Prototype APIs and companion workspaces may stop compiling while the target
  is being built.
- Useful implementation code must be selected deliberately instead of
  preserved wholesale.

These costs are acceptable before launch and materially cheaper than carrying
compatibility indefinitely.

## Rejected alternatives

### Introduce protocol V2

Rejected because there is no external V1 population to migrate or support.
V2 would add code, documentation, tests, downgrade handling, and audit surface
without user value.

### Preserve old V1 and add optional target fields

Rejected because absent audiences, constraints, plan bindings, status policy,
and profile identifiers have different authority meaning. Optional
compatibility fields would weaken the new contract.

### Keep a hidden legacy decoder

Rejected because unused parsing and verification code still expands the
trusted computing base and fuzzing burden.

### Translate prototype proofs

Rejected because there are no user proofs to preserve and translation cannot
create signatures over changed meaning.

## Safety condition

This decision relies on the stated prelaunch condition: no external user or
durable deployment depends on current V1 bytes. If that condition changes
before the reset lands, this ADR must be superseded before compatibility code
is introduced.

## Required follow-up

- Rewrite `spec/v1` and `fixtures/v1` before target Rust types.
- Use V1 consistently throughout target-state documentation.
- Treat current exchange and MCP workspaces as reusable prototypes, not
  supported downstream releases.
- Freeze V1 only after the complete target grammar and corpus pass review.
