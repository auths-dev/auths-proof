# 05 — Primary product waist

**Status:** implemented product waist; public clean-break cutover is owned by Milestone D
**Milestones:** B — facade design; C — vertical proof; D — public cutover
**Evidence inputs:** [02](02_SECURITY_AND_PARITY_GUARDRAILS.md) and the error registry in [08](08_ERRORS_RECOVERY_AND_DIAGNOSTICS.md)
**Co-designed with:** [03](03_CUSTOMER_VOCABULARY.md) and recipe prototypes from [11](11_OUTCOME_FIRST_RECIPES.md)

## Current issue

Auths has the operations needed for a safe workflow, but applications must
assemble too many of them. The current full path can require loading trust,
attaching an agent, selecting a profile, sourcing authority, authorizing an
action, handling a command, creating a gateway, reserving state, acquiring
credentials, and interpreting receipts.

The SDK accurately exposes its mechanisms but has not compressed them into the
smallest safe product workflow.

## Components of the problem

- initialization describes subsystems instead of the intended environment;
- delegation and attachment are separate concepts in the user's path;
- authorization and execution are separate even for a closed effect;
- effect-capable profile commands can become visible between steps;
- bindings can accidentally duplicate lifecycle sequencing;
- public idempotency inputs can be unrelated to the committed request;
- TypeScript and Python reach equivalent meaning through different journeys;
- recovery is scattered across decisions, gateways, stores, and receipts.

## Product decision

Create one authority-bound `Auths` facade with three primary operations:

- `delegate`: return the same facade with narrower authority;
- `execute`: authorize and run one action or ordered plan through a
  profile-owned closed session; and
- `resume`: reopen an incomplete execution from an opaque,
  commitment-bound reference.

Resource disposal is language-native. Inert proof and receipt verification
remain independently available from `verify`; identity remains independently
available from `identity`.

`Auths` is not a generic remote-effect engine. The selected action and provider
must belong to the same qualified profile. That profile owns request
construction, credential timing, remote-result parsing, transition semantics,
reconciliation, and receipt claims.

## Development quickstart

The first-effect path uses an explicit development composition rather than
making the user construct infrastructure:

```ts
import { development } from "@auths-dev/sdk/integrations";
import { mcp } from "@auths-dev/sdk/profiles";

const reports = mcp.developmentProvider({
  tools: { publish_report: publishReport },
});

await using auths = await development.createAuths({
  authority: mcp.allowTools(["publish_report"]),
});
const result = await auths.execute({
  action: mcp.callTool({ name: "publish_report", arguments: report }),
  provider: reports,
});
```

```python
from auths.integrations import development
from auths.profiles import mcp

reports = mcp.development_provider(
    tools={"publish_report": publish_report},
)

async with development.create_auths(
    authority=mcp.allow_tools(["publish_report"]),
) as auths:
    result = await auths.execute(
        action=mcp.call_tool(name="publish_report", arguments=report),
        provider=reports,
    )
```

The development factory supplies actor identity, signer, local trust, atomic
state, no-approval policy, clock, and receipt sink. The caller supplies a
profile-owned bounded authority so the first effect demonstrates the product's
central promise. Every development-supplied component is visibly
development-only and rejected by a production composition.

The introductory recipe omits `requestId`/`request_id`. Later operational
recipes may add it as a bounded application correlation identifier. It is not
a provider idempotency key. Rust and the profile derive the internal
reservation and provider idempotency identity from the exact action, authority,
context, profile, plan position, and optional application request identifier.

## Explicit composition

After the quickstart, applications may compose explicit mechanisms:

```ts
import { createAuths } from "@auths-dev/sdk";

await using auths = await createAuths({
  actor,
  authority,
  trust,
  signer,
  state,
  receipts,
});
```

This composition does not change the `execute` contract and does not permit a
caller to replace profile-owned effect semantics with a generic callback.
Production-shaped reference compositions are Phase B of Spec 09, not a
dependency of the development quickstart or public cutover.

## Result and recovery model

Authorization outcomes remain ordinary values:

- `completed`: the profile has committed an execution receipt for the observed
  outcome;
- `denied`: authority did not authorize the action and no effect occurred;
- `indeterminate`: required evidence was unavailable and no effect occurred.

Operational failures use the registry from Spec 08 and report effect state as
`not-applied`, `possible`, or `applied`. A possible effect returns an opaque
execution reference but no effect-capable command:

```ts
const execution = await auths.resume(error.executionReference);
const recovered = await execution.reconcile();
```

```python
execution = await auths.resume(error.execution_reference)
recovered = await execution.reconcile()
```

`resume` accepts only a Rust-authenticated reference bound to the original
profile, commitment, and state record. The caller does not supply a provider
idempotency key, unrelated provider, command bytes, or replacement action.
Provider reconnection material, if required, comes from the profile-owned
composition associated with that reference.

## Delegation UX

Delegation returns another authority-bound facade:

```ts
await using child = await auths.delegate({
  identity: reportAgent,
  authority: { actions: [publishReport], expiresIn: "10m", uses: 1 },
  approval,
});

await child.execute({ action, provider, requestId });
```

The child owns its native attachment and ephemeral signer lifetime. Closing
the parent closes its owned ephemeral children. Rust parses and enforces every
attenuation dimension before anything is signed.

## Architecture

```text
create Auths
     |
     +--> parse composition + bind exact native ABI
     +--> establish identity, authority, trust, and resources
     |
     +--> delegate ------> Rust attenuation/signing ------> child Auths
     |
     +--> execute(action + profile-typed provider)
            |
            +--> Rust creates opaque profile session
            +--> binding performs only the requested bounded I/O
            +--> Rust accepts result and releases next step or terminal value
            +--> completed / denied / indeterminate / recoverable error
     |
     +--> resume(opaque reference) ------> same profile session
```

A shared private FFI carrier may represent `next step`, but it may not encode a
universal domain state machine. Each profile's Rust implementation owns which
steps exist and what their results mean.

## Implementation steps

- [x] Derive the exact root call/result types from executable TypeScript and
  Python recipe prototypes.
- [x] Bind missing Rust operations so no binding reconstructs authorization,
  transition, idempotency, reconciliation, or receipt meaning.
- [x] Implement an opaque profile-session/step handle that cannot be cloned,
  serialized, pickled, subclassed, or constructed by binding code.
- [x] Implement TypeScript and Python I/O drivers that submit bounded results
  to Rust and receive the next permitted step.
- [ ] Implement explicit development factories with equivalent defaults,
  required profile-owned bounded authority, and unmistakable development
  diagnostics.
- [x] Make action/provider compatibility type-driven per profile.
- [x] Make `delegate` return a resource-owning child facade.
- [x] Make `resume` accept only opaque commitment-bound references.
- [ ] Add Rust-generated success, denial, indeterminate, replay, cancellation,
  ambiguous-outcome, reconciliation, delegation, and ordered-plan fixtures.
- [ ] Land root exports and delete the old normal path in Milestone D.

## Acceptance criteria

- A development effect requires a bounded authority, action, and matching
  profile-typed provider; it requires no caller-orchestrated security
  transition.
- Recipe 3 stays within Spec 01's separate security, domain, setup, and input
  budgets without hiding required concepts in ordinary API counts.
- Calling an MCP tool outside `allowTools`/`allow_tools` returns denial and
  produces zero handler, credential, or provider entry.
- No facade operation accepts a caller-chosen provider idempotency key.
- The facade never exposes an effect-capable command or profile step handle.
- Rust must accept one bounded result before any subsequent side effect is
  available.
- Denied and indeterminate results cause zero state, credential, and provider
  calls.
- Ambiguous effects can only continue through `resume` and profile-owned
  reconciliation; blind `execute` retry remains blocked.
- TypeScript and Python pass the same product and profile-session fixtures.

## Non-goals

- A universal provider, result, reconciliation, or effect state-machine API.
- Hiding explicit production trust, custody, durability, and provider choices.
- A blocking Python facade over asynchronous I/O.
