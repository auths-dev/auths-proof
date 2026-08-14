# Epic 3 — Build Runtime Orchestration and Recovery

**Parent:** [AP-SPEC-038](../0038-production-runtime-custody-observability-and-assurance.md)

**Depends on:** Epics 1–2 and AP-SPEC-026

**Blocks:** Epics 5–9

## Outcome

Provide one Rust-owned, multi-host-safe orchestration mechanism around the
existing lifecycle kernel. It must enforce durable ordering, mint opaque
recovery references, expose bounded status, support safe cancellation and
resumption, and schedule profile-owned reconciliation without creating a
generic provider executor.

## Zero-context starting point

Read:

- `product/runtime/auths-lifecycle/src/{model,transition,sealed,codec}.rs`;
- `product/runtime/auths-runtime/src/lib.rs`;
- `product/runtime/auths-kernel-runtime/src/lib.rs`;
- `product/errors/auths-errors/src/lib.rs`;
- `product/integrations/auths-{opentofu,postgresql,github}/src/service.rs`;
- their `lifecycle.rs`, `executor.rs`, `ports.rs`, and receipt modules;
- `product/stores/auths-stores/src/lifecycle.rs`; and
- the profile/domain abstraction boundary plan.

Current facts:

- `auths-lifecycle` already owns the closed transition relation and canonical
  record codec.
- `execute_store_transaction` creates a sealed `DurableTransitionV1` only
  after validating store acknowledgement.
- `ExecutionAuthorizationV1` can be created only from the newly durable
  credential-authorization event.
- `ProviderCallAuthorizationV1` can be created only from a newly durable
  provider-call-entry event.
- OpenTofu, PostgreSQL, GitHub, and Stripe services already implement concrete
  domain execution/reconciliation flows, with some duplicated sequencing.
- TypeScript and Python currently contain higher-level language-owned runtime
  state machines. Epic 7 will delete those paths after this Rust waist exists.

## Product constraint

The normal SDK experience remains five verbs:

```text
create -> delegate -> execute -> resume -> verify
```

Developers do not manually advance lifecycle states or assemble transition
gates. `execute` returns one closed result. `resume` accepts one opaque
reference. Detailed stages, revisions, commitments, and recovery operations
are progressively disclosed through inspection and operator APIs.

A user who receives `outcome-unknown` gets an explicit instruction not to
retry and a recovery reference they can persist safely.

## Architecture

```text
profile-owned decision/projection
             |
             v
+-----------------------------+
| LifecycleCoordinator<S>     |
| exact store transactions    |
| sealed stage outputs        |
+--------------+--------------+
               |
       +-------+--------+
       |                |
       v                v
profile-owned       profile-owned
credential/gateway  observer/reconciler
       |                |
       +-------+--------+
               |
               v
     canonical record + receipts

One scheduler may discover recoverable records. It does not interpret them.
One concrete worker exists per qualified profile and calls that profile's
observer and reconciliation function.
```

Do not add `GenericProvider`, `GenericEffect`, `execute(profile, json)`, a
callback-based universal workflow, or a `match operation` that constructs
provider requests. Shared orchestration ends at sealed transition mechanics.

## Rust APIs and types

Add a production module to `auths-runtime`, or extract a new package only if an
architecture case file proves a cleaner dependency boundary. Prefer extending
the existing coherent runtime package.

```rust
pub struct LifecycleCoordinator<S> {
    store: S,
    recovery_references: RecoveryReferenceStore,
    clock: TrustedClock,
}

pub struct OpaqueRecoveryReference(SecretBytes32);

pub enum WorkflowResult<R> {
    Completed { receipt: R },
    Denied { code: StableErrorCode },
    Indeterminate { code: StableErrorCode },
    Recoverable { reference: OpaqueRecoveryReference, state: RecoverableState },
    Unavailable { code: StableErrorCode },
}

pub enum RecoverableState {
    Reserved,
    ExecutionIntentRecorded,
    Executing,
    OutcomeUnknown,
}

pub struct WorkflowStatus {
    pub state: LifecycleState,
    pub revision: u64,
    pub profile: ProfileRef,
    pub effect_state: EffectState,
    pub recovery_action: RecommendedAction,
    pub updated_at: VerifierTime,
    pub receipt: Option<ReceiptDisclosureLocator>,
}
```

`OpaqueRecoveryReference`:

- is 32 random bytes from an OS CSPRNG;
- is returned once to the caller in an opaque Rust/TypeScript/Python type;
- has no public constructor, fields, `Debug`, serialization-by-default, or
  string conversion that leaks the token;
- uses a deliberate URL-safe encode/decode only at the HTTP boundary;
- is stored only as a domain-separated SHA-256 digest;
- maps to exactly one workflow and profile; and
- is constant-time compared.

Bind `recovery_reference_digest` into the immutable `DecisionInputV1`. This is
an intentional prelaunch semantic change: update codec, fixtures, lifecycle
semantic identity, formal translation inputs, TypeScript/Python native ABI,
and semantic-freeze data atomically. Do not add a reader for old records.

Add narrow store ports:

```rust
pub trait LifecycleReader {
    fn load(&self, workflow: &WorkflowId)
        -> Result<Option<LifecycleRecordV1>, StoreError>;
}

pub trait RecoveryReferenceStore {
    fn bind(&self, digest: RecoveryReferenceDigest, workflow: &WorkflowId,
            profile: &ProfileRef) -> Result<(), StoreError>;
    fn resolve(&self, digest: RecoveryReferenceDigest)
        -> Result<Option<RecoveryTarget>, StoreError>;
}

pub trait RecoverableWorkStore {
    fn list_recoverable(&self, profile: &ProfileRef, cursor: RecoveryCursor,
                        limit: RecoveryBatchSize)
        -> Result<RecoveryPage, StoreError>;
    fn claim_reconciliation(&self, request: RecoveryLeaseRequest)
        -> Result<RecoveryLease, StoreError>;
}
```

The PostgreSQL implementation stores reference digests and bounded recovery
leases in dedicated tables. Leases are scheduling state, not authorization.
Every reconciliation transition still uses the record's expected revision and
fresh profile-owned evidence; a lease cannot create a sealed provider command.

## Ordered execution protocol

The coordinator and concrete vertical must perform these steps in order:

1. Parse profile-specific action, policy, evidence, and configuration.
2. Run Rust verification and the concrete pure profile evaluator.
3. Create and durably bind the recovery-reference digest.
4. Record the eligible decision and decision receipt.
5. Atomically reserve every capacity intent.
6. Derive the exact verified command and provider request in the profile.
7. Record `ExecutionIntentV1` with command, request, condition, contract, and
   retry commitments.
8. Re-read critical profile evidence where that vertical requires it.
9. Durably authorize credential acquisition.
10. Derive `ExecutionAuthorizationV1`; only now call the profile credential
    broker.
11. Durably start the attempt.
12. Durably mark provider-call entry.
13. Derive `ProviderCallAuthorizationV1`; only now call the profile gateway.
14. Persist definite effect, definite non-effect, or outcome unknown.
15. Persist the domain receipt and shared lifecycle receipt.
16. Return a bounded product result.

Cancellation before provider entry follows the profile's
`CancellationDisposition`. Cancellation after possible provider entry never
releases capacity without definite non-effect evidence.

## Recovery protocol

`resume(reference)`:

1. parses the bounded opaque reference;
2. hashes and resolves it to workflow/profile;
3. loads and validates the canonical record;
4. returns terminal receipt if already terminal;
5. returns the current bounded state if another worker owns an unexpired lease;
6. invokes the concrete profile recovery entry point when appropriate; and
7. returns terminal or recoverable state without blindly re-executing.

Each profile implements a concrete entry point, for example:

```rust
impl SavedPlanService<...> {
    pub fn resume_saved_plan_apply(
        &self,
        lease: RecoveryLease,
        record: &LifecycleRecordV1,
    ) -> Result<WorkflowOutcome, ServiceError>;
}
```

The entry point may observe provider state and submit a `Reconcile` transition.
It cannot obtain an ordinary execution authorization from the recovery lease.

## UX

Default SDK result:

```text
Completed(receipt)
Denied(code)
Indeterminate(code)
Recoverable(reference, "outcome-unknown")
```

Detailed operator status:

```text
Workflow: 7X...
Profile:  auths.postgresql.bounded-update/1
State:    outcome-unknown
Effect:   possible
Action:   observe-before-retry
Updated:  2026-08-14T12:00:00Z
Receipt:  pending
```

No default result prints proof bytes, action bodies, principals, resource IDs,
provider payloads, credentials, or receipt bytes.

## Files to change

- `product/runtime/auths-lifecycle`: recovery digest in the immutable input,
  updated codec/fixtures/formal inputs, and any closed recovery identifiers.
- `product/runtime/auths-runtime`: coordinator, result/status types, reference
  parser, and bounded mechanisms.
- `product/stores/auths-stores`: reference lookup, recovery query, and lease
  tables/implementations.
- `product/errors/auths-errors`: stable runtime and recovery codes plus effect
  and recommended-action mapping.
- each selected vertical's `service.rs`: direct source cutover to coordinator
  calls while retaining profile semantics.
- `product/fixtures/v1/lifecycle`: canonical and adversarial vectors.
- `formal/`: update lifecycle translation/refinement only for the intentional
  immutable-input change.
- `architecture.toml`, `compliance.toml`, semantic freeze, and release subjects.

## Implementation steps

- [ ] Add bounded recovery identifiers and digest binding.
- [ ] Extend lifecycle input/codec/fixtures/formal subjects atomically.
- [ ] Add read/reference/recoverable-work ports without expanding
  `LifecycleStore::transact` into a generic database API.
- [ ] Implement in-memory reference and PostgreSQL adapters.
- [ ] Implement `LifecycleCoordinator` stage methods that accept typed inputs
  and return sealed stage outputs.
- [ ] Cut one vertical—OpenTofu—onto the coordinator and compare every existing
  valid/invalid fixture, transition, credential call, provider call, receipt,
  and recovery outcome.
- [ ] Cut PostgreSQL and GitHub over only after OpenTofu differential evidence
  passes.
- [ ] Delete superseded orchestration code in the same change; retain
  profile-local evaluators, gateways, observers, receipts, and test oracles.
- [ ] Add profile-specific resume entry points and one bounded scheduler per
  selected profile in the reference deployment.
- [ ] Register stable errors for conflict, unavailable, cancelled,
  outcome-unknown, observation-pending, observation-inconclusive, and terminal.
- [ ] Prove telemetry hooks cannot alter coordinator return values.

## Adversarial and concurrency tests

Test at every stage:

- death immediately before and after durable commit;
- duplicate delivery from another host;
- changed proof/action/policy/configuration/provider-request commitments;
- forged store acknowledgement;
- forged, malformed, unknown, cross-profile, and swapped recovery references;
- cancellation before reservation, after reservation, before attempt, after
  call entry, and after possible provider effect;
- credential broker called before authorization;
- gateway called without `ProviderCallAuthorizationV1`;
- two recovery workers racing the same record;
- expired lease followed by a new worker;
- stale worker observing after a newer revision;
- stale, mismatched, or inconclusive reconciliation evidence;
- receipt persistence failure after provider response; and
- exact replay after unknown commit acknowledgement.

Assertions include zero credential calls before durable authorization, zero
gateway calls before durable call entry, at most one logical execution
authorization, no capacity release from unknown evidence, no partial command
exposure, and identical canonical records across in-memory and PostgreSQL
stores.

## Validation commands

```text
cargo test -p auths-lifecycle
cargo test -p auths-runtime
cargo test -p auths-stores
cargo test -p auths-opentofu -p auths-postgresql -p auths-github
cargo xtask formal qualify aeneas
cargo xtask semantic-freeze
cargo xtask arch
cargo xtask compliance
```

## Exit gate

This epic is complete when three processes can execute and resume the same
workflow safely; only sealed durable stages unlock credentials and provider
calls; opaque references cannot be forged or swapped; unknown effects remain
recoverable rather than retryable; and all selected vertical fixtures retain
their exact domain decisions, requests, transitions, and receipts.
