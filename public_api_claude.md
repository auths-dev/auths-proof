# Auths public SDK redesign — TypeScript and Python

**Status:** proposal, decision-ready. Not implemented.
**Scope:** the public surface of `@auths-dev/sdk` (npm) and `auths` (PyPI).
**Audience:** an engineer with zero prior context who will implement this.
**Authority:** subordinate to `AGENTS.md`, `architecture.toml`, `compliance.toml`, workspace metadata, `xtask`, and `docs/target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md`. Where this document conflicts with those, they win and this document is wrong.

Every factual claim below was checked against the source at the cited line on the `dev-githubAgentDemo` working tree. Prior proposals (`docs/specs/0036`, `0037`, the index-only `0040`, `docs/plans/simplify/**`, `docs/target-state/v1-api-*`) were read and treated as non-authoritative input; §13 records what was taken and what was rejected.

---

## 0. Summary

| | Today | Proposed |
|---|---|---|
| TS entry points / public symbols | 8 / 203 | 5 / 89 |
| Python modules / public symbols | 8 / 180 | 5 / 89 |
| Client types for one product | 3 (`Auths`, `ServiceClient`, `GitHubAgentClient`) | 1 (`Auths`) |
| Constructors | 6 | 1 (`connect`) + 2 runtime descriptors |
| Result unions a caller may switch on | 8 objects / 19 named variants / 18 string enums | 2 objects / 7 named variants / 6 Rust-owned enums |
| Exception classes on the happy path | 4 (`AuthsError`, `AuthsWorkflowError`, `GitHubAgentError`, `ProviderOperationError`) | 1 (`AuthsError`), never for a denial |
| Cross-language name overlap | 123 / 197 (62%) | 100%, gated |
| README quickstart concepts | 18 (TS), 18 (Py) | 6 |
| Python README quickstart | does not run | runs, executed in CI |

The single structural change: **one noun, one lifecycle, two runtimes, four outcomes.** Everything else follows.

---

## 1. Diagnosis

### 1.1 The package publishes three unrelated products under one name

`bindings/typescript/README.md` calls all three `auths`. They share no type, no result vocabulary, and no error class.

| | `Auths` | `ServiceClient` | `GitHubAgentClient` |
|---|---|---|---|
| Defined | [product.ts:163](bindings/typescript/src/product.ts:163) | [service.ts:179](bindings/typescript/src/service.ts:179) | [github-agent.ts:120](bindings/typescript/src/github-agent.ts:120) |
| Action input | `McpAction` (typed) | `Uint8Array` | none — `execute(session)` |
| Wire | in-process WASM | CBOR `application/auths+cbor` | JSON |
| Routes | — | `/v1/authority/*`, `/v1/profiles/*` | `/v1/demo/*` |
| Result | `Completed \| Denied \| Indeterminate \| RecoveryResult` | `ServiceCompleted \| ServiceDenied \| ServiceIndeterminate \| ServiceRecoverable` | `GitHubAgentOutcome` (5 kinds) |
| Errors | `AuthsWorkflowError` (unexported) | none — projects to results | `GitHubAgentError` |
| Disposal | `close()` + `Symbol.asyncDispose` | none | none |

`docs/product/PRODUCTION_SDK_QUICKSTART.md:16` names the third one `auths`. The maintainer's own flagship document wants one configured noun; the package offers three unnamed candidates.

### 1.2 The root entry point is MCP-only wearing profile-neutral names

`@auths-dev/sdk` exports `Auths`, `Authority`, `Actor`, `ExecutionResult`, `createAuths`. All of them are MCP.

- [product.ts:42](bindings/typescript/src/product.ts:42) — `export type Authority = McpToolAuthority;`
- [product.ts:167-176](bindings/typescript/src/product.ts:167) — `execute` takes `McpAction` and `McpClosedProvider`.
- [product.ts:145](bindings/typescript/src/product.ts:145) — `ExecutionReference.decode` accepts only `/^mcp1\.[0-9a-f]{64}\.[0-9a-f]{64}$/`, length exactly 134.
- Four of the five parameter types on `interface Auths` cannot be named from the root; `ProfilePlan` is exported from no public subpath at all.

GitHub, OpenTofu and PostgreSQL — three of the four `qualifiedProfiles` in `bindings/public-topology-v1.json` — cannot reach this object.

### 1.3 The product-named factory, and the entire production path, are unreachable

`createAuths(configuration)` requires an `AuthsConfiguration` minted by `createAuthsConfiguration`, exported from no entry point ([product.ts:343](bindings/typescript/src/product.ts:343); grep finds exactly one caller, `integrations.ts:156`, which hard-codes `"development"`). The SDK's own test codifies the trap: `assert.throws(() => createAuths({mode:"development",diagnostics:[]}), /not created by an integration/)` (`test/unit/product.test.js:13`).

`production.createAuths` ([integrations.ts:136-143](bindings/typescript/src/integrations.ts:136)) demands `configuration.mode === "production"`. No public code path can produce one. The same holds in Python (`_product.py` `_create_auths_configuration` is private, its one caller hard-codes `"development"`), where the guard additionally dereferences `.mode` before validating the argument type and so raises `AttributeError` rather than the documented `TypeError`.

**The documented production composition is dead code in both languages.**

### 1.4 The "generic five-verb transport" hands the developer raw protocol bytes

Both READMEs claim "No protocol bytes or GitHub credential enter application code." `ServiceClient` is `create(request: Uint8Array)`, `execute(authority, action: Uint8Array)` ([service.ts:180-188](bindings/typescript/src/service.ts:180)). No public helper builds those bytes. Two of its five methods are unusable against the reference node, which answers `core.unauthenticated-principal` for `create` and `delegate` — which is why `importAuthority` had to be added ([service.ts:507-527](bindings/typescript/src/service.ts:507), whose own docstring calls the client "a proof-carrying client that could not carry a proof inward").

### 1.5 One third of the public surface has never been exemplified

60 of 197 TypeScript exports and 43 of 173 Python exports appear in no test, doc, demo or recipe; 27 are dead in both languages simultaneously. Three whole families ship with zero worked examples: the GitHub agent types (6), `ReceiptInspection*`/`ReceiptSummary*`/`ReceiptViewMode`/`ReceiptDisclosure*` (12), and the `Service*` result/transport types (12).

`@auths-dev/sdk/framework` publishes `Signer` and `AtomicReservationStore` — and **no public API in the package accepts either one.** The MCP loop takes the unrelated 6-method `McpExecutionState`; the application profile takes the unrelated 4-method `ApplicationExecutionStore`.

### 1.6 Five result vocabularies and four "what next" vocabularies for the same questions

Same three outcomes, three disjoint name sets: `{Completed, Denied, Indeterminate}` at root, `{AuthorizedResult, DeniedResult, IndeterminateResult}` in `./verify`, `{ServiceCompleted, ServiceRejected, ServiceIndeterminate}` in `./service`. A caller composing execute → verify → remote writes three structurally identical switches over three unrelated name sets.

`retry` names three incompatible vocabularies on public types in one package: `RetryClass` (`never|safe|conditional|unknown`), `NextCall` (`never|backoff|resume|reconcile`), and `GitHubAgentOutcome.next` (`none|reconcile`). `ServiceIndeterminate.next_call` is populated from a native field literally named `retry`.

### 1.7 Both READMEs are broken, and the gates cannot see it

- The Python README quickstart **crashes**: it declares `async def publish_report(arguments)` (one parameter) while `DevelopmentMcpProvider.invoke` calls `handler(arguments, context)` → `McpProviderContractError`. It is also `async with` at module scope, a `SyntaxError` under `python file.py`. `bindings/python/tools/check_doc_snippets.py:32-37` only `compile()`s snippets; it never executes them.
- The flagship TypeScript clean-consumer gate cannot load: `bindings/typescript/test/package/packed-consumer.test.js` calls `readFile` at module top level while the `node:fs/promises` import on line 3 no longer includes it. The file throws `ReferenceError` at import, so the strictest public-surface assertion in the repository — claimed as evidence at `compliance.toml:1456` — never executes.
- Neither README contains a single error-handling example.
- The repository root `README.md` contains no link to any SDK documentation.

### 1.8 The error a TypeScript caller actually receives is not exported

`AuthsWorkflowError` is thrown at 177 sites, including from the public `Auths.execute`. It `extends Error`, not `AuthsError`, and is exported from no published subpath. A consumer can only `catch (e)` and regex `e.message`. Its 36 `WorkflowErrorCode`s are checked against `product/errors/v1/registry.json`: **zero of 36 are registered.** Family and retry are derived from `code.startsWith(...)` / `code.endsWith("-failed")` ([workflow/errors.ts:124-138](bindings/typescript/src/workflow/errors.ts:124)). Python fixed its half; TypeScript did not, so the two languages disagree about whether a workflow failure is catchable as `AuthsError`.

### 1.9 Definite denials are silently converted to "indeterminate" in both languages

`GitHubAgentClient.execute/replay/reconcile` route through one helper that wraps everything in a bare catch ([github-agent.ts:168-184](bindings/typescript/src/github-agent.ts:168)):

```ts
try { return projectOutcome(await call(`/v1/demo/sessions/${id}/${operation}`, {method:"POST"})); }
catch { return Object.freeze({ kind:"indeterminate", code:"transport-uncertain",
                               credentialRequests:"unknown", mutations:"unknown", next:"reconcile" }); }
```

`GitHubAgentError` is raised on every non-2xx and is swallowed here — along with schema mismatches and projection `TypeError`s. The one public error class of this client is nearly unreachable, and a policy denial becomes a reconciliation instruction. Python's `_operate` does the same with `except Exception`.

### 1.10 The two SDKs are not one API in two languages

62% name overlap. The divergence is architectural, not cosmetic:

- `identity`: TypeScript ships an adapter/parse/loader tier (`IdentityMethodAdapter`, `SignatureSuiteAdapter`, `loadIdentity`); Python ships a registry/resolver tier (`IdentityRegistry`, `IdentityResolver`, `ResolvedIdentityRecord`). **Recipe 01 in the two languages shares no API call.**
- `verify`: TypeScript has `loadVerifier()` → `Verifier`; Python has free functions `verify`/`verify_many` and no verifier object.
- MCP results: TypeScript exports 2 union aliases with anonymous inline variants (caller cannot name the success case); Python exports 5 named variant classes with no union alias (caller cannot annotate a return type). Both languages made the opposite wrong choice.
- `./framework` — the only surface third parties implement, and the only layer with 11/11 **name** parity — is structurally incompatible: `close?()`/`reopen?()` optional in TypeScript, `aclose()`/`reopen()` required in Python; `Signer.dispose?()` versus `Signer.aclose()`.
- A ported transport is wrong by 1000×: `timeoutMs` integer 100–120000 (TS) versus `timeout_seconds` float 0.1–120 (Python).

Nothing detects any of this. There is no general TypeScript↔Python name diff anywhere in the repository; `bindings/python/tests/test_vocabulary_parity.py` pins roughly twelve hand-picked symbols by substring-searching TypeScript source from a Python test.

### 1.11 Delegation makes the caller transcribe the boundary it was just handed

`delegate` takes 10 fields, 7 copied verbatim off the `boundary()` the SDK returned one line earlier, with one silent rename (`maximumExpirySeconds` → `expiresInSeconds`). `demos/github-issue/src/app.rs:1773` (`every_task_widening_is_rejected_before_session_creation`) proves the server rejects any widening. **The transcription buys zero security and is pure typo surface.**

### 1.12 Type-level defects on the primary success path

Python: `ExecutionResult` is not a discriminated union. `Completed.kind` and `PlanCompleted.kind` are both `Literal["completed"]`, and `execute` returns the wide 6-member union regardless of whether the caller passed `action=` or `plan=`. Verified with `mypy --strict`: `error: Item "PlanCompleted" of "Completed | PlanCompleted" has no attribute "receipt" [union-attr]` — **the primary success path does not type-check.**

TypeScript: the actual return types of `Auths.execute` (`SingleExecutionResult`, `PlanExecutionResult`) are private; the exported `ExecutionResult` is returned by nothing.

### 1.13 What is already right, and must survive

Not everything is broken. These are load-bearing and the redesign preserves all of them:

- **The effect axis.** `EffectState {not-applied, possible, applied}` is derived from the generated registry type in TypeScript (`Definition["outcomes"][number]["effect"]`), so it cannot drift from Rust by construction. That derivation trick is the pattern this proposal generalizes.
- **Fail-closed classification.** `auths_errors::classify` returns `known:false, retry: Unknown, effect: Possible, recommendedAction: ResumeAndReconcile` for an unrecognized code ([product/errors/auths-errors/src/lib.rs:310-318](product/errors/auths-errors/src/lib.rs:310)) — never downgraded to `NotApplied`, never a fourth value.
- **`RetryClass` vs `NextCall` named by the question each answers.** Different questions, permanently different identifiers.
- **Transport failure is Rust's decision.** `service.ts:317-324` classifies only what the platform *proved* into a closed 7-member `TransportFailure` and asks Rust what it means.
- **Required vs executed verifier configuration is compared before a session exists** ([github-agent.ts:198-200](bindings/typescript/src/github-agent.ts:198)).
- **Sealed handles.** `ExecutionReference`, `ServiceAuthority`, `ServiceReceipt` hold bytes in module-private `WeakMap`s with `toJSON(): never`.
- **The five security nouns and five product verbs**, hard-coded in `xtask/src/sdk_vocabulary.rs:129-136` and `product-errors.ts:31`.

---

## 2. Mental model and navigation

### 2.1 The model, in five sentences

1. An **Identity** is who is acting. It grants nothing.
2. An **Authority** is the bounded set of things that identity may do. Delegation only narrows it.
3. An **Action** is one exact, inert proposal, minted by a **profile** that owns its meaning.
4. `execute` produces an **Outcome**: it either applied the effect and gave you a **Receipt**, or it did not, and told you whether the effect might have happened anyway.
5. Verifying evidence is a separate, effect-free question that never returns permission.

Those are the five machine-enforced nouns (`xtask/src/sdk_vocabulary.rs:129`) plus one container word, `Outcome`. There is nothing else to learn to run the first example.

### 2.2 The one shape

```
        profile (owns the exact effect)
           │  mints
           ▼
   Authority ── narrowed by ──▶ delegate()
      │
      │  connect(local | remote)
      ▼
    Auths  ── execute(Action) ──▶ Outcome ──▶ Receipt
      │                              │
      │                              └── recoverable ──▶ resume(reference)
      └── close()

   verify(receipt, trust)  ──▶ Verification        [effect-free, no Auths needed]
   authenticate(message)   ──▶ AuthenticatedMessage [effect-free, no Auths needed]
```

**Who performs the effect is chosen once, at `connect`, and is visible in the descriptor name.** `local(...)` means this process performs it and you supply the handlers, the signer, and the store. `remote(...)` means an Auths operator runtime holds the credentials and performs it, and you supply an endpoint and a proof you already hold. That difference is security-meaningful, so it is a named argument at the one call site where the trust decision is actually made — and nowhere else.

### 2.3 Package navigation

Five entry points, four purpose labels from the enforced owner set (`product`, `component`, `profile`, `testkit`).

| Import | Owner | One-line purpose | Needs the execution engine? |
|---|---|---|---|
| `@auths-dev/sdk` / `auths` | `product` | Run protected actions | yes |
| `@auths-dev/sdk/profiles` / `auths.profiles` | `profile` | Which exact effects: `mcp`, `github`, `opentofu`, `postgresql` | no (values only) |
| `@auths-dev/sdk/verify` / `auths.verify` | `component` | Check proofs and receipts. Effect-free. Never returns permission | verification only |
| `@auths-dev/sdk/identity` / `auths.identity` | `component` | Authenticate signed bytes. No capability, no execution | identity only |
| `@auths-dev/sdk/testkit` / `auths.testkit` | `testkit` | Fixtures and adapter conformance | test-time |

Deleted as public entry points: `./service` (remote is a runtime, not a second product), `./integrations` (`local`/`remote` are runtime descriptors and belong beside `connect`), `./framework` (`Signer` and `AtomicReservationStore` are literally the named fields of `local(...)`, so IntelliSense on that options object *is* the discovery path — strictly better than a subpath nobody imports).

**Progressive disclosure is by argument depth, not by module.** `local({profile, authority})` runs. `local({profile, authority, signer, store, receipts, trust, approval, observer})` is production. You meet each contract exactly when you type the field that needs it.

---

## 3. The proposed public surface

### 3.1 TypeScript — `@auths-dev/sdk` (product)

```ts
// ─── branding (not exported; makes profile linkage unforgeable) ──────────
declare const BRAND: unique symbol;

// ─── the five security nouns ────────────────────────────────────────────

/** Who is acting. Projected from public key material. Never secret. */
export interface Identity {
  readonly principal: string;            // did:key:… / did:keri:…
  readonly method: string;
  readonly suite: string;
}

/** What may be done, bound to the profile that minted it. Narrows only. */
export interface Authority<P extends Profile = Profile> {
  readonly [BRAND]: readonly ["authority", P];
  readonly profileId: string;
  toJSON(): never;                       // credential material never serializes
}

/** One exact inert proposal. `R` is the result type this action produces. */
export interface Action<R = unknown> {
  readonly [BRAND]: readonly ["action", R];
  readonly profileId: string;
}

/** An ordered, all-or-stop sequence. Minted only by profiles that plan. */
export interface Plan<R extends readonly unknown[] = readonly unknown[]> {
  readonly [BRAND]: readonly ["action", R];
  readonly profileId: string;
  readonly length: number;
}

/** Signed evidence of a decision or an observed effect. */
export interface Receipt {
  readonly executionId: string;
  readonly profileId: string;
  readonly issuedAt: number;             // unix seconds
  toJSON(): never;                       // use encodeReceipt from ./verify
}

/** Optional confirmation of one exact transaction. Not authority. */
export interface Approval {
  readonly [BRAND]: readonly ["approval", never];
  readonly policyId: string;
}

// ─── profile linkage ────────────────────────────────────────────────────

export interface Profile {
  readonly [BRAND]: readonly ["profile", string];
  readonly id: string;
  readonly version: number;
}

// ─── the one client ─────────────────────────────────────────────────────

export interface Auths<P extends Profile = Profile> extends AsyncDisposable {
  /** Who this handle acts as. */
  readonly identity: Identity;
  /** What it may do — description only. Never credential bytes. */
  readonly scope: Scope;
  /** How it is wired, and every reason it is not production-ready. */
  readonly runtime: RuntimeFacts;

  execute<R>(action: Action<R> & { readonly profileId: P["id"] },
             options?: ExecuteOptions): Promise<Outcome<R>>;

  executePlan<R extends readonly unknown[]>(
             plan: Plan<R> & { readonly profileId: P["id"] },
             options?: ExecuteOptions): Promise<Outcome<R>>;

  /** Narrow authority for another identity. Never widens. */
  delegate(grant: Grant): Promise<Delegation<P>>;

  /** Continue an execution that returned `kind: "recoverable"`. */
  resume(reference: Reference): Promise<Outcome<unknown>>;

  close(): Promise<void>;
}

export interface Scope {
  readonly permissions: readonly string[];
  readonly audiences: readonly string[];
  readonly notBefore: number;
  readonly expiresAt: number;
  readonly remainingDepth: number;
}

export interface RuntimeFacts {
  readonly mode: "development" | "production" | "remote";
  /** Every property that is not production-durable, e.g.
   *  "state=in-memory-not-production-durable". Empty in production. */
  readonly warnings: readonly string[];
  readonly profileId: string;
  readonly sdkVersion: string;
}

export interface ExecuteOptions {
  /** Idempotency key. Omitting it means a retry is a second effect. */
  readonly requestId?: string;
  readonly signal?: AbortSignal;
}

export interface Grant {
  readonly label: string;
  readonly expiresInSeconds: number;
  /** Omitted: inherit the parent scope unchanged. Supplied: narrow further. */
  readonly permissions?: readonly string[];
}

// ─── connecting ─────────────────────────────────────────────────────────

export interface Runtime<P extends Profile> { readonly [BRAND]: readonly ["runtime", P]; }

export function connect<P extends Profile>(runtime: Runtime<P>): Promise<Auths<P>>;

/** This process performs the effect. You own the handlers and the custody. */
export function local<P extends Profile>(options: Readonly<{
  profile: P;
  authority: Authority<P>;
  /** Omit for an ephemeral development key; `runtime.mode` reports it. */
  signer?: Signer;
  /** Omit for non-durable in-memory state; `runtime.mode` reports it. */
  store?: ReservationStore;
  receipts?: ReceiptStore;
  approval?: ApprovalPolicy;
  observer?: Observer;
}>): Runtime<P>;

/** An Auths operator runtime holds the credentials and performs the effect. */
export function remote<P extends Profile>(options: Readonly<{
  endpoint: string | URL;
  profile: P;
  identity: Uint8Array;
  authority: Authority<P>;
  timeoutMs?: number;                    // 100..120_000, default 15_000
  fetch?: typeof fetch;
}>): Runtime<P>;

// ─── the one outcome ────────────────────────────────────────────────────
// `kind` tells you which fields exist. The four Rust-owned axes tell you
// what to do. No axis is ever a literal — see §7.1.

interface Axes {
  readonly code: AuthsErrorCode;
  readonly effect: EffectState;          // did it happen?
  readonly retry: RetryClass;            // may I retry?
  readonly next: NextCall;               // what do I call next?
  readonly recommendedAction: RecommendedAction;
  readonly stage: ProductStage;
  readonly requestId?: string;
}

export interface Completed<R> {
  readonly kind: "completed";
  readonly ok: true;
  readonly value: R;
  readonly receipt: Receipt;
  readonly executionId: string;
}
export interface Denied      extends Axes { readonly kind: "denied";        readonly ok: false; readonly reason: string; }
export interface Indeterminate extends Axes { readonly kind: "indeterminate"; readonly ok: false; readonly reason: string; }
export interface Recoverable extends Axes { readonly kind: "recoverable";   readonly ok: false; readonly reference: Reference; readonly executionId: string; }

export type Outcome<R> = Completed<R> | Denied | Indeterminate | Recoverable;

export type Delegation<P extends Profile> =
  | { readonly kind: "delegated"; readonly ok: true; readonly auths: Auths<P> }
  | Denied | Indeterminate;

/** Opaque, serializable handle to an interrupted execution. */
export interface Reference {
  encode(): Uint8Array;
  toJSON(): never;
}
export function decodeReference(bytes: Uint8Array): Reference;

// ─── the Rust-owned vocabularies (types only; values live in Rust) ──────
export type EffectState = "not-applied" | "possible" | "applied";
export type RetryClass = "never" | "safe" | "conditional" | "unknown";
export type NextCall = "never" | "backoff" | "resume" | "reconcile";
export type RecommendedAction = /* generated from the registry */ string & {};
export type ProductStage = /* generated from the registry */ string & {};
export type ProductVerb = "create" | "delegate" | "execute" | "resume" | "verify";
export type AuthsErrorCode = /* generated union of the 48 registry codes */ string & {};

// ─── the one error class ────────────────────────────────────────────────
/**
 * Thrown only when there is NO outcome to report: invalid configuration,
 * engine load failure, use after close. A denial or an indeterminate result
 * is never an exception.
 */
export class AuthsError extends Error {
  readonly code: AuthsErrorCode;
  readonly effect: EffectState;
  readonly retry: RetryClass;
  readonly next: NextCall;
  readonly recommendedAction: RecommendedAction;
  readonly stage: ProductStage;
  readonly requestId?: string;
  readonly reference?: Reference;        // present iff effect === "possible"
}

// ─── production contracts (implement these; they are `local()`'s fields) ─
export interface Signer {
  identity(): Promise<Identity>;
  sign(request: SigningRequest): Promise<SigningResponse>;
  close(): Promise<void>;
}
export interface SigningRequest  { readonly kind: SigningObjectKind; readonly payload: Uint8Array; }
export interface SigningResponse { readonly signature: Uint8Array; readonly suite: string; }
export type SigningObjectKind = "authority" | "action" | "receipt";

export interface ReservationStore {
  reserve(executionId: string, record: ReservationRecord): Promise<"acquired" | "exact-replay" | "conflict">;
  markProviderEntry(executionId: string, record: ReservationRecord): Promise<void>;
  load(reference: string): Promise<ReservationRecord | undefined>;
  release(executionId: string): Promise<void>;
  close(): Promise<void>;
}
export interface ReservationRecord { readonly executionId: string; readonly reference: string; readonly record: Uint8Array; }

export interface ReceiptStore {
  persist(executionId: string, receipt: Uint8Array): Promise<void>;
  close(): Promise<void>;
}

export interface Observer { checkpoint(event: CheckpointEvent): void; }
export interface CheckpointEvent {
  readonly stage: "reserved" | "provider-entry" | "provider-exit" | "committed" | "released";
  readonly executionId: string;
  readonly requestId?: string;
}

export interface ApprovalPolicy {
  readonly [BRAND]: readonly ["approval-policy", never];
  readonly policyId: string;
}
export const approval: {
  none(options: Readonly<{ policyId: string }>): Promise<ApprovalPolicy>;
  threshold(options: Readonly<{ policyId: string; threshold: number; approvers: readonly Approver[] }>): Promise<ApprovalPolicy>;
};
export interface Approver { approve(request: ApprovalRequest): Promise<Approval>; }
export interface ApprovalRequest { readonly requestId: string; readonly transactionDigest: Uint8Array; readonly policyId: string; }

// ─── diagnostics ────────────────────────────────────────────────────────
/** Bounded installed-runtime facts. Never reads application secrets. */
export function doctor(): Promise<DoctorReport>;
export interface DoctorReport {
  readonly ok: boolean;
  readonly warnings: readonly string[];
  readonly facts: Readonly<Record<string, string>>;
  toString(): string;                    // the `auths doctor` CLI rendering
  toJSON(): object;
}
```

**Root count: 47 declarations** (`Identity`, `Authority`, `Action`, `Plan`, `Receipt`, `Approval`, `Profile`, `Auths`, `Scope`, `RuntimeFacts`, `ExecuteOptions`, `Grant`, `Runtime`, `connect`, `local`, `remote`, `Completed`, `Denied`, `Indeterminate`, `Recoverable`, `Outcome`, `Delegation`, `Reference`, `decodeReference`, `EffectState`, `RetryClass`, `NextCall`, `RecommendedAction`, `ProductStage`, `ProductVerb`, `AuthsErrorCode`, `AuthsError`, `Signer`, `SigningRequest`, `SigningResponse`, `SigningObjectKind`, `ReservationStore`, `ReservationRecord`, `ReceiptStore`, `Observer`, `CheckpointEvent`, `ApprovalPolicy`, `approval`, `Approver`, `ApprovalRequest`, `doctor`, `DoctorReport`).

### 3.2 TypeScript — `@auths-dev/sdk/profiles` (profile)

Profiles mint the five nouns. **They introduce no new noun names**, which is why ~30 `Mcp*` types disappear.

```ts
import type { Action, Authority, Plan, Profile } from "@auths-dev/sdk";

// ─── MCP ────────────────────────────────────────────────────────────────
export type ToolMap = Record<string, (input: never, context: ToolContext) => unknown>;
export interface ToolContext { readonly executionId: string; readonly signal: AbortSignal; }

export interface McpProfile<T extends ToolMap> extends Profile {
  readonly id: "auths.mcp";
  readonly version: 1;
  /** Mints an Action. A tool name not in T is a compile error. */
  call<K extends keyof T & string>(tool: K, input: Parameters<T[K]>[0]): Action<Awaited<ReturnType<T[K]>>>;
  /** Mints an Authority bound to THIS profile. A typo is a compile error. */
  allowTools<K extends keyof T & string>(tools: readonly K[]): Authority<McpProfile<T>>;
  /** Ordered, all-or-stop. Result is a tuple of member results. */
  plan<const A extends readonly Action<unknown>[]>(members: A): Plan<{ [I in keyof A]: A[I] extends Action<infer R> ? R : never }>;
}

export const mcp: {
  /** `service` is the MCP service name the authority is bound to. */
  tools<const T extends ToolMap>(service: string, handlers: T): McpProfile<T>;
};

// ─── operator-runtime profiles (no in-process handlers) ─────────────────
export interface RemoteProfile<Request, Result> extends Profile {
  action(request: Request): Action<Result>;
  authority(proof: Uint8Array): Authority<RemoteProfile<Request, Result>>;
}

export const github: {
  issueAddress(): RemoteProfile<IssueAddressRequest, IssueAddressResult>;
};
export interface IssueAddressRequest {
  readonly candidateBundle: Uint8Array;
  readonly candidateRevision: string;
}
export interface IssueAddressResult {
  readonly branchRef: string;
  readonly pullRequestNumber: number;
  readonly pullRequestUrl: string;
}

export const opentofu:   { savedPlanApply(): RemoteProfile<SavedPlanApplyRequest, SavedPlanApplyResult> };
export const postgresql: { boundedUpdate(): RemoteProfile<BoundedUpdateRequest, BoundedUpdateResult> };
// (request/result interfaces for these two follow the same shape)
```

**Profiles count: 14 declarations.** Down from 35.

### 3.3 TypeScript — `@auths-dev/sdk/verify` (component)

Effect-free. Takes its trust anchor explicitly. **Never takes an endpoint** — see §13.3.

```ts
import type { AuthsErrorCode, Receipt } from "@auths-dev/sdk";

/** The trust anchor a verification is evaluated against. */
export interface Trust { readonly [BRAND]: readonly ["trust", never]; }
export function trustFromRawKey(publicKey: Uint8Array, options?: Readonly<{ suite?: string }>): Trust;
export function trustFromBundle(bundle: Uint8Array): Trust;

export interface Verified   { readonly kind: "verified";   readonly passed: true;  readonly stage: VerificationStage; readonly principal: string; readonly profileId: string; }
export interface Rejected   { readonly kind: "rejected";   readonly passed: false; readonly stage: VerificationStage; readonly code: AuthsErrorCode; readonly reason: string; }
export interface Unproven   { readonly kind: "unproven";   readonly passed: false; readonly stage: VerificationStage; readonly code: AuthsErrorCode; readonly reason: string; }
export type Verification = Verified | Rejected | Unproven;
export type VerificationStage = "decode" | "authority" | "action" | "context" | "signature" | "policy";

/** Verify one proof against an exact action and a trust anchor. */
export function verifyProof(input: Readonly<{
  proof: Uint8Array; action: Uint8Array; context: Uint8Array; trust: Trust;
}>): Promise<Verification>;

/** Bounded batch: 1..256 inputs. Fails closed on the first malformed input. */
export function verifyProofs(inputs: readonly Readonly<{
  proof: Uint8Array; action: Uint8Array; context: Uint8Array; trust: Trust;
}>[]): Promise<readonly Verification[]>;

/** Verify a receipt's signature and its decision→execution link. In-process. */
export function verifyReceipt(receipt: Receipt | Uint8Array, trust: Trust): Promise<Verification>;

export function encodeReceipt(receipt: Receipt): Uint8Array;
export function decodeReceipt(bytes: Uint8Array): Receipt;
```

**Verify count: 13 declarations.** Down from 37.

> `verifyProof` takes a **named record**, not three positional `Uint8Array`s. Today `verifier.verify(proof, action, context)` type-checks when transposed and fails only as a runtime denial ([verifier/result.ts:145](bindings/typescript/src/verifier/result.ts:145)); Python's `VerificationInput` is a bare `Tuple[bytes, bytes, bytes]` consumed positionally.

### 3.4 TypeScript — `@auths-dev/sdk/identity` (component)

```ts
export interface Identity { readonly principal: string; readonly method: string; readonly suite: string; }

/** Parse public identity bytes. Fails closed; never throws for bad input. */
export function decodeIdentity(packet: Uint8Array): Identity | undefined;
export function encodeIdentity(identity: Identity): Uint8Array;

/** The exact bytes a signer must sign to authenticate `message` as `identity`. */
export function signingPreimage(identity: Identity, message: Uint8Array): Uint8Array;

export interface AuthenticatedMessage { readonly identity: Identity; readonly message: Uint8Array; }

/**
 * Authenticate `message` as signed by `identity`. Returns `undefined` when the
 * signature does not verify. Performs the cryptography in-process; no
 * caller-supplied adapter can substitute the message or the identity.
 */
export function authenticate(input: Readonly<{
  identity: Identity; message: Uint8Array; signature: Uint8Array;
}>): Promise<AuthenticatedMessage | undefined>;
```

**Identity count: 6 declarations.** Down from 15 (TS) / 19 (Python), and the two languages now share all six.

> `Identity` is published from both `.` and `./identity`. It must be **one declaration re-exported**, never a second structurally identical one, or the homonym rule fires (`public-api.mjs:132-146` compares `sourceFile:pos`; `test_vocabulary_parity.py:214-238` compares `id(value)`). Declare it in `src/identity.ts` and write `export type { Identity } from "./identity.js";` at the root. The same rule governs `Profile` (root + `./profiles`), `Receipt` (root + `./verify`), and every port re-exported into `./testkit`. Verify with `node tools/public-api.mjs --shape` before writing consumer code.

### 3.5 TypeScript — `@auths-dev/sdk/testkit` (testkit)

```ts
import type { Approver, Observer, ReceiptStore, ReservationStore, Signer } from "@auths-dev/sdk";

/** Deterministic development doubles. Never valid in production. */
export const fixtures: {
  signer(): Promise<Signer>;
  reservationStore(): ReservationStore;
  receiptStore(): ReceiptStore;
  approver(decision?: "approved" | "rejected"): Approver;
  observer(): Observer & { readonly events: readonly CheckpointEvent[] };
  clock(atUnixSeconds: number): Clock;
  trust(): Promise<Trust>;
};
export interface Clock { now(): number; }

/**
 * Auths owns the assertions. The candidate factory cannot mark a case passed;
 * the runner chooses inputs, schedules concurrency and cancellation, injects
 * faults, and assigns results to Rust-owned case ids.
 */
export function certifySigner(factory: () => Promise<Signer>): Promise<ConformanceReport>;
export function certifyReservationStore(factory: () => Promise<ReservationStore>): Promise<ConformanceReport>;
export function certifyReceiptStore(factory: () => Promise<ReceiptStore>): Promise<ConformanceReport>;
export function certifyApprover(factory: () => Promise<Approver>): Promise<ConformanceReport>;

export interface ConformanceReport {
  readonly ok: boolean;
  readonly suiteVersion: string;
  readonly cases: readonly ConformanceCase[];
  toString(): string;
}
export interface ConformanceCase {
  readonly id: string;                   // Rust-owned case id
  readonly ok: boolean;
  readonly detail?: string;
}
```

**Testkit count: 9 declarations.** Down from 29.

**TypeScript total: 47 + 14 + 13 + 6 + 9 = 89 declarations across 5 entry points** (203 → 89, −56%). Python is the same 89 after case normalization.

### 3.6 Python — `auths` (product)

Same symbols, Python idiom. `Auths` is **not generic** — see §6.3 for the mypy evidence.

```python
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Generic, Literal, Mapping, Optional, Protocol, TypeVar, Union

R = TypeVar("R")

# ─── the five security nouns ────────────────────────────────────────────

@dataclass(frozen=True)
class Identity:
    principal: str
    method: str
    suite: str

class Authority:
    """What may be done. Narrows only. Credential material never serializes."""
    profile_id: str
    def __reduce__(self) -> NoReturn: ...          # not picklable

@dataclass(frozen=True)
class Action(Generic[R]):
    """One exact inert proposal. `R` is the result this action produces."""
    profile_id: str

@dataclass(frozen=True)
class Plan(Generic[R]):
    profile_id: str
    length: int

class Receipt:
    execution_id: str
    profile_id: str
    issued_at: int
    def __reduce__(self) -> NoReturn: ...          # use auths.verify.encode_receipt

@dataclass(frozen=True)
class Approval:
    policy_id: str

class Profile(Protocol):
    id: str
    version: int

# ─── the one client ─────────────────────────────────────────────────────

class Auths:
    identity: Identity
    scope: Scope
    runtime: RuntimeFacts

    async def execute(self, action: Action[R], *, request_id: Optional[str] = None) -> Outcome[R]: ...
    async def execute_plan(self, plan: Plan[R], *, request_id: Optional[str] = None) -> Outcome[R]: ...
    async def delegate(self, *, label: str, expires_in_seconds: int,
                       permissions: Optional[tuple[str, ...]] = None) -> Delegation: ...
    async def resume(self, reference: Reference) -> Outcome[Any]: ...
    async def aclose(self) -> None: ...
    async def __aenter__(self) -> Auths: ...
    async def __aexit__(self, *exc: object) -> None: ...

@dataclass(frozen=True)
class Scope:
    permissions: tuple[str, ...]
    audiences: tuple[str, ...]
    not_before: int
    expires_at: int
    remaining_depth: int

@dataclass(frozen=True)
class RuntimeFacts:
    mode: Literal["development", "production", "remote"]
    warnings: tuple[str, ...]
    profile_id: str
    sdk_version: str

# ─── connecting ─────────────────────────────────────────────────────────

class Runtime:
    """Opaque runtime descriptor. Build with local() or remote()."""

async def connect(runtime: Runtime) -> Auths: ...

def local(*, profile: Profile, authority: Authority,
          signer: Optional[Signer] = None,
          store: Optional[ReservationStore] = None,
          receipts: Optional[ReceiptStore] = None,
          approval: Optional[ApprovalPolicy] = None,
          observer: Optional[Observer] = None) -> Runtime: ...

def remote(*, endpoint: str, profile: Profile, identity: bytes, authority: Authority,
           timeout_ms: int = 15_000) -> Runtime: ...

# ─── the one outcome ────────────────────────────────────────────────────

@dataclass(frozen=True)
class Completed(Generic[R]):
    kind: Literal["completed"]
    ok: Literal[True]
    value: R
    receipt: Receipt
    execution_id: str
    def __bool__(self) -> bool: raise TypeError(
        "an Auths outcome has no truth value; branch on outcome.ok, or match outcome.kind")

@dataclass(frozen=True)
class Denied:
    kind: Literal["denied"]
    ok: Literal[False]
    code: AuthsErrorCode
    effect: EffectState
    retry: RetryClass
    next: NextCall
    recommended_action: RecommendedAction
    stage: ProductStage
    reason: str
    request_id: Optional[str] = None
    def __bool__(self) -> bool: raise TypeError(...)

@dataclass(frozen=True)
class Indeterminate:            # same fields as Denied
    kind: Literal["indeterminate"]
    ...

@dataclass(frozen=True)
class Recoverable:              # Denied's fields plus:
    kind: Literal["recoverable"]
    reference: Reference
    execution_id: str
    ...

Outcome = Union[Completed[R], Denied, Indeterminate, Recoverable]

Delegation = Union["Delegated", Denied, Indeterminate]

@dataclass(frozen=True)
class Delegated:
    kind: Literal["delegated"]
    ok: Literal[True]
    auths: Auths

class Reference:
    def encode(self) -> bytes: ...
def decode_reference(data: bytes) -> Reference: ...

# ─── Rust-owned vocabularies (str enums so `.value` round-trips) ─────────
class EffectState(str, Enum):  NOT_APPLIED = "not-applied"; POSSIBLE = "possible"; APPLIED = "applied"
class RetryClass(str, Enum):   NEVER = "never"; SAFE = "safe"; CONDITIONAL = "conditional"; UNKNOWN = "unknown"
class NextCall(str, Enum):     NEVER = "never"; BACKOFF = "backoff"; RESUME = "resume"; RECONCILE = "reconcile"
class RecommendedAction(str, Enum): ...        # generated from the registry
class ProductStage(str, Enum): ...             # generated from the registry
class ProductVerb(str, Enum):  CREATE = "create"; DELEGATE = "delegate"; EXECUTE = "execute"; RESUME = "resume"; VERIFY = "verify"
AuthsErrorCode = str                            # narrowed by the generated registry

# ─── the one error class ────────────────────────────────────────────────
class AuthsError(Exception):
    code: AuthsErrorCode
    effect: EffectState
    retry: RetryClass
    next: NextCall
    recommended_action: RecommendedAction
    stage: ProductStage
    request_id: Optional[str]
    reference: Optional[Reference]      # present iff effect is POSSIBLE

# ─── production contracts (local()'s named fields) ──────────────────────
class Signer(Protocol):
    async def identity(self) -> Identity: ...
    async def sign(self, request: SigningRequest) -> SigningResponse: ...
    async def aclose(self) -> None: ...

class ReservationStore(Protocol):
    async def reserve(self, execution_id: str, record: ReservationRecord) -> Literal["acquired","exact-replay","conflict"]: ...
    async def mark_provider_entry(self, execution_id: str, record: ReservationRecord) -> None: ...
    async def load(self, reference: str) -> Optional[ReservationRecord]: ...
    async def release(self, execution_id: str) -> None: ...
    async def aclose(self) -> None: ...

class ReceiptStore(Protocol):
    async def persist(self, execution_id: str, receipt: bytes) -> None: ...
    async def aclose(self) -> None: ...

class Observer(Protocol):
    def checkpoint(self, event: CheckpointEvent) -> None: ...

class Approver(Protocol):
    async def approve(self, request: ApprovalRequest) -> Approval: ...

class approval:
    @staticmethod
    async def none(*, policy_id: str) -> ApprovalPolicy: ...
    @staticmethod
    async def threshold(*, policy_id: str, threshold: int, approvers: tuple[Approver, ...]) -> ApprovalPolicy: ...

# ─── diagnostics ────────────────────────────────────────────────────────
async def doctor() -> DoctorReport: ...

@dataclass(frozen=True)
class DoctorReport:
    ok: bool
    warnings: tuple[str, ...]
    facts: Mapping[str, str]
    def __str__(self) -> str: ...       # the `python -m auths doctor` rendering
```

Python `auths.profiles`, `auths.verify`, `auths.identity`, `auths.testkit` mirror §3.2–§3.5 with snake_case names, `Protocol` where TypeScript uses `interface`, and keyword-only arguments where TypeScript uses an options object. Every symbol name in each module is the case-normalized twin of its TypeScript counterpart, and §11.2 makes that a gate.

---

## 4. Before and after

### 4.1 Workflow A — protect one MCP action (the README quickstart)

**Before (TypeScript, `bindings/typescript/README.md:16-43`, 26 lines, 18 concepts):**

```ts
import { development } from "@auths-dev/sdk/integrations";
import { mcp } from "@auths-dev/sdk/profiles";

const provider = mcp.developmentProvider({
  tools: {
    async publish_report(arguments_) { return { published: true, arguments: arguments_ }; },
  },
});
const auths = await development.createAuths({ authority: mcp.allowTools(["publish_report"]) });
try {
  const result = await auths.execute({
    action: mcp.callTool({ name: "publish_report", arguments: { period: "weekly" } }),
    provider,
  });
  console.log(result);            // `result` is a 4-member union; `.receipt` does not narrow
} finally {
  await auths.close();
}
```

The handler parameter is spelled `arguments_` to dodge a reserved word, and `arguments` is an options key. `result.kind` must be checked before anything is readable. The `provider` is passed on every call.

**After (TypeScript, 11 lines, 6 concepts — `connect`, `local`, `mcp`, `authority`, `execute`, `outcome.ok`):**

```ts
import { connect, local } from "@auths-dev/sdk";
import { mcp } from "@auths-dev/sdk/profiles";

const reports = mcp.tools("reports", {
  publish_report: async ({ period }: { period: string }) => ({ published: period }),
});

await using auths = await connect(local({
  profile: reports,
  authority: reports.allowTools(["publish_report"]),
}));

const outcome = await auths.execute(reports.call("publish_report", { period: "weekly" }));
if (outcome.ok) console.log(outcome.value.published, outcome.receipt.executionId);
else console.error(outcome.code, outcome.effect, outcome.next);
```

`outcome.value.published` is `string` — inferred through the tool map. `reports.call("publish_repot", …)` is a compile error. `reports.allowTools(["delete_report"])` is a compile error. Neither is possible today.

**Before (Python, `bindings/python/README.md:17-38`) — this does not run.** It is `async with` at module scope (`SyntaxError`) and the one-parameter handler is rejected by `DevelopmentMcpProvider.invoke`, which calls `handler(arguments, context)`.

**After (Python, runs as `python quickstart.py`):**

```python
import asyncio
from auths import connect, local
from auths.profiles import mcp

reports = mcp.tools("reports", {
    "publish_report": lambda period: {"published": period},
})

async def main() -> None:
    async with await connect(local(
        profile=reports,
        authority=reports.allow_tools(("publish_report",)),
    )) as auths:
        outcome = await auths.execute(reports.call("publish_report", period="weekly"))
        if outcome.ok:
            print(outcome.value["published"], outcome.receipt.execution_id)
        else:
            print(outcome.code, outcome.effect, outcome.next)

asyncio.run(main())
```

The handler signature is the tool's own signature. `ToolContext` is available as an optional second parameter and is not required — which is the defect in today's README, fixed in the contract rather than in the prose.

### 4.2 Workflow B — the GitHub issue agent (the launch golden path)

**Before (`docs/product/PRODUCTION_SDK_QUICKSTART.md:13-43`, 29 lines):**

```ts
import { createGitHubAgentClient } from "@auths-dev/sdk/service";

const auths = createGitHubAgentClient({ endpoint: "https://executor.example" });
const boundary = await auths.boundary();
const task = await auths.delegate({
  repository: boundary.repository,          // ─┐
  issueNumber: boundary.issueNumber,        //  │
  baseRef: boundary.baseRef,                //  │ 7 fields copied verbatim
  baseRevision: boundary.baseRevision,      //  │ off the object the SDK
  allowedPaths: boundary.allowedPaths,      //  │ returned one line earlier,
  protectedPaths: boundary.protectedPaths,  //  │ with one silent rename
  expiresInSeconds: boundary.maximumExpirySeconds, // ─┘
  branchBudget: 1,
  draftPullRequestBudget: 1,
  agentLabel: "issue-agent",
});
const candidate = await auths.inspectCandidate(task, {
  path: "./candidate.bundle", baseRevision: boundary.baseRevision, candidateRevision,
});
if (candidate.kind !== "inspected") throw new Error(candidate.decisionCode);
let result = await auths.execute(task);               // `task` threaded through 5 calls
if (result.next === "reconcile") result = await auths.reconcile(task);
if (result.kind !== "completed" && result.kind !== "reconciled") throw new Error(result.code);
const receipts = await auths.verifyReceipts(task);    // counts array entries; verifies nothing
```

**After (13 lines):**

```ts
import { connect, remote } from "@auths-dev/sdk";
import { github } from "@auths-dev/sdk/profiles";
import { readFile } from "node:fs/promises";

const issueAddress = github.issueAddress();

await using auths = await connect(remote({
  endpoint: "https://executor.example",
  profile: issueAddress,
  identity: await readFile("./agent.identity"),
  authority: issueAddress.authority(await readFile("./agent.proof")),
}));

const outcome = await auths.execute(issueAddress.action({
  candidateBundle: await readFile("./candidate.bundle"),
  candidateRevision,
}), { requestId: "issue-agent-1" });

if (outcome.ok) console.log(outcome.value.pullRequestUrl, outcome.receipt.executionId);
```

What changed and why:

- **`boundary()` is gone.** The deployment owns the repository, issue, base revision, path policy and budgets. `app.rs:1773` already rejects every widening, so restating them client-side bought nothing. If an operator wants to show the caller its bounds, `auths.scope` reports them as a description.
- **`delegate(task)` is gone from the golden path.** The caller was not delegating; it was restating a boundary in order to obtain a session. `connect(remote({authority}))` carries the proof the caller already holds. `delegate` survives for its real meaning — minting *narrower* authority for another identity — and now returns a result union (§7.2).
- **The session argument is gone.** `execute`, `replay`, `reconcile`, `verifyReceipts` all took a `session` the client had just validated. The handle is the session.
- **`reconcile` is gone as a verb.** Reconciliation is `outcome.next === "reconcile"` plus `resume(outcome.reference)`; there is no second recovery vocabulary.
- **`verifyReceipts` is gone.** It counted array entries and compared one id while its name and its `kind: "verified"` claimed cryptographic verification. Real receipt verification is `verifyReceipt(receipt, trust)` in `./verify`, in-process, against a trust anchor the caller names.
- **`GitHubAgentError` is gone**, and with it the bare catch that turned every denial, HTTP status and schema mismatch into `indeterminate / transport-uncertain`.

### 4.3 Workflow C — delegate narrower authority to an agent

**Before (`bindings/recipes/typescript/04-delegate-to-agent.ts`, 24 lines):**

```ts
const auths = await development.createAuths({ authority: mcp.allowTools(["publish_report","delete_report"]) });
const agent = await auths.delegate({ authority: mcp.allowTools(["publish_report"]), name: "report-agent", expiresInSeconds: 300 });
const first  = await agent.execute({ action, provider, requestId: "delegated-once" });
const second = await agent.execute({ action, provider, requestId: "delegated-once" });
const broader = await agent.execute({ action: mcp.callTool({name:"delete_report",…}), provider, requestId:"delegated-broader" });
if (first.kind !== "completed" || second.kind !== "exact-replay" || broader.kind !== "denied") throw new Error(…);
```

`delegate` returns `Promise<Auths>`, so a denial can only be an exception — and against the reference node a denial is the *normal* path (`core.unauthenticated-principal`, `product/runtime/auths-node/src/kernel.rs:324`).

**After:**

```ts
const delegation = await auths.delegate({ label: "report-agent", expiresInSeconds: 300,
                                          permissions: ["publish_report"] });
if (!delegation.ok) {
  console.error("delegation refused", delegation.code, delegation.effect, delegation.next);
  return;
}
await using agent = delegation.auths;

const first  = await agent.execute(reports.call("publish_report", { period: "weekly" }), { requestId: "once" });
const second = await agent.execute(reports.call("publish_report", { period: "weekly" }), { requestId: "once" });
const wider  = await agent.execute(reports.call("delete_report",  { period: "weekly" }));

console.log(first.ok, second.receipt === first.receipt, wider.kind === "denied");
```

A refused delegation is a value with the four axes on it, not an exception a caller will wrap in `catch (e) { retry() }`.

### 4.4 Workflow D — verify a receipt offline (a relying party, no execution runtime)

**Before:** `decodeReceipt` and `verifyReceipt` exist in **two** places — `./verify` and, as unreachable dead code, in `product.ts:371-381`. `verifyReceipt(receipt)` takes no trust anchor at all; the trust is whatever the packaged engine was built with.

**After:**

```ts
import { decodeReceipt, trustFromBundle, verifyReceipt } from "@auths-dev/sdk/verify";
import { readFile } from "node:fs/promises";

const trust = trustFromBundle(await readFile("./trust-bundle.cbor"));
const receipt = decodeReceipt(await readFile("./receipt.cbor"));
const result = await verifyReceipt(receipt, trust);

if (result.passed) console.log("verified", result.principal, result.profileId);
else console.error(result.kind, result.stage, result.code, result.reason);
```

```python
from auths.verify import decode_receipt, trust_from_bundle, verify_receipt

trust = trust_from_bundle(open("trust-bundle.cbor", "rb").read())
result = await verify_receipt(decode_receipt(open("receipt.cbor", "rb").read()), trust)
print(result.passed, result.kind, result.stage)
```

The trust anchor is named at the call site. Under the current API, a caller who verifies through the remote client is asking the receipt's own issuer whether the receipt is good — see §13.3.

### 4.5 Workflow E — authenticate a signed message (identity, no capability)

**Before (`bindings/recipes/typescript/01-authenticate-identity.ts`, 40 lines, 12 API calls across 3 objects):**

```ts
const identity = await loadIdentity();
const method   = await loadRawKeyIdentityAdapter();
const suite    = await loadEd25519RawKeyAuthentication();
const sent     = method.create("ed25519-v1", publicKey);
const received = identity.parseIdentity(identity.decodePublicIdentity(sent.packet), method);
const preimage = identity.signingPreimage(received, message);
const signingBytes = new Uint8Array(preimage.length); signingBytes.set(preimage);
const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", keys.privateKey, signingBytes.buffer));
const authenticated = identity.authenticate(
  identity.decodeSignedMessage(identity.encodeSignedMessage(received, message, signature)),
  received, suite);
```

The Python recipe of the same name (`bindings/recipes/python/01_authenticate_identity.py`) uses `IdentityRegistry`, `VerificationRelationship`, `VerificationMaterial`, `encode_identity`, `decode_identity` — **it shares no API call with the TypeScript version.**

**After (both languages, 4 calls, identical shape):**

```ts
import { authenticate, decodeIdentity, signingPreimage } from "@auths-dev/sdk/identity";

const identity = decodeIdentity(packet);
if (identity === undefined) throw new Error("malformed identity packet");

const signature = await sign(signingPreimage(identity, message));   // your key, your signer
const result = await authenticate({ identity, message, signature });
if (result === undefined) throw new Error("signature did not verify");
console.log(result.identity.principal);
```

```python
from auths.identity import authenticate, decode_identity, signing_preimage

identity = decode_identity(packet)
if identity is None:
    raise ValueError("malformed identity packet")

signature = await sign(signing_preimage(identity, message))
result = await authenticate(identity=identity, message=message, signature=signature)
if result is None:
    raise ValueError("signature did not verify")
print(result.identity.principal)
```

The adapter and suite indirections are internalized. Today they let a caller-supplied `SignatureSuiteAdapter` decide whether a signature verified while the type is named `AuthenticatedIdentityMessage`; the SDK performs structural re-comparison to bound the damage but "the entire proof is delegated to a caller-supplied adapter that the SDK cannot attest." The new `authenticate` does the cryptography itself.

### 4.6 Workflow F — production configuration (development vs production, side by side)

**Development** — every non-durable property is reported, never silently defaulted:

```ts
await using auths = await connect(local({ profile: reports, authority: reports.allowTools([...]) }));
console.log(auths.runtime.mode);      // "development"
console.log(auths.runtime.warnings);
// [ "signer=ephemeral-ed25519", "state=in-memory-not-production-durable",
//   "receipts=in-memory-not-production-durable", "approval=none" ]
```

**Production** — the same function, with the contracts supplied:

```ts
import { connect, local, type ReservationStore, type Signer } from "@auths-dev/sdk";
import { KmsSigner } from "./kms-signer.js";              // implements Signer
import { PostgresReservations } from "./pg-store.js";      // implements ReservationStore
import { S3Receipts } from "./s3-receipts.js";             // implements ReceiptStore

await using auths = await connect(local({
  profile: reports,
  authority: reports.allowTools(["publish_report"]),
  signer:   new KmsSigner({ keyId: process.env.AUTHS_SIGNING_KEY_ID! }),
  store:    new PostgresReservations(pool),
  receipts: new S3Receipts({ bucket: process.env.AUTHS_RECEIPT_BUCKET! }),
  approval: await approval.threshold({ policyId: "reports.two-person", threshold: 2, approvers }),
}));

if (auths.runtime.mode !== "production") {
  throw new Error(`refusing to start: ${auths.runtime.warnings.join(", ")}`);
}
```

`runtime.mode` is **derived**, not declared: it is `"production"` only when `signer`, `store` and `receipts` were all supplied and none is a testkit fixture. That guard is three lines a service can put in its startup path, and it is the check the current `production.createAuths` was supposed to provide and never could (§1.3).

Before any of this, prove the adapters:

```ts
import { certifyReservationStore, certifySigner } from "@auths-dev/sdk/testkit";

test("custody and durability adapters are conformant", async () => {
  assert.ok((await certifySigner(() => new KmsSigner({ keyId: TEST_KEY }))).ok);
  assert.ok((await certifyReservationStore(() => new PostgresReservations(testPool))).ok);
});
```

---

## 5. Disposition of every current public export

Legend: **keep** (name and meaning survive) · **rename** · **move** · **merge** · **split** · **internalize** (stays in the codebase, leaves the published surface) · **remove** (deleted from the codebase).

Per `AGENTS.md`, every disposition is a direct source cutover: no alias, no shim, no deprecation window.

All 267 distinct export names across both snapshots are dispositioned below. Tables are written in the TypeScript spelling; each row applies to its snake_case Python twin (`createAuths` ⇒ `create_auths`, `verifyReceipt` ⇒ `verify_receipt`, …). §5.9 covers only the symbols that exist in **one** language.

### 5.1 TypeScript `.` — 34 symbols

| Symbol | Disposition | Replacement / rationale |
|---|---|---|
| `Actor` | **rename** | → `Identity`. `Actor` is a sixth noun for one of the five (`{principal: string}`). |
| `approval` | **keep** | Namespace value; members typed (`ApprovalPolicy`, `Approver`, `ApprovalRequest` now exported). |
| `ApprovalPolicy` | **keep** | Now actually usable: `Approver`/`ApprovalRequest`/`Approval` join it on the public surface. §1.5 |
| `Authority` | **keep** | Ceases to be `= McpToolAuthority`; becomes `Authority<P>`, minted by a profile. §1.2 |
| `Auths` | **keep** | Becomes `Auths<P>`, profile-generic, no longer MCP-only. |
| `AuthsConfiguration` | **remove** | A nominal capability token disguised as a structural interface; its payload lived in a `WeakMap`. Replaced by `Runtime<P>` from `local()`/`remote()`. §1.3 |
| `AuthsError` | **keep** | Becomes the *only* exception class, and gains `next`, `stage`, `reference`. §1.8 |
| `AuthsErrorCode` | **keep** | Registry-derived union in both languages (today `= str` in Python). |
| `AuthsErrorDetails` | **internalize** | Zero usages; every field is now on the outcome. |
| `CauseCategory` | **internalize** | Zero usages. |
| `classifyErrorCode` | **internalize** | Every result already carries `effect`/`retry`/`next`/`recommendedAction`; a caller never classifies a code itself. |
| `CodeClassification` | **internalize** | With `classifyErrorCode`. |
| `Completed` | **keep** | Becomes `Completed<R>` with typed `value`. |
| `createAuths` | **rename** | → `connect(runtime)`. Frees the verb `create`, which today means three things; and the current function is unreachable. §1.3, §13.4 |
| `Denied` | **keep** | Gains `reason` (the kernel diagnostic TypeScript discards today) and all four axes. |
| `doctor` | **keep** | |
| `DoctorMode` / `DoctorOptions` / `DoctorState` | **merge** | → `DoctorReport` (`ok`, `warnings`, `facts`, `toString`). Four types for one report; none exists in Python. |
| `DoctorReport` | **keep** | |
| `EffectState` | **keep** | |
| `EnteredBoundaries` | **internalize** | Zero usages; the two bindings fabricate *opposite* values on the unknown-code path. |
| `ErrorFamily` | **internalize** | A disjoint 6-member set overlapping Rust's 7 by two, derived from string suffixes. |
| `ExecutionReference` | **rename** | → `Reference` + `decodeReference`. Drops the MCP-only `/^mcp1\./` regex; the sealed handle and `toJSON(): never` survive. |
| `ExecutionResult` | **rename** | → `Outcome<R>`. The current type is returned by nothing; the real return types are private. §1.12 |
| `Indeterminate` | **split** | → `Indeterminate` (no reference) + `Recoverable` (reference required), mirroring Rust's `ClientOutcomeKind`. §7.1 |
| `isProductVerb` | **internalize** | Zero usages. |
| `Outcome` | **rename** | The base interface becomes the union name; the axes are inlined on each variant. |
| `ProductStage` | **keep** | Now carried on every non-success result and on `AuthsError`. |
| `ProductVerb` | **keep** | Wire verb set, unchanged: `create\|delegate\|execute\|resume\|verify`. |
| `Receipt` | **keep** | |
| `RecommendedAction` | **keep** | |
| `RecoveryResult` | **merge** | Its four `kind` values mixed effect state with replay disposition. → `Recoverable` + the `effect` axis. |
| `RetryClass` | **keep** | |

**New at root:** `connect`, `local`, `remote`, `Runtime`, `Identity`, `Action`, `Plan`, `Profile`, `Scope`, `RuntimeFacts`, `ExecuteOptions`, `Grant`, `Delegation`, `Recoverable`, `Reference`, `decodeReference`, `Approval`, `Approver`, `ApprovalRequest`, `Signer`, `SigningRequest`, `SigningResponse`, `SigningObjectKind`, `ReservationStore`, `ReservationRecord`, `ReceiptStore`, `Observer`, `CheckpointEvent`.

### 5.2 TypeScript `./identity` — 15 symbols

| Symbols | Disposition | Rationale |
|---|---|---|
| `loadIdentity`, `IdentityClient`, `loadRawKeyIdentityAdapter`, `RawKeyIdentityAdapter`, `loadEd25519RawKeyAuthentication`, `Ed25519RawKeyAuthentication` | **merge** | → `decodeIdentity` / `signingPreimage` / `authenticate`. Three loaders and three objects for one operation. §4.5 |
| `IdentityMethodAdapter`, `IdentityMethodParse`, `SignatureSuiteAdapter`, `SignatureSuiteParse` | **internalize** | Caller-supplied adapters decide whether a signature verified while the SDK cannot attest them; both `parse` methods are synchronous, structurally excluding every async signature backend. |
| `DecodedIdentity`, `ValidatedIdentity` | **merge** | → `Identity`. Both are `Object.freeze`d wrappers around **mutable** `Uint8Array`s that `signingPreimage` re-reads at call time. |
| `AuthenticatedIdentityMessage`, `DecodedSignedIdentityMessage` | **merge** | → `AuthenticatedMessage`. |
| `IdentityPrincipal` | **merge** | → `Identity.principal`. |

**New:** `decodeIdentity`, `encodeIdentity`, `signingPreimage`, `authenticate`, `Identity`, `AuthenticatedMessage`.

### 5.3 TypeScript `./verify` — 37 symbols

| Symbols | Disposition | Rationale |
|---|---|---|
| `loadVerifier`, `Verifier` | **merge** | → `verifyProof` / `verifyProofs`. The object exists only to hold a lazily-loaded engine, which is a module concern. Removes the TS/Python asymmetry (Python has no verifier object). |
| `VerificationInput` | **rename** | → a named record. Three same-typed positional `Uint8Array`s type-check when transposed. §3.3 |
| `AuthorizedResult`, `DeniedResult`, `IndeterminateResult` | **rename** | → `Verified`, `Rejected`, `Unproven`. Third vocabulary for the same three outcomes. §1.6 |
| `VerificationResult` | **rename** | → `Verification`. |
| `VerdictKind` | **merge** | → the `kind` discriminant. |
| `VerificationStage` | **keep** | |
| `VerifiedAction` | **internalize** | A sealed capability the caller cannot use for anything; Python's `AuthorizedResult` already discards it. |
| `VerificationOptions`, `VerificationBatchOptions` | **remove** | Both are typed against `TelemetryPort`, which is exported from no entry point. |
| `VerificationMetrics` | **internalize** | |
| `Explanation`, `inspectDecision`, `DecisionInspection` | **remove** | `Explanation.message` is hardcoded English chosen by verdict kind alone and never varies with the code; `retryable: true` for every indeterminate is a fourth retry vocabulary. |
| `ImmutableArtifactCache`, `ImmutableArtifactCacheOptions` | **internalize** | Caching is the module's business; no Python counterpart. |
| `verifyReceipt` | **keep** | Gains a required `trust` argument. §13.3 |
| `encodeReceipt`, `decodeReceipt` | **keep** | And the duplicate unreachable copies in `product.ts:371-381` are deleted. |
| `inspectReceipt`, `ReceiptInspectionResult`, `ReceiptInspectionCommitments`, `ReceiptInspectionMetadata`, `ReceiptInspectionProfile`, `ReceiptInspectionSigner`, `ReceiptSummary`, `ReceiptSummaryField`, `ReceiptViewMode`, `VerifiedOpaqueReceipt`, `VerifiedDisclosedReceipt`, `InvalidReceiptInspection` | **move** | → `demos/github-issue/web/`. This is receipt *rendering*: view modes, summary fields, display metadata. Zero usages in either language. It is the demo's receipt page, not the SDK's. |
| `createReceiptDisclosure`, `ReceiptDisclosureMaterial`, `ReceiptDisclosureProtector`, `ReceiptDisclosureStore` | **remove** | Exported public interfaces that nothing in the SDK accepts, calls, or implements. Reintroduce with a worked example if selective disclosure ships. |

**New:** `Trust`, `trustFromRawKey`, `trustFromBundle`, `verifyProof`, `verifyProofs`, `Verification`, `Verified`, `Rejected`, `Unproven`.

### 5.4 TypeScript `./service` — 38 symbols — **entry point removed**

| Symbols | Disposition | Rationale |
|---|---|---|
| `createServiceClient`, `ServiceClient`, `ServiceClientOptions` | **merge** | → `connect(remote({...}))`. Remote is a runtime, not a second product. §1.1 |
| `ServiceCompleted`, `ServiceDenied`, `ServiceIndeterminate`, `ServiceRecoverable`, `ServiceExecutionResult` | **merge** | → the one `Outcome`. Fifth result vocabulary. |
| `ServiceVerified`, `ServiceRejected`, `ServiceVerificationResult` | **merge** | → `Verification` in `./verify`. |
| `ServiceAuthority`, `ServiceAuthorityResult` | **merge** | → `Authority<P>`; `create`/`delegate` no longer mint it (§1.4). |
| `importAuthority` | **merge** | → `profile.authority(proofBytes)`, which binds the proof to a profile at the type level. |
| `ServiceReceipt` | **merge** | → `Receipt`. Today it is a dead end: opaque, `toJSON()` throws, and the only consumer returns nothing useful. |
| `ServiceRecoveryReference` | **merge** | → `Reference`. |
| `ServiceProfile`, `ServiceProfileId` | **merge** | → `Profile`. Also removes a dual-export: both are published from `./service` **and** `./profiles`. |
| `githubIssueAddress`, `opentofuSavedPlanApply`, `postgresqlBoundedUpdate` | **move** + **rename** | → `github.issueAddress()`, `opentofu.savedPlanApply()`, `postgresql.boundedUpdate()` in `./profiles`, declared once. Six public rows for three functions today. |
| `ServiceTransport`, `ServiceTransportRequest`, `ServiceTransportResponse` | **remove** | A byte-level transport port with no Python counterpart and a 1000× unit divergence. Testing seam becomes `remote({fetch})`, which Python gains as an injectable transport it lacks today. |
| `TransportFailure` | **internalize** | The closed 7-member classification stays; it is Rust's input, not the caller's. |
| `NextCall` | **move** | → root, carried on every non-success outcome. Requires amending `test_vocabulary_parity.py:58`. §12 |
| `createGitHubAgentClient`, `GitHubAgentClient`, `GitHubAgentClientOptions`, `GitHubAgentBoundary`, `GitHubAgentTask`, `GitHubAgentSession`, `GitHubAgentOutcome`, `GitHubCandidateFile`, `GitHubCandidateInspection`, `GitHubVerifiedReceipts`, `GitHubDenialFixture`, `GitHubAgentError` | **remove** | A JSON client for `/v1/demo/*` routes shipped in the production SDK, whose `execute`/`replay`/`reconcile` swallow every error into a fixed indeterminate (§1.9). Replaced by `github.issueAddress()` + `remote()`. `GitHubDenialFixture` moves to `./testkit`. |

### 5.5 TypeScript `./profiles` — 35 symbols

| Symbols | Disposition | Rationale |
|---|---|---|
| `mcp` | **keep** | `mcp.tools(service, handlers)` replaces `developmentProvider`/`allowTools`/`callTool`/`plan`. |
| `McpProfile`, `McpProfileOptions` | **rename** | → `McpProfile<T>` typed by the tool map. |
| `McpToolAuthority`, `McpAuthority` | **merge** | → `Authority<McpProfile<T>>`, minted by `profile.allowTools`. |
| `McpAction`, `McpCommand` | **merge** | → `Action<R>`, minted by `profile.call`. |
| `McpToolHandler`, `McpToolContext` | **rename** | → `ToolMap` entry + `ToolContext`. |
| `McpClosedProvider`, `McpDevelopmentProviderOptions` | **merge** | → the `handlers` argument of `mcp.tools`. The provider stops being a per-call argument. §7.5 |
| `McpClosedResult`, `McpPlanClosedResult` | **merge** | → `Outcome<R>`. Anonymous inline variants a caller cannot name. |
| `executeMcpClosed`, `executeMcpPlanClosed`, `resumeMcpClosed` | **internalize** | Exported but uncallable: four of their parameter types are unexported. No Python counterpart. |
| `resourcesForMcpAuthority` | **internalize** | |
| `McpExecutionState`, `McpReceiptSink` | **merge** | → `ReservationStore` / `ReceiptStore` at root — the contracts `local()` actually accepts. Resolves §1.5: `AtomicReservationStore` had no consumer because the real port was this one. |
| `McpRecoveryCheckpoint` | **rename** | → `ReservationRecord`. |
| `McpExecutionObserver`, `McpExecutionCheckpointEvent`, `McpExecutionCheckpointStage` | **rename** | → `Observer`, `CheckpointEvent` at root. |
| `McpExecutionResources` | **internalize** | |
| `McpGateway`, `McpGatewayCall`, `McpGatewayError` | **internalize** | `McpGatewayError` publishes `effect: "not-applied" \| "applied" \| "unknown"` — no `possible`. A non-Rust effect vocabulary on the published surface. |
| `McpHandlerOutcome`, `McpHandlerCause` | **rename** | → the handler's return type plus `Outcome`'s axes. Today `isMcpOutcome` duck-types a provider payload's `effect` property while Python uses `isinstance` — same handler, opposite recorded effect. |
| `McpReceipt` | **merge** | → `Receipt`. Its `outcome` field is a fifth effect spelling. |
| `githubIssueAddress`, `opentofuSavedPlanApply`, `postgresqlBoundedUpdate`, `ServiceProfile`, `ServiceProfileId` | **rename** | → `github`/`opentofu`/`postgresql` namespaces + `Profile`, declared once (they are dual-exported today). |

**New:** `ToolMap`, `ToolContext`, `McpProfile`, `mcp`, `RemoteProfile`, `github`, `opentofu`, `postgresql`, and the six request/result interfaces.

### 5.6 TypeScript `./integrations` — 4 symbols — **entry point removed**

| Symbol | Disposition | Rationale |
|---|---|---|
| `development` | **rename** + **move** | → `local()` at root. `development` names a trust *maturity*; the axis that matters at construction is *who performs the effect*. Maturity is now derived from which contracts you supplied and reported in `runtime.mode`. |
| `production` | **remove** | Unreachable in both languages (§1.3). Its intent is served by `local()` with real contracts plus the `runtime.mode !== "production"` guard (§4.6). |
| `DevelopmentAuthsOptions` | **rename** | → the inline options of `local()`. |
| `RecoverableAuthsOptions` | **remove** | `development.createRecoverableAuths({directory})` becomes `local({store: fileStore(dir), receipts: fileReceipts(dir)})` — the durability decision stops being a second factory and becomes the field it always was. |

Python-only extras: `exchange_identity`, `IdentityTransport`, `FrameworkAdapter` — **remove**. No TypeScript counterpart, no worked example, and the conformance catalog already records `generic-framework-adapter` disposition as *delete*.

### 5.7 TypeScript `./framework` — 11 symbols — **entry point removed**

All eleven **move to root**, because they are the named fields of `local()`:

| Symbol | Disposition |
|---|---|
| `Signer`, `SigningRequest`, `SigningResponse`, `SigningObjectKind` | **move** to root. `Signer.close()` becomes required in both languages (today: optional in TS, required in Python — §1.10). |
| `AtomicReservationStore`, `AtomicReservationRecord` | **rename** + **move** → `ReservationStore`, `ReservationRecord` at root, reconciled with the 6-method `McpExecutionState` the runtime actually calls. This is the fix for "a published contract no public API accepts" (§1.5). |
| `SignerLifecycle` | **internalize** |
| `ControlEvidence`, `PrincipalDescriptor` | **internalize** | Zero usages. |
| `ProviderFailureKind`, `ProviderOperationError` | **remove** | A second error class minting retry/effect pairs the registry's own validator forbids. Provider failure becomes the handler's return value plus the registry code. §7.2 |

### 5.8 TypeScript `./testkit` — 29 symbols

| Symbols | Disposition | Rationale |
|---|---|---|
| `certifySigner`, `certifyAtomicStore` | **keep** / **rename** | → `certifySigner`, `certifyReservationStore`. Factory-taking harness pattern kept — Auths owns the assertions, not the adapter author. Fix `atomic-store/isolated-instances`, which today cannot be passed by a genuinely durable shared-backend store. |
| `certifyMcpProvider` | **remove** | The provider is now the tool map; its contract is the tool signature. |
| `certifyByteTransport`, `ByteTransportCandidate`, `ByteTransportFactory` | **remove** | With `ServiceTransport`. |
| `fixtures` | **keep** | Gains `reservationStore`, `receiptStore`, `approver`, `observer`, `trust`. `fixtures.ephemeralSigner()` must stop failing 3 of 8 of `certifySigner`'s own cases. |
| `CONFORMANCE_CATALOG`, `ConformanceMetadata`, `ConformanceCaseResult`, `MechanismConformanceReport`, `CustodyConformanceReport`, `CustodyConformanceResult`, `ProductWaistConformanceReport` | **merge** | → `ConformanceReport` + `ConformanceCase`. Seven report shapes for one answer. |
| `custodyConformance`, `CustodyConformanceCase`, `CustodyConformanceOptions`, `productWaistConformance`, `ProductWaistConformanceCase`, `ProductWaistExpected` | **internalize** | Repository conformance drivers, not consumer API. `ProductWaistExpected.code` is even named `expected` in the wire manifest, forcing every caller to hand-translate. |
| `createDiagnosticVerifier`, `DiagnosticVerifier`, `DiagnosticResult` | **internalize** | |
| `BoundedApprovalSession`, `BoundedApprovalSessionOptions` | **remove** | |
| `InMemoryApplicationExecutionStore` | **rename** | → `fixtures.reservationStore()`. |
| `AtomicReservationRecord`, `AtomicReservationStoreCandidate`, `McpProviderFactory` | **remove** | The candidate types are the real contracts; a separate candidate type let `McpProviderFactory` declare a handler signature omitting the `AbortSignal` the real handler has. |
| `ADAPTER_CONTRACT_VERSION` (Python) | **merge** | → `ConformanceReport.suiteVersion`. |

**New:** `ConformanceReport`, `ConformanceCase`, `Clock`, `certifyReceiptStore`, `certifyApprover`, `GitHubDenialFixture` (moved from `./service`).

### 5.9 Python-only symbols

| Symbols | Disposition | Rationale |
|---|---|---|
| `PlanCompleted`, `PlanRecoveryResult`, `McpPlan`, `McpPlanCompleted`, `McpPlanRecoveryResult`, `McpCompleted`, `McpRecoverable` | **merge** | → `Outcome[R]`. `PlanCompleted.kind` and `Completed.kind` are both `Literal["completed"]`, which is why the Python success path does not type-check (§1.12). |
| `IdentityRegistry`, `IdentityResolver`, `ResolverIdentityMethod`, `ResolutionEvidence`, `ResolvedIdentity`, `ResolvedIdentityRecord`, `RawKeyIdentityMethod`, `IdentityMethod`, `SignatureSuite`, `Ed25519SignatureSuite`, `VerificationMaterial`, `VerificationRelationship`, `encode_raw_key_identity`, `AuthenticatedIdentity` | **internalize** / **merge** | The Python-only identity tier. `SignatureSuite.verify` and `IdentityMethod.validate` are declared `-> None` and signal failure only by raising — an implementation returning a falsy value on a bad signature silently authenticates it. `ResolverIdentityMethod.validate` can never fail and nothing compares `ResolutionEvidence.expires_at` to a clock. → the six shared `auths.identity` symbols. |
| `decode_identity`, `encode_identity` | **keep** | Python-only today; **TypeScript gains both** as `decodeIdentity`/`encodeIdentity`. `decode_identity` currently returns an object whose every subsequent method raises bare `ValueError`/`TimeoutError` outside the error model; the new `decodeIdentity` returns `Identity \| undefined` and fails closed. |
| `verify`, `verify_many` | **rename** | → `verify_proof`, `verify_proofs` (named-record input). |
| `ApprovalInspection`, `DecisionCommitments`, `DecisionSummary`, `KernelSummary`, `inspect_decision` | **remove** | With the TypeScript inspection surface. |
| `auths.service` re-exports of `AuthsError`, `AuthsErrorCode`, `EffectState`, `ProductVerb`, `RecommendedAction`, `RetryClass` | **remove** | Six symbols re-exported from the root into a module that ceases to exist. TypeScript never did this. |
| `check_approval_provider`, `check_identity_method`, `check_signer`, `check_telemetry` | **merge** | → the `certify_*` family. Python carries both spellings today. |
| `DevelopmentApproval`, `DevelopmentEd25519Signer`, `DevelopmentIdentityMethod`, `DevelopmentReceiptAttestor`, `DevelopmentSignatureSuite`, `DevelopmentSigner`, `MemoryGateway`, `RecordingTelemetry`, `FixedClock`, `DiagnosticEngine`, `DiagnosticExplanation` | **merge** | → the `fixtures` namespace, matching TypeScript. |
| `DevelopmentMcpProvider` | **merge** | → the `handlers` argument of `mcp.tools`. |
| `ConformanceReport` | **keep** | TypeScript gains it. |

### 5.10 Surface not covered by either snapshot — a gate gap to close

Both generators enumerate module-level exports only (`public-api.mjs:55` walks `getExportsOfModule`; `check_public_api.py:22` reads `__all__`). Four categories of real public surface are invisible to them, and **removing `approval.planOnce` today produces no line change in `public-api.txt`**:

1. Members of exported namespace objects (`approval` ×8, `fixtures` ×5, `mcp.*`, `development.*`, `production.*`).
2. The installed CLIs: the npm `bin` (`auths`) and `python -m auths doctor`. Neither generator reads `bin` or `__main__`.
3. Raw WASM shipped in the npm `files` array (20 ABI exports) with no `exports` subpath.
4. Two separately published adapter distributions with their own versions and no snapshot: `auths-sqlite` and `@auths-dev/runtime-json-store`. The latter implements a port name (`ExecutionStatePort`) that appears in neither binding.

**Disposition:** extend both generators to walk one level into exported namespace objects and to record `bin`/`__main__`; add the two adapter packages to the topology as published coordinates or unpublish them. §11.4.

---

## 6. Deliberate similarities and differences

### 6.1 Same, and gated (§11.2)

Entry-point set · symbol set after case normalization · result and verification variant names and their `kind` strings · field names on every public type · the four Rust-owned axes and their closed value sets · stable error codes · `ok`/`passed` discriminants · profile ids and versions · every numeric limit (byte bounds, batch bounds, timeout bounds, expiry bounds) · which operations are async · disposal semantics · the set of methods on every port.

### 6.2 Deliberately different (idiom)

| Concern | TypeScript | Python | Why |
|---|---|---|---|
| Disposal | `await using` / `Symbol.asyncDispose` / `close()` | `async with` / `aclose()` | Native idiom in each. Today there are **four** disposal spellings across the two bindings with no shared vocabulary. |
| Result shape | discriminated union of `interface` | frozen dataclasses + `Literal` + `match` | Structural vs nominal. |
| Options | one `Readonly<{...}>` object | keyword-only arguments | `local(*, profile, authority, …)` reads wrong as a dict in Python. |
| Ports | `interface` (structural) | `Protocol` (structural, `@runtime_checkable` where a runtime check is load-bearing) | |
| Collections | `readonly T[]` | `tuple[T, ...]` | Immutability by convention vs by construction. |
| Client generic | `Auths<P extends Profile>` | `Auths` (non-generic); the type variable lives on `Action[R]` | **§6.3.** |
| Truthiness guard | the `ok` literal narrows; `if (outcome)` does not compile | `__bool__` raises `TypeError` | TypeScript's checker rejects the shortcut statically; Python's cannot, so a runtime backstop is added. It is a backstop, not the mechanism — the mechanism in both languages is that `value` exists only on `Completed`. |
| Namespaces | `const mcp = {...}` frozen object | module-level functions in `auths.profiles.mcp` | |
| Timeout unit | `timeoutMs` | `timeout_ms` | Deliberately **not** idiomatic Python seconds. Today `timeoutMs` (int ms) vs `timeout_seconds` (float s) makes a ported adapter wrong by 1000×. The unit is in the name in both languages. |

### 6.3 The one asymmetry that is not cosmetic

`Auths` is generic in TypeScript and not in Python. Verified with `mypy --strict --python-version 3.9`:

```
error: Argument 1 to "takes_base" has incompatible type "Auths[McpProfile]"; expected "Auths[Profile]" [arg-type]
```

`Auths[P]` is invariant, and covariance is illegal because `P` appears contravariantly in `execute(self, action: Action[P])`. So the first helper anyone writes — `async def audit(clients: list[Auths[Profile]])`, or a `@pytest.fixture` returning `Auths[Profile]` — cannot type-check, and the only escape is `Auths[Any]`, which deletes the typing the generic existed to provide. TypeScript's structural, bivariant method parameters have no such problem.

**Resolution:** put the type variable on the *action*, which is where the result actually comes from. `Auths` is non-generic in Python; `execute(action: Action[R]) -> Outcome[R]` still gives `reveal_type(outcome.value) == IssueCreated`. TypeScript keeps `Auths<P>` because it costs nothing there and gives cross-profile mismatch a good error message. **Both languages type the result off the action**; only the client's own arity differs. This is recorded as an accepted exception in the parity gate's exception list (§11.2).

### 6.4 A Python floor change is required

`match` statements are 3.10+. So are `dataclass(slots=True)`, `dataclass(kw_only=True)`, runtime `A | B` aliases, `typing.TypeAlias` and `typing.Self` — and `mypy --strict --python-version 3.9` flags **none** of them, because they are runtime `TypeError`/`ImportError`, not type errors. `pyproject.toml` declares no `dependencies`, so there is no `typing_extensions` fallback. Today the package would import fine on the maintainer's 3.12 and explode on the declared floor.

**Change `requires-python` to `>=3.10`** and update `bindings/python/tools/check_wheel.py:142,146`, the classifiers, and the CI matrix in `.github/workflows/python-sdk.yml:151`. The `abi3-py39` tag is an ABI tag and does not force the *language* floor. Python 3.9 reached end of life in October 2025. Add `[tool.mypy] python_version = "3.10"` so the floor is bound mechanically rather than by review.

---

## 7. Conventions

### 7.1 Results: `kind` says which fields exist; four axes say what to do

`Outcome` has exactly four kinds, and they are **Rust's own `ClientOutcomeKind` minus the two verification kinds** (`product/runtime/auths-production-client/src/lib.rs:390-399`). The binding invents nothing.

| `kind` | `ok` | Extra fields | Rust arm and its validated shape (`lib.rs:620-650`) |
|---|---|---|---|
| `completed` | `true` | `value`, `receipt`, `executionId` | `Completed`: `code.is_none() && recovery_reference.is_none() && receipt.is_some() && retry == Never` |
| `denied` | `false` | `reason` | `Denied`: `code.is_some() && recovery_reference.is_none() && retry == Never` |
| `indeterminate` | `false` | `reason` | `Indeterminate`: `code.is_some() && recovery_reference.is_none() && retry ∈ {Backoff, Reconcile}` |
| `recoverable` | `false` | `reference`, `executionId` | `Recoverable`: `code.is_some() && recovery_reference.is_some() && retry == Resume` |

`kind` is a **total** discriminant: `switch (outcome.kind)` reaches `outcome.reference` under `case "recoverable"` with no second narrowing, and `default: const _: never = outcome` proves exhaustiveness. That is not true of any current union.

**No axis is ever a literal type.** `code`, `effect`, `retry`, `next`, `recommendedAction` and `stage` carry their full Rust-owned enum on every non-success variant, populated from `classifyErrorCode(code)`. Three verified reasons:

1. `auths_errors::classify` returns `effect: Possible, retry: Unknown` for a code this build does not know (`product/errors/auths-errors/src/lib.rs:310-318`). Baking `effect: "not-applied"` into `Denied` would make a newer node's possible-effect code arrive as "nothing happened, safe to abandon" — the exact fail-open this product exists to prevent.
2. Ten of the 48 registry codes have `effect: "not-applied"` with `retry != "never"` (`custody.throttled`, `custody.unavailable`, `core.runtime-unavailable`, …). `if (outcome.kind === "denied" && outcome.retry === "never") giveUp()` would abandon a throttled custody call that is explicitly retryable.
3. `mcp.receipt-persist-failed` is the registry's one `effect: "applied"` **failure** — the irreversible thing happened and the proof was lost. With full axes it is representable as a `recoverable` carrying `effect: "applied"`; with literal axes it fits nothing and falls off the type.

`Verification` is the same discipline over Rust's `Verified | Rejected` plus an `Unproven` arm, with `passed` as the literal gate.

### 7.2 Errors: denials are results, exceptions are for "there is no outcome"

`AuthsError` is thrown for exactly three situations:

1. **Invalid configuration** — bad endpoint, out-of-range timeout, a profile/authority mismatch, a missing required contract. Detected in `local()`/`remote()`/`connect()`, before any I/O.
2. **Engine unavailable** — WASM or the native extension failed to load. Today this is a raw platform error because the boundary guard is installed only *after* a successful load, so the most likely first-run failure is the one failure the error model does not cover.
3. **Use after close** — a `TypeError`/`ValueError` today; becomes `AuthsError` with `core.session-closed`.

Everything else — every denial, every indeterminate, every transport failure, every provider fault — is a value. Deleted: `AuthsWorkflowError` (177 throw sites, unexported, 36 unregistered codes), `GitHubAgentError`, `ProviderOperationError`, `McpGatewayError`.

Argument-contract violations stay `TypeError`/`ValueError` and are **never** relabelled as an authorization outcome — the existing rule at `internal/wasm-boundary.ts:26-31` and `_boundary.py:11-12`, preserved verbatim.

**A bare catch that converts an unknown failure into a fixed outcome is forbidden.** §1.9's `catch { return indeterminate }` has no successor: transport failures are classified into the closed 7-member `TransportFailure` and handed to Rust to interpret; anything else propagates.

### 7.3 Lifecycle and disposal

`Auths` owns: the native/WASM session, ephemeral key material it minted, and every child produced by `delegate`. It does **not** own a `Signer`, `ReservationStore`, `ReceiptStore` or `Observer` you supplied — those are yours, and `close()` does not close them. That ownership rule is stated once and holds in both languages.

- `close()` / `aclose()` is idempotent, closes children first, then releases owned resources, and zeroizes owned key material.
- TypeScript: `await using` (requires `lib: ["ESNext.Disposable"]`, which the packed-consumer type test already sets) or `try/finally`.
- Python: `async with await connect(...)` or explicit `await auths.aclose()`.
- After close, every method rejects with `AuthsError(core.session-closed)`. Today post-disposal misuse raises three incompatible error types, two of them outside the product error model.
- A delegated child closes when its parent closes; closing a child does not close its parent.

### 7.4 Async

**Every operation that can touch the engine, the network, the filesystem, or a caller-supplied port is async in both languages.** That is `connect`, `execute`, `executePlan`, `delegate`, `resume`, `close`, `doctor`, `authenticate`, `verifyProof`, `verifyProofs`, `verifyReceipt`, and every `certify*`.

Everything else is sync in both: `local`, `remote`, `decodeIdentity`, `encodeIdentity`, `signingPreimage`, `encodeReceipt`, `decodeReceipt`, `decodeReference`, `trustFromRawKey`, `trustFromBundle`, and every profile mint (`mcp.tools`, `profile.call`, `profile.allowTools`, `profile.plan`).

This replaces a rule that is stated and broken: TypeScript's `doctor`, `inspectReceipt`, `verifyReceipt` and `createReceiptDisclosure` are async while every Python equivalent is sync, so no code sample and no conformance test transfers between the languages. `doctor` is async in Python here even though the native extension loads at import — parity beats a microscopic ceremony cost, and it keeps the door open for a doctor that probes a remote endpoint.

**No dual-protocol object.** `connect` is a plain async function; `Auths` is the context manager. The alternative — an object that is both awaitable and an async context manager — is what the repository ships today (`integrations.py:278-301`, `class _PendingAuths(Awaitable[Auths])`), and a forgotten `await` on it is a **silent no-op**: no exception, no warning, execution continues on a handle object. A plain coroutine emits `RuntimeWarning: coroutine was never awaited`. In a security SDK, the setup step that loads the signer and the trust anchor must keep its runtime tripwire.

### 7.5 Concurrency and cancellation

- One `Auths` handle is safe to use concurrently. Exactly-once is enforced by `ReservationStore.reserve`, not by client-side serialization; `requestId` is the idempotency key and omitting it means a retry is a second effect. This is documented on `ExecuteOptions.requestId` in both languages.
- The engine is loaded once per process behind a memo that **does not cache rejections**. Today both TypeScript loaders memoize failures permanently with no reset, so one transient load error poisons the process. There is also exactly one loader: today `verifier/wasm.ts:8` and `identity.ts:358` each declare their own memo and both call the wasm-bindgen initializer, which has no in-flight deduplication.
- Cancellation is uniform: `ExecuteOptions.signal` (TypeScript) and `asyncio` cancellation (Python) reach the handler as `ToolContext.signal`. A cancellation before provider entry yields `mcp.cancelled-before-entry` (`effect: not-applied`); after entry it yields a `recoverable` outcome. Cancellation never produces a silent partial effect.
- The provider is captured and frozen at `connect()` time — `Object.freeze({profile, service, invoke: fn.bind(…)})` — and the per-call profile/service equality assertion at `product.ts:335-340` runs against the frozen copy on **every** `execute` and `resume`. Moving handlers to construction must not turn a per-call check into a one-time check against a caller-mutable object; a `service` field defined as a getter, or reassigned later by a plugin, would otherwise redirect a payments-scoped authority to an admin service with no error.

---

## 8. Advanced capabilities without a heavier default path

The rule: **advanced capability is reached by supplying an argument, never by importing a different module.** There is no `advanced` namespace (forbidden by `docs/product/sdk-glossary.json` `forbiddenBeginnerTerms` and by `xtask/src/sdk_vocabulary.rs:155-181`).

| Capability | How you reach it | Cost on the default path |
|---|---|---|
| Custody (HSM/KMS) | `local({signer})` — `Signer` is the field's type | one optional field |
| Durable exactly-once state | `local({store})` — `ReservationStore` | one optional field |
| Durable receipts | `local({receipts})` — `ReceiptStore` | one optional field |
| Human approval | `local({approval: await approval.threshold({...})})` | one optional field |
| Telemetry / progress | `local({observer})` | one optional field |
| Remote operator runtime | `connect(remote({...}))` instead of `local` | one function name |
| Test transport injection | `remote({fetch})` | one optional field; **Python gains a seam it lacks today** (its built-wheel consumer proof currently monkeypatches a private method) |
| Ordered plans | `profile.plan([...])` + `executePlan` | only on profiles that mint plans |
| Adapter conformance | `certify*` in `./testkit` | test-time only |
| Offline verification | `./verify` — no `Auths`, no runtime | separate entry point |
| Identity-only | `./identity` — no capability machinery | separate entry point |
| Protocol-level byte verification | `verifyProof({proof, action, context, trust})` | present but demoted below the receipt path in all docs |

**Plans are profile-owned, not a client capability.** `executePlan(plan: Plan<R> & {profileId: P["id"]})` is uncallable for a profile that mints no `Plan`, because there is no value of that type. Today `execute` has two overloads over an implementation with both `action?` and `plan?` optional, and pays for it with a runtime `throw new TypeError("Auths execute requires exactly one action or plan")` — a type-system failure paid for with an exception. Two named methods make the invalid state unrepresentable and delete the throw. `executePlan` reports `verb: "execute"` on the wire; `ProductVerb` is unchanged.

**On the abstraction-boundary plan.** `docs/target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md:125,295,297` prohibits generic runtimes that dispatch effect semantics from an operation tag or accept domain behavior as callbacks. This design is compliant, and the compliance is structural rather than asserted:

- The SDK client is **transport and projection**. Every evaluator, verified command, gateway, credential scope, transition and receipt claim stays in Rust, profile-owned (`plan:148-151`).
- `Auths<P>` never matches on a profile tag to select behavior. The profile mints the action; the action carries its own canonical bytes; the runtime routes on a Rust-owned table.
- Each profile keeps its own denial codes and receipt claims (`plan:104-118`) — they travel in `code`, which is why the axes must not be literals (§7.1).
- Nothing profile-specific is hoisted into a shared evaluator; the shared thing is the *result projection*, whose contract is `auths_errors::classify` and is already Rust-owned and identical across all four profiles.

Per `plan:429-450` this still requires an **abstraction case file** naming `Auths<P>` as the candidate, listing all four profiles as consumers, and stating what remains profile-owned. That is review unit R1 in §12, and a reviewer must be able to reject `Auths<P>` without blocking the rest of the consolidation (`plan:449`).

---

## 9. Documentation and discoverability

### 9.1 The npm/PyPI README, in order

1. **What it is** — two sentences, unchanged from today.
2. **Install** — `npm install @auths-dev/sdk` / `pip install auths`, plus the one-line promise that no Rust toolchain is needed.
3. **The whole thing works in 11 lines** — §4.1 verbatim, executed in CI (§11.3).
4. **What just happened** — the five nouns, one line each, with the negative that prevents the security mistake:
   - Identity — who is acting. *Identity does not grant permission.*
   - Authority — what that identity may do. *Delegation only narrows.*
   - Action — one exact proposal. *An action is inert data.*
   - Receipt — signed evidence. *A receipt cannot be replayed as permission.*
   - Approval — optional confirmation of one transaction. *Approval is not authority.*
5. **Handle every outcome** — the four-arm switch, complete, the first error-handling code in either README's history:

   ```ts
   switch (outcome.kind) {
     case "completed":     return outcome.value;
     case "denied":        throw new Error(`refused: ${outcome.code} — ${outcome.reason}`);
     case "recoverable":   return retryLater(outcome.reference);      // effect: possible
     case "indeterminate": return outcome.next === "reconcile" ? reconcileLater() : backoff();
   }
   ```
6. **Go to production** — §4.6 side by side, with the `runtime.mode !== "production"` guard.
7. **Five entry points** — the table from §2.3.
8. **Check your install** — `npx --package @auths-dev/sdk auths doctor` / `python -m auths doctor`.

Not in the README: protocol bytes, `verifyProof`, plans, delegation, disclosure, conformance. Those live in recipes.

### 9.2 Recipes

Five maintained recipes per language, executed against the **packed artifact** in CI, and each is the *same program* in both languages so a reader can diff them:

| # | Recipe | Entry points |
|---|---|---|
| 01 | Execute one exact action, and watch an undeclared one get denied | `.`, `./profiles` |
| 02 | Delegate narrower authority to an agent, and prove it cannot widen | `.`, `./profiles` |
| 03 | Survive a crash: `recoverable` → `resume`, with no second effect | `.`, `./profiles`, testkit stores |
| 04 | Verify a receipt offline, with no execution runtime | `./verify` |
| 05 | Authenticate a signed message | `./identity` |

Recipe 01 is the README example. Today recipe 01 is the *identity* recipe, is 40 lines, and shares no API call between the two languages (§4.5) — that is why the order changes.

### 9.3 Discoverability fixes that are not code

- The repository `README.md` gains a link to the SDK docs. There is currently no path from the front door to the learn surface.
- `docs/adoption-layers.md` documents `@auths-dev/sdk/authority` and `@auths-dev/sdk/approvals`, which do not exist and which `xtask/src/sdk_experience.rs:384` asserts are `internal-leak`. It also tells readers Python has no identity API. **Delete the subpath table; keep the "does not initialize" column.**
- `docs/product/recipes/06_PRODUCTION_FAILURES.md` calls an API that exists in neither language and branches on `retry` values the local SDK can never emit. Rewrite against §9.1 step 5.
- Three of the ten docs shipped inside the npm tarball instruct readers to use symbols that are not exported. Ship only docs that are snippet-executed (§11.3).
- Every public declaration gets a doc comment stating contract, inputs, outputs, errors, limits and security-relevant behavior, per `AGENTS.md`. At 89 declarations that is achievable; at 203 it was not.

---

## 10. Acceptance criteria

Measured against `bindings/customer-journey-matrix-v1.json`, whose `targetBudgets` exist today and are **compared to nothing** (`xtask/src/sdk_experience.rs:179` only embeds them in a printed report). Flip `experience.enforcement` from `"baseline"` to `"enforced"` and make each row a gate.

| # | Criterion | Today | Target | Gate |
|---|---|---|---|---|
| A1 | TS entry points / Python modules | 8 / 8 | 5 / 5 | `sdk-experience` |
| A2 | TS / Python public symbols | 203 / 180 | ≤ 90 / ≤ 90 | `sdk-experience` |
| A3 | Case-normalized name parity | 62% | 100% minus a reviewed exception list | new parity gate (§11.2) |
| A4 | Public symbols with no test, doc, demo or recipe | 60 / 43 | **0** | new coverage gate (§11.5) |
| A5 | README quickstart: distinct concepts | 18 / 18 | ≤ 6 | `sdk-experience`, counted from the parsed snippet |
| A6 | README quickstart: user-written lines | 26 / 21 | ≤ 12 | same |
| A7 | Both README quickstarts execute against the packed artifact | TS yes / Python **no** | both | `packed-examples`, snippet execution (§11.3) |
| A8 | Distinct result unions a caller may switch on | 8 | 2 | `--shape` inventory |
| A9 | Distinct "what next" vocabularies on public types | 4 | 2 (`RetryClass`, `NextCall`) | vocabulary gate |
| A10 | Exception classes reachable from a public call | 4 | 1 | new gate: every `throw`/`raise` reachable from a public entry is `AuthsError`, `TypeError` or `ValueError` |
| A11 | Public error codes absent from the registry | 36 | 0 | `test_registry_code_inventory` extended to TypeScript |
| A12 | Clean-consumer install with no Rust toolchain | claimed | proved on Linux/macOS/Windows × Node 20/22/24 × Python 3.10–3.14 | `packed-consumer`, `python_wheel_smoke` |
| A13 | Moderated cohort: unfamiliar developer completes recipe 01 on a clean machine | cohort size **0** | ≥ 5 developers, ≥ 4 unaided, median ≤ 15 min | `moderatedRecipeThreeCohort` in the matrix |
| A14 | `mypy --strict` and `pyright` clean on the README example | fails (`union-attr`) | clean | `bindings/python/typecheck` |
| A15 | `tsc --strict --exactOptionalPropertyTypes` clean on every README and recipe snippet | partial | clean | `packed-consumer` type block |

A13 is the only criterion that cannot be automated, and it is the one the repository already names as the freeze gate (`docs/product/vocabulary-review.json`: `freezeEligible: false`, `cohort: []`). It stays blocking.

---

## 11. Tests required before cutover

### 11.1 Security and invariant tests (must pass before the surface is frozen)

| # | Test | Asserts |
|---|---|---|
| S1 | Axis fidelity | For all 48 registry codes, the `effect`/`retry`/`next`/`recommendedAction` on a projected outcome equal `auths_errors::classify(code)`, in both languages. No binding-side literal anywhere. |
| S2 | Unknown-code fail-closed | An outcome carrying a code absent from this build's registry projects `effect: possible`, `retry: unknown`, `recommendedAction: resume-and-reconcile` — never `not-applied`, never a fourth value. |
| S3 | Reference invariant | `kind === "recoverable"` ⟺ `reference` present ⟺ `next === "resume"`; and no `indeterminate` ever carries a reference. Cross-checked against `ProductionResponse::new`'s shape validation. |
| S4 | Registry/type coherence | For every definition, `outcomes.some(o => o.effect === "possible") === allowsExecutionReference`. Today true for all 9; make it a build-time gate so a future entry cannot produce an unconstructable variant. |
| S5 | No fabricated outcomes | No `catch`/`except` on a public path returns a constructed outcome. Static check plus a fault-injection test proving a 4xx denial from a remote runtime surfaces as `denied`, not `indeterminate`. Directly regresses §1.9. |
| S6 | Denial precedes credentials | An action outside the authority produces `denied` with zero provider invocations and zero credential requests. |
| S7 | Provider binding is per-call | Mutating the caller's handler object after `connect` (including via a getter) cannot redirect an execution; the frozen-capture assertion fires. §7.5 |
| S8 | Authority never serializes | `JSON.stringify(auths)`, `repr(auths)`, `pickle.dumps(auths)`, and logging `auths.scope` never emit credential bytes. `Authority.toJSON()`/`__reduce__` throw. |
| S9 | Verification is not authorization | `verifyProof`/`verifyReceipt` return no executable handle and no value accepted by `execute`. Static check on the declaration files. |
| S10 | Trust anchor is explicit | `verifyReceipt` requires a `Trust`; no public verification function accepts an endpoint. Regresses §13.3. |
| S11 | Bounded input | Byte, collection, depth and batch limits enforced identically in both languages, with boundary and boundary-plus-one fixtures; malformed input returns a typed error and never panics. |
| S12 | Fail-closed routing | The profile→route table is exhaustive with a `never` assertion. Today `endpointPath` falls through to the GitHub execute path for any unlisted profile, and Python keys routes by positional index into a tuple. |
| S13 | Config equality | Required and executed verifier configuration are compared before any persistence, reservation, credential acquisition or provider I/O; a mismatch is an explicit failure. |
| S14 | Exactly-once under concurrency | N concurrent `execute` calls with one `requestId` produce exactly one provider entry, against both the fixture store and a real `ReservationStore` via `certifyReservationStore`. |
| S15 | Crash and resume | Crash before and after provider entry; `resume` re-enters reconciliation, never the handler. |

### 11.2 Semantic parity gate — new, and the load-bearing missing gate

There is **no** general TypeScript↔Python name diff in the repository today. `test_vocabulary_parity.py` pins about twelve hand-picked symbols by substring-searching TypeScript source from a Python test, and the cross-language `equivalentNames` check in `xtask/src/sdk_vocabulary.rs:97-103` is dormant (`enforcement: "prototype"`) and would fail spuriously if enabled, because it looks for `delegate`/`execute`/`resume` as module-level exports when they are methods.

Build `xtask/src/sdk_parity.rs`:

1. Parse both `public-api.txt` files. Normalize (strip `_`, lowercase). Assert set equality per entry point.
2. Assert the module↔entry-point mapping is the declared bijection.
3. Assert every closed string-literal set (`kind` values, `EffectState`, `RetryClass`, `NextCall`, `RecommendedAction`, `ProductStage`, `ProductVerb`, `VerificationStage`) has identical members in both languages, read from the *generated* projections.
4. Assert every port has the same method-name set and the same async-ness. This is what catches `close?()` optional vs `aclose()` required — invisible to every name-based check because `./framework` has 11/11 name parity.
5. Assert every numeric limit and every option name with a unit is identical. This is what catches `timeoutMs` vs `timeout_seconds`.
6. Exceptions live in `bindings/parity-exceptions-v1.json`, each with a `reason`. A stale exception is a failure, matching the existing allowance-file discipline in `public-api.mjs:147-158`. Seed it with exactly one entry: `Auths` generic arity (§6.3).

### 11.3 Documentation-execution gate

`bindings/python/tools/check_doc_snippets.py:32-37` only `compile()`s snippets, which is why the crashing README example shipped. Extend both languages to **execute** every fenced block tagged `runnable` against the packed artifact, and mark every README and recipe snippet `runnable`. A snippet that cannot run must be tagged `illustrative` and must not appear before a runnable one.

### 11.4 Package and platform tests

| # | Test |
|---|---|
| P1 | **Fix `packed-consumer.test.js` first.** It cannot load (missing `readFile` import), so the strictest public-surface gate in the repository has not been running. This is a prerequisite for every other package assertion. |
| P2 | The packed tarball exposes exactly the five entry points; `service`, `integrations`, `framework` and the 13 previously removed subpaths all fail with `ERR_PACKAGE_PATH_NOT_EXPORTED`. The `removed` array is hand-maintained — the three new names must be added. |
| P3 | The wheel contains exactly the five public modules. Move `auths/_service.py`, `auths/service.py`, `auths/framework.py`, `auths/integrations.py` from `REQUIRED_PACKAGE_FILES` to `REMOVED_PUBLIC_FILES` in `check_wheel.py`, which asserts the inverse and forces actual deletion. |
| P4 | Clean-machine install with an empty package cache and no Rust toolchain: Node 20/22/24 × {linux, macos, windows}; Python 3.10–3.14 × {linux, macos-arm64, macos-x86_64, windows}. Add the missing macOS x86_64 wheel; resolve the declared 3.13/3.14 support against `freeThreaded: false`, which leaves no supported install path on a free-threaded interpreter. |
| P5 | Browser bundle: `./verify` and `./identity` load and run with no Node built-in. Today `inspectCandidate` does `await import("node:fs/promises")` inside a subpath advertised as browser-capable. |
| P6 | Tree-shaking: a bundle importing only `./verify` does not pull the execution runtime. Report the byte delta; the current single 1.3–2.2 MB WASM blob backs all eight subpaths with no splitting. |
| P7 | The committed `.tgz` matches what the repo builds. It does not today: 1,350,608 vs 2,226,278 bytes of WASM, and 7,016 vs 159,860 bytes of glue. |
| P8 | `_native.pyi` matches the extension. It declares 148 symbols against 115 that exist and omits one runtime symbol, while being `py.typed`-covered and wheel-mandatory. |
| P9 | `bin` and `__main__` are covered by the public-API snapshot (§5.10). |

### 11.5 Coverage gate

For every name in either `public-api.txt` — including one level into exported namespace objects — assert at least one reference in `test/`, `tests/`, `docs/`, `demos/`, `bindings/recipes/`, or an executed README snippet. Today this fails for 60 TypeScript and 43 Python names. **This is the gate that keeps the surface from re-accreting**, and it is the one gate whose absence explains every dead family in §1.5.

### 11.6 Differential and conformance

Unchanged in kind, extended in coverage: canonical fixtures, mutation corpus, cross-language differential vectors, and stable-code agreement between Rust, WASM and PyO3. Add: the parity gate (§11.2) runs in the same CI phase, and `certify*` reports pin an exact suite version.

---

## 12. Implementation sequence

Fifteen bounded review units. Each is independently reviewable and leaves the repository green. Per `AGENTS.md`, push each to its PR and let GitHub CI be the verification run.

**Order matters: gates must be worked in dependency order, not CI order.** `cargo xtask ci preflight` dies at step 2 (`semantic-freeze`) before it looks at the SDK at all, so a naive loop gives no useful signal. The working order is: source cutover → regenerate snapshots → bump freeze versions → rebaseline experience → fix compliance anchors → `cargo test -p xtask` → `ci preflight` → `bindings`.

**Do all of this while both packages are prerelease.** `xtask/src/evolution_policy.rs:526-528` short-circuits the MAJOR-bump floor while every coordinate is a prerelease; `@auths-dev/sdk` is `1.0.0-rc.1` and `auths` is `1.0.0rc1`. After either leaves rc, the same diff demands a major bump on both and runs `validate_stable_immutables`.

| # | Unit | Contents | Green when |
|---|---|---|---|
| **R0** | Unblock the gates | Restore `readFile` in `packed-consumer.test.js`; fix the Python README handler arity; add snippet *execution* (§11.3). **No API change.** | The clean-consumer gate runs for the first time; the Python README executes |
| **R1** | Abstraction case file | `docs/adr/` entry per `PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md:429-450`: `Auths<P>` as candidate, four profiles as consumers, exact shared contract, what stays profile-owned, differential evidence, cutover plan. Reviewable and rejectable on its own. | Reviewed |
| **R2** | Parity gate | `xtask/src/sdk_parity.rs` + `bindings/parity-exceptions-v1.json`, seeded with today's 74 + 50 divergences as *expiring* exceptions. Makes every later unit measurable. | Gate runs; exception list matches today exactly |
| **R3** | Coverage gate | §11.5, seeded with today's 103 unreferenced names as expiring exceptions. | Gate runs |
| **R4** | Result model | `Outcome` (4 kinds, full axes), `Verification`, `Reference`, `AuthsError`. Delete `AuthsWorkflowError`, `GitHubAgentError`, `ProviderOperationError`, `McpGatewayError`. Tests S1–S5. **Largest semantic unit; no topology change yet.** | S1–S5 pass in both languages |
| **R5** | Python floor | `requires-python = ">=3.10"`, `check_wheel.py:142,146`, classifiers, CI matrix, `[tool.mypy] python_version`. | 3.10–3.14 matrix green |
| **R6** | Profiles | Branded `Profile`/`Action`/`Authority`/`Plan`; `mcp.tools`; `github`/`opentofu`/`postgresql` namespaces. Delete the ~30 `Mcp*` public types. | Recipes 01–03 compile and run in both languages |
| **R7** | `connect`/`local`/`remote` | One constructor; `local` absorbs `development`/`createRecoverableAuths`; `remote` absorbs `createServiceClient`; `runtime.mode` derived. Delete `createAuths`, `AuthsConfiguration`, `production`. Move `Signer`/`ReservationStore`/`ReceiptStore`/`Observer` to root and reconcile them with `McpExecutionState`/`McpReceiptSink`. Test S7. | §4.1 and §4.6 run |
| **R8** | GitHub vertical | `github.issueAddress()` + `remote()` replaces `GitHubAgentClient`. Rewrite `demos/github-issue/examples/{typescript,python}/agent.*`; delete the untracked `agent_ideal.*`. Test S5 against a real 4xx. | The demo's live opt-in test passes end to end |
| **R9** | `./verify` | `Trust`, `verifyProof`/`verifyProofs` (named record), `verifyReceipt(receipt, trust)`. Delete the inspection/disclosure/summary families; move receipt rendering to `demos/github-issue/web/`. Tests S9, S10. | Recipe 04 runs |
| **R10** | `./identity` | Six shared symbols; internalize both adapter tiers. Recipe 05 becomes the same program in both languages. | Recipe 05 runs; parity exception list shrinks by 28 |
| **R11** | `./testkit` | `fixtures`, four `certify*`, one `ConformanceReport`. Fix `fixtures.signer()` failing 3 of 8 of `certifySigner`; fix `certifyReservationStore`'s isolated-instances case so a durable shared-backend store can pass. | `certify*` green against the sqlite adapter |
| **R12** | Topology cutover | Delete `./service`, `./integrations`, `./framework`. In one commit: `bindings/public-topology-v1.json`; `package.json` exports **in topology order** (`public-api.mjs:19` compares stringified arrays); both `sdk-runtime-contract.json` (move the three Python modules into `excludedModules`, which forces real deletion via `find_spec`); `check_wheel.py` required→removed; `xtask/src/sdk_experience.rs:253-277` classifier arms **and** the assertions at `:378-389`; `xtask/src/sdk_vocabulary.rs:138` owner array; `sdk-capability.json` evidence paths in both languages; `checks.rs:237-257` smoke source; `packed-consumer.test.js` removed-subpath array and root-export allowlist; `test_vocabulary_parity.py` (5 assertions across 3 tests); `effect-axis.ts:29`; `full_workflow_consumer.py`; the two `demos/open-production-reference` installed-SDK tests. | `cargo xtask bindings` green |
| **R13** | Regenerate and freeze | `node tools/public-api.mjs --update`; `check_public_api.py --update`; `check_type_stub.py --update`; then `release/semantic-freeze-versions.toml`: `freeze_version 141→142`, `auths.identity.protocol 36→37`, `auths.release.evolution-contract 24→25`; `cargo xtask semantic-freeze --update`; `cargo xtask sdk-experience --update`. Fix the `compliance.toml` claim anchors this cutover renames (`:1220-1222`, `:1444-1445`, `:1456-1458`). **All three version bumps in one commit** — bumping only `freeze_version` still fails the per-identity rule. | `cargo xtask ci preflight` green |
| **R14** | Docs and enforcement | Both READMEs per §9.1; five recipes per language; delete the stale subpath table in `docs/adoption-layers.md`; rewrite `06_PRODUCTION_FAILURES.md`; root README link; flip `customer-journey-matrix` `enforcement` to `"enforced"` with the §10 targets; drain the R2/R3 exception lists to empty. | §10 A1–A12, A14, A15 green |
| **R15** | Cohort | Run A13 with ≥5 developers unfamiliar with Auths on clean machines. Record in `moderatedRecipeThreeCohort` and `docs/product/vocabulary-review.json`. | `freezeEligible: true` |

R15 is the only unit that cannot be completed by an engineer alone, and it is the repository's own stated freeze gate.

---

## 13. Tradeoffs, rejected alternatives, remaining decisions

### 13.1 Rejected: free functions with an explicit context, no client object

`execute(action, ctx)` with `ctx` a plain value. Genuinely attractive: it deletes the whole disposal/use-after-close problem class, and `createAuths`-unreachability and `production` dead code disappear because there is no configuration to mint.

**Rejected for three reasons.** (1) Authority-chain verification cannot be amortized; a hot agent re-derives from authority bytes on every call, and the only mitigation is an invisible, untunable internal memo. (2) The context must be threaded through every call site, and a staging context and a production context are the same type — a handle turns "wired to the wrong backend" into one construction-site mistake, free functions make it available at every call site. (3) No `close()` means Auths can never zeroize owned key material or flush a receipt buffer at shutdown; `AGENTS.md` requires secret material to be zeroized on drop.

**Taken from it:** `delegate` should ideally return a *value* rather than a second live handle with a child-close cascade. Not adopted here because a delegated `Auths` needs its own child signer, but recorded in §13.5.

### 13.2 Rejected: profile-first — the domain module is the SDK

`github.issueAddress.connect({endpoint})`, with no generic client. This is the most faithful reading of `PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md`, and it makes cross-profile confusion impossible.

**Rejected because** it forbids the polymorphic consumer entirely — gateways, policy proxies, multi-tenant brokers and observability middleware must write and maintain an N-arm switch — and it duplicates `connect/execute/delegate/resume/close` four times in each language, so a timeout or disposal bug is fixed in eight places. It also leaves the root import with nothing executable, which is the overwhelmingly common first move.

**Taken from it:** profiles mint the nouns and own their denial codes and receipt claims; the client never dispatches on a profile tag; the abstraction case file (R1) is mandatory rather than optional.

### 13.3 Rejected: `auths.verify(...)` on the client

The candidate design had `verify` on `Auths` so all five product verbs sat on one object. **Rejected as a fail-open regression**, and this is the sharpest finding in the review.

Locally, `verifyReceipt` verifies in-process against the packaged engine with no network. Remotely, `ServiceClient.verify` posts to `/v1/authority/verify` on `this.#endpoint` — **the same origin that issued the receipt**. Those are opposite trust claims. One method on one object whose runtime was chosen at a `connect()` call in another module makes them indistinguishable:

```ts
const v = await auths.verify(receipt);
if (v.passed) archiveAsProven(receipt);
```

Tested against `local(...)` this really is independent verification. Wired to `remote({endpoint})` in production, a compromised or merely buggy node answers `passed: true` for receipts it forged, and the audit path is self-certifying.

**Resolution:** verification is a free function in `./verify` that takes an explicit `Trust` and never takes an endpoint (S10). If operator-side re-verification is later needed, it must be named for what it is (`attestation()`) and return a type structurally incompatible with `Verification` — no `passed`, no `verified`.

### 13.4 Rejected: `open()` as the constructor name

`open` shadows the Python builtin (`auths/__init__.py` could no longer call builtin `open` after defining the name; ruff `A004` and flake8-builtins `A001` fire on the SDK's headline call) and collides with the DOM global `window.open` and with `import { open } from "node:fs/promises"` in exactly the server code that uses this SDK. `connect` collides with neither, pairs with `close()`, and does real work — it loads the signer, initializes the engine and compiles the trust anchor.

Also rejected: `operator()` for the remote runtime. It is a Python stdlib module name, and more importantly it is a **category error** — `development`/`production` name a trust *maturity* while `operator` names a *locality*, and they are orthogonal. A developer pointing at a staging reference node had to choose between the correct locality and the correct maturity, and `doctor` would print the wrong answer either way. `local`/`remote` names the locality; maturity is derived and reported in `runtime.mode`.

### 13.5 Rejected: two distributions (`@auths-dev/sdk` + `@auths-dev/verify`)

A relying party that only checks receipts pays for a 1.3–2.2 MB WASM blob today, and the install-size argument is real.

**Rejected because** the enforcement-time verification inside `execute` must keep sealed native authority (`verify_v1_sealed` exists precisely so the executed action is derived from verified canonical bytes without re-parsing), so it cannot be delegated across a module boundary without weakening an invariant that must survive — meaning the verify crates would ship in **two** artifacts, and every Rust change would re-qualify four binaries instead of three. Add lockstep versioning, a peer range, a second coordinate block in `public_naming.rs` (where `@auths-dev/sdk` and `auths` are hard-coded literals), and a new failure mode: mismatched versions sharing an `AuthsErrorCode` union.

**Taken from it:** P6 makes the tree-shaking delta a measured, reported number. If it stays bad and real demand appears, splitting later is a package decision, not an API decision — which is the point of keeping `./verify` free-function-shaped and engine-lazy.

### 13.6 Accepted costs

1. **`exact-replay` loses its own `kind`.** Today `RecoveryResult.kind` can be `exact-replay`, and recipe 04 asserts on it. There is no `Replayed` in Rust's `ClientOutcomeKind`, and the local `exact-replay` branch returns neither result nor receipt (`product.ts:403`), so a first-class `Replayed{ok:true, value, receipt}` would be a shape the runtime cannot fill — a binding author would route it into `Completed` and hand the caller a receipt it did not earn on that call. The information survives in `code` and in `receipt.executionId`. See §13.7 D1.
2. **Exhaustive handling covers branches a given deployment cannot produce.** Under `local(...)` a caller essentially never sees `next === "reconcile"`; the type does not say so. The three-client split made reachability visible in the type you held, at the cost of three unrelated client shapes. The trade is worth it, but it is a trade.
3. **`Auths` generic arity differs between the languages** (§6.3). The one parity exception, and it is forced by Python's invariance rather than chosen.
4. **Deleting the identity adapter tier removes a real extension point.** A third party can no longer plug in a custom identity method or signature suite. Nothing uses it today, both `parse` methods are synchronous (structurally excluding every async backend), and the SDK cannot attest what an adapter did. It is free to remove exactly once — now, at zero external users — and never again.
5. **Five entry points exceeds the stated four-layer budget by one module** (though it uses exactly four purpose labels). `./identity` and `./verify` are both `component`. Merging them would put `authenticate` inside a module named `verify`, which the glossary's own misuse rules forbid.
6. **The cutover is total.** ~23 files, 2 semantic-freeze identity bumps, 1 freeze-version bump, and every recipe, demo, external consumer and parity test rewritten. Defensible only because there are zero external users and publication status is `blocked` in both `sdk-capability.json` files. The same proposal one week after publication would be indefensible.

### 13.7 Remaining decisions

| # | Decision | Recommendation |
|---|---|---|
| **D1** | Should exactly-once replay return the original receipt? The local `ReceiptStore` already holds the bytes keyed by `executionId`, so returning them on `exact-replay` is a lookup, not new semantics. The remote path would need `ClientOutcomeKind::Replayed` with a `receipt.is_some() && retry == Never` arm. | **Yes, as a separate Rust unit after R4.** Then add `Completed.replayed: boolean`. Do not ship a `Replayed` type ahead of the runtime that fills it. |
| **D2** | Does selective receipt disclosure ship in v1? §5.3 removes the four-symbol port because nothing implements or calls it. | **Remove now, reintroduce with a worked example** if a design partner needs it. |
| **D3** | `requires-python >= 3.10` (§6.4) — a policy change with a support-matrix consequence. | **Yes.** 3.9 reached EOL in October 2025 and the current `match`-based idiom is unbuildable on it. |
| **D4** | Do `Signer`/`ReservationStore` belong at root, or is a `./runtime` component entry point clearer? | **Root.** They are the named fields of `local()`, so IntelliSense on that options object is the discovery path. `./framework` proves the alternative: the two contracts have shipped there for months with no consumer at all. |
| **D5** | `auths` vs `auths-proof` on crates.io. `v1-api-contract` §10A ratified dropping `auths-proof`, but `xtask/src/public_naming.rs:231-232` *requires* surface `rust-proof-component` to target it and both remain in the 42-crate closure. Acting on the ratified default fails the enforced inventory. | **Out of scope for this proposal, but blocking for release.** Settle before freeze. |
| **D6** | The error registry declares `operation: "sign"` (18 codes) and zero `delegate` codes, so its operation axis disagrees with the five wire verbs; a failed `connect()` will carry `operation: "create"`. | **Do not rename the registry as part of this cutover.** Document it on `connect`. Fix as a separate Rust unit if the taxonomy should match. |
| **D7** | Should `bindings/typescript/adapters/durable-json` and `bindings/python-adapters/sqlite` be published coordinates with their own snapshots, or unpublished? The JSON one implements a port name (`ExecutionStatePort`) that exists in neither binding. | **Unpublish the JSON adapter; keep sqlite** and add it to the topology, since it implements the real contract and is already certified in CI. |
| **D8** | `frameworkContracts` and `qualifiedProfiles` in `public-topology-v1.json` are read by no gate, and the three rosters that list profiles disagree (topology 4, the release manifest 3, the docs bundle 1). | **Give them a gate in R12** or delete the fields. Unread metadata that disagrees with itself is worse than absent. |

---

## Appendix A — files a redesign must touch

Derived from `bindings/public-topology-v1.json`, which is the single source of truth for the entry-point set.

**Derived from the topology (change it and they follow):** `bindings/typescript/tools/public-api.mjs:14-21` (order-sensitive `JSON.stringify` comparison) · `bindings/typescript/test/package/package.test.js:16-24` · `bindings/typescript/test/package/packed-consumer.test.js:10-12` · `bindings/python/tools/check_public_api.py:11-16` · `bindings/python/tests/test_vocabulary_parity.py:214-238` · `xtask/src/sdk_experience.rs:401-436`.

**Restated by hand (must be edited in the same commit):** `bindings/typescript/package.json:9-42` · `bindings/typescript/sdk-runtime-contract.json:7-16` · `bindings/python/sdk-runtime-contract.json:37-69` · `bindings/python/tools/check_wheel.py:33-69` · `bindings/typescript/test/package/packed-consumer.test.js:14-17,30-33,132-163` · `xtask/src/sdk_experience.rs:253-277,378-389` · `xtask/src/sdk_vocabulary.rs:138-151` · `docs/product/sdk-glossary.json` (`ownerConcepts`, `equivalentNames`) · `bindings/{typescript,python}/sdk-capability.json` (`eliteScorecard` evidence paths are `access()`-checked) · `xtask/src/checks.rs:237-257` (inline smoke source) · `bindings/typescript/test/package/packed-node.test.js:12` · `bindings/typescript/test/contract/effect-axis.ts:29` · `bindings/recipes/{typescript,python}/03,04,05` · `bindings/python/external/full_workflow_consumer.py:7,9` · `demos/open-production-reference/tests/installed-sdk-e2e.mjs:19` and its Python twin · `compliance.toml:1220-1222,1444-1445,1456-1458` · `release/semantic-freeze-versions.toml:1,49,70`.

## Appendix B — verified counts

| Metric | Value | How |
|---|---|---|
| TS entry points / symbols | 8 / 203 | parsed from `bindings/typescript/api/public-api.txt` |
| TS per entry point | `.` 34, `./identity` 15, `./verify` 37, `./service` 38, `./profiles` 35, `./integrations` 4, `./framework` 11, `./testkit` 29 | same |
| Python modules / symbols | 8 / 180 | parsed from `bindings/python/api/public-api.txt` |
| Python per module | `auths` 22, `.identity` 19, `.verify` 34, `.service` 36, `.profiles` 20, `.integrations` 5, `.framework` 11, `.testkit` 33 | same |
| Name overlap (normalized) | 123 shared / 74 TS-only / 50 Python-only | `s.replace("_","").lower()` set comparison |
| Registry codes | 48 | `product/errors/v1/registry.json` |
| Codes with `effect: applied` | 1 (`mcp.receipt-persist-failed`) | same |
| Codes with `effect: not-applied` and `retry != never` | 10 | same |
| Codes with `effect: possible` | 9, all `allowsExecutionReference: true` | same |
| Proposed TS surface | 89 declarations across 5 entry points (47 + 14 + 13 + 6 + 9) | §3 |
