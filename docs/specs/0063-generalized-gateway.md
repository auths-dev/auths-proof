# AP-SPEC-063: The generalized gateway: recovery capability, provider capabilities, one spend limit, operator plane, and evidence

- **Status:** Draft, written on owner direction on 2026-09-25 before its epic
  starts. Nothing here is implemented. Writing it does not start an epic, and
  the WIP limit (program board rule 1) still governs implementation. §13's
  readings are PROVISIONAL until the owner reviews them. On 2026-09-27 the
  owner chose §12 option A: the gateway becomes the single provider-write
  path. This change adds this file and its program board entries.
- **Depends on:** [AP-SPEC-053](0053-declarative-credential-isolated-gateway.md)
  (gateway, recipe language, stages),
  [AP-SPEC-056](0056-openapi-derived-operation-contracts.md) (derivation),
  [AP-SPEC-059](0059-commitment-bound-provider-evidence.md) (echo),
  [AP-SPEC-060](0060-evidence-conditioned-authority.md) (observation
  requirements, gateway observer, attenuation),
  [AP-SPEC-025](0025-closed-bounded-authorization-policy.md) §24–§25 (bounded
  policy in the gateway),
  [AP-SPEC-038](0038-production-runtime-custody-observability-and-assurance.md)
  §9 (production trust),
  [AP-SPEC-040](0040-generic-profile-sdk-and-contributor-system.md) §7.2–§7.4
  (local agent sockets, connection registry, credential lifecycle),
  [AP-SPEC-012](0012-stripe-bounded-refunds.md) (the Stripe vertical's
  features), [ADR 0012](../adr/0012-declarative-credential-isolated-gateway-boundary.md),
  [abstraction case 0007](../research/domains/abstraction-cases/0007-declarative-credential-isolated-request.md),
  and the [boundary plan](../target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md).
  It builds on three pull requests merged on 2026-09-26, without duplicating
  them: #156 (the derived `Idempotency-Key`), #155 (the gateway's
  provider-secret handling), and #160 (the doctor probe's environment and
  provider HTTP clients).
- **Enables:** board §0 step 2 with the provider result for every entry, and
  provider-held evidence for the Stripe recipe; a cross-process admin
  guarantee the owner may add to AP-SPEC-038 §9's done gate; and §12's
  consolidation onto one provider-write path.
- **Retires:** per-actor window counts; recipe source `/1` and its digest
  domain; attempt record `/2`; outcome `/1`; observe request `/1`; audit
  bundle and report `/1`; installation manifest `/2`; PostgreSQL schema
  `auths.lifecycle.postgresql/4`; evaluator
  `auths.gateway.argument-ceiling-window-count/1`; declared operator
  principals; and, under §12's decision, the five local-agent effect
  profiles.
- **Scope:** product layer only: `product/runtime/auths-gateway`,
  `product/stores/auths-stores`, `product/policy/auths-bounded-policy`,
  `product/tools/auths-openapi-derive`, `auths-node gateway recipe check` in
  `product/runtime/auths-node`, the Python and TypeScript gateway clients,
  `formal/Auths/Product/`, and `examples/stripe-refund-approval`. No core
  change.
- **Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** specify
  implementation requirements

## 1. Decision and claim

The 2026-09-24 code review confirmed the gateway's core: native verification
before any durable state, a one-use claim before any credential lease, a
pinned transport with no proxy or redirect, and no stage that promotes a
response into an effect. It found five gaps.

- A recipe cannot say what it can prove after an ambiguous write.
- The north-star Stripe refund recipe lacks what the `auths-stripe` vertical
  proved necessary: a pinned API version, a test-mode guard, a fresh evidence
  re-read, and a provider-held link to the action.
- Window counts are kept per actor, so delegation multiplies a parent's count.
- The operator plane needs its own capacity and deadlines, admin mutations
  that never wait on provider calls, connection state that holds in every
  process sharing a store, separation checks that compare keys, and an
  authenticated operator.
- The signed outcome and the offline audit omit the provider's response, and
  the gateway has no fuzz, Kani, or property coverage.

This spec closes them inside ADR 0012's data-only mechanism. Gateway code
gains no provider semantics. Each provider-specific choice (a header value,
a key prefix, a JSON pointer, a retention period) is recipe data that the
author writes, the compiler bounds, the review shows, and the operator
approves by digest (053 §3.1).

| # | Change area | Section |
| --- | --- | --- |
| 1 | Recovery capability per recipe | §4 |
| 2 | Capabilities the Stripe vertical proved necessary | §5 |
| 3 | One spend limit | §6 |
| 4 | An operator plane the application cannot interfere with | §7 |
| 5 | Evidence and assurance | §8 |

All five share one recipe revision (§3) and one store contract (§9).

**Claim, once implemented.**

- Before approval, the gateway publishes which evidence a recipe can produce
  and how an ambiguous write of that recipe can resolve.
- For every claimed submission it records the stage, the gateway evaluation
  time, the refusal code when it refused, and the HTTP status and response
  digest when a complete response exists. When an observer key is
  provisioned, it signs that record on request as `auths.gateway-outcome/2`.
  A production gateway has no observer key until AP-SPEC-038 Epic 4 supplies a
  custody client (§16).
- Within one namespace and one store, a bounded grant's count bounds every
  action of its subject and its delegates together in each fixed window, and
  the bound's ceiling times its count bounds the sum of the bounded argument
  over those actions.
- Admin mutations commit without waiting for provider calls and reach every
  process sharing the store at that process's next reload.
- The offline audit shows the provider result beside `verified`, which still
  means authorized and entered.

**Not a claim.**

- Provider effect, acceptance, or settlement (053 §3.3).
- Authorship. The echo is unkeyed and shows consistency, not who wrote a
  record (059 §1).
- Observer honesty. Observer trust is operator trust.
- A conditional write. A pre-entry re-read narrows the window; it does not
  close it.
- That a provider honors a declared idempotency mechanism or keeps it for the
  declared retention.
- A rolling limit. Fixed windows admit up to twice a count across a boundary.
- Claims or counts after store loss. A wiped or restored store forgets both.
- That an audit bundle is complete.
- Separation of persons, or key comparison for a method whose identifier does
  not name one key.
- An authenticated gateway clock.

## 2. Evidence and the abstraction boundary

The boundary plan requires vertical-first semantics, extraction of identical
mechanisms only, a written comparison first, and no operation tag, optional
union, or callback in a shared API. Every capability here is a closed,
digest-bound field of the recipe AST or a gateway runtime mechanism.

| Capability | Classification | Public evidence | Stays operation- or domain-owned |
| --- | --- | --- | --- |
| Version headers (§5.1) | Request mechanism; the response rule is per registry entry | `bounded_provider_result` sends and requires `Stripe-Version` (`product/integrations/auths-stripe/src/local_agent.rs`); `product/integrations/auths-github/src/adapters.rs` sends `X-GitHub-Api-Version` | Which version, and what it means |
| Credential guard (§5.2) | Byte-prefix allowlist and one JSON equality | `valid_static_secret`, `verify_account_response` (`product/integrations/auths-stripe/src/connection/onboarding.rs`); the lease check in `product/integrations/auths-stripe/src/connection/credentials.rs`; 012 §7 | What test mode means |
| Idempotency declaration (§4.1) | Deterministic key from explicit commitments, plus declared data | #156; `IdempotencyPreimage` (`product/integrations/auths-stripe/src/types.rs`); `uuid` in `bindings/fixtures/gateway/todoist/recipe.json` | Whether the provider honors it; retention |
| Response locator (§4.1) | One bounded value from the recorded response in one path segment | 012 §14; case 0007 | The meaning of a read-back match |
| Form echo (§5.4) | 059's token in one new form key | `echo_token` (`product/runtime/auths-gateway/src/recipe.rs`); Stripe metadata tagging in `local_agent.rs` | Authorship (none) |
| Pre-entry re-read (§5.3) | Reuse of 060 requirements and predicates | 012 §13; the plan's Phase 2 order; `product/runtime/auths-gateway/src/observed_tests.rs` | Which conditions apply; conditional writes |
| Recovery capability (§4) | Derived from the declarations | 059 §3.3; the claim ledger's Todoist limit | — |
| Aggregate counts (§6) | New evaluator identifier (025 §6) | 025 §24–§25; 012 §6 | Amount-sum budgets |
| Operator plane (§7) | Runtime mechanism | `serve`, `admin_session` (`product/runtime/auths-gateway/src/bin/auths-gateway.rs`); `separation.rs`; 038 §9.2 | — |
| Outcome and audit `/2` (§8) | Evidence record, not a qualified receipt (053 §3.3) | Board §0 step 2; `audit.rs` | Settlement meaning |

The six recipe capabilities each rest on fewer than three merged consumers
across two domains, so each is a smaller promotion that needs an ADR (plan,
"Domain to shared product"). Epic 1 writes ADR 0013, which amends ADR 0012 for
all six and adds each comparison to case 0007. A reviewer may reject any one
of them without blocking the others.

## 3. Recipe source `/2`

### 3.1 Shape

The north-star Stripe recipe after Epic 7 shows most new fields. The header
value, probe endpoint, and retention are examples the author confirms against
the provider's documentation; this repository makes no provider calls. The
recipe declares no `pre_entry`, for the reason in §5.3.

```json
{
  "schema": "auths.gateway-recipe-source/2",
  "profile_schema_digest": "<64 lowercase hex>",
  "service": "stripe-refunds",
  "tool": "create_refund_v1",
  "operator_namespace": "stripe-refunds",
  "credential": {
    "kind": "bearer",
    "guard": {
      "prefixes": ["rk_test_", "sk_test_"],
      "probe": {
        "path": [{"kind": "fixed", "value": "v1"}, {"kind": "fixed", "value": "balance"}],
        "json_pointer": "/livemode",
        "equals": false,
        "maximum_response_bytes": 16384
      }
    }
  },
  "origin": "https://api.stripe.com",
  "provider_headers": {"Stripe-Version": "<pinned version>"},
  "write": {
    "method": "POST",
    "path": [{"kind": "fixed", "value": "v1"}, {"kind": "fixed", "value": "refunds"}],
    "body": {
      "kind": "form",
      "fields": {
        "payment_intent": {"kind": "field", "name": "payment_intent"},
        "amount": {"kind": "field", "name": "amount"}
      }
    },
    "idempotency": {"kind": "derived-header", "retention_seconds": 86400}
  },
  "observation": {
    "path": [
      {"kind": "fixed", "value": "v1"},
      {"kind": "fixed", "value": "refunds"},
      {"kind": "response-field", "pointer": "/id", "max_bytes": 255}
    ],
    "json_pointer": "/amount",
    "expected_field": "amount",
    "maximum_response_bytes": 16384
  },
  "echo": {
    "write": {"kind": "form-field", "name": "metadata[auths_echo]"},
    "observe": "/metadata/auths_echo"
  }
}
```

### 3.2 Fields and compile rules

`CompiledRecipe::compile` (`product/runtime/auths-gateway/src/recipe.rs`)
parses the source once into the typed AST and refuses anything outside these
rules with the listed code. Rules not listed are 053 §3.2.1 and 059 §3.2.

| Field | Required | Rule | Code |
| --- | --- | --- | --- |
| `schema` | yes | Exactly `auths.gateway-recipe-source/2`; `/1` is refused | `gateway.recipe.invalid-source` |
| `credential` | yes | As `/1`; a `header-api-key` header may not be `Idempotency-Key` or a registered version header | `gateway.recipe.invalid-credential` |
| `credential.guard.prefixes` | with `guard` | 1–4 unique strings of 1–32 bytes in `0x21..=0x7e` | `gateway.recipe.invalid-credential-guard` |
| `credential.guard.probe` | no | `path` of 1–16 `fixed` segments; `json_pointer` under the observation pointer rules; `equals` a JSON string of at most 256 bytes, an integer of magnitude at most 2^53 − 1, or a boolean; `maximum_response_bytes` 1–65 536 | `gateway.recipe.invalid-credential-guard` |
| `provider_headers` | no | At most 2 entries, each name and value as §5.1's registry allows | `gateway.recipe.invalid-provider-header` |
| `write.path` | yes | As `/1`; no `response-field` segment | `gateway.recipe.response-locator-conflict` |
| `write.idempotency` | no | §4.1; `retention_seconds` 1–2 592 000; an `operation-id-field` location must resolve to a field reference to `operation_id` | `gateway.recipe.invalid-idempotency` |
| `observation.path` | with `observation` | As `/1`, plus at most 2 `response-field` segments, each with an observation pointer and `max_bytes` 1–255 | `gateway.recipe.response-locator-conflict` |
| `echo.write` | with `echo` | `{"kind": "json-pointer", "pointer": ...}` for a JSON body (059 §7.1) or `{"kind": "form-field", "name": ...}` for a form body (§5.4), matching the body; `echo` still requires `observation` | `gateway.recipe.echo-conflict`, `gateway.recipe.echo-without-observation` |
| `pre_entry` | no | `path` of 1–16 `fixed` or `field` segments under the write path's rules; 1–4 unique `pointers` under the observation pointer rules; `maximum_response_bytes` 1–65 536 | `gateway.recipe.invalid-pre-entry`, `gateway.recipe.unsafe-path` |
| `preconditions.read_back_subject` | no | As `/1`; refused when the observation path has a `response-field` segment | `gateway.recipe.precondition-conflict` |

Every profile field is still consumed, now by the write, the observation, the
pre-entry path, or the preconditions (`gateway.recipe.unsafe-template`
otherwise). The 64 KiB source bound, the 16 KiB body bound, and every other
`/1` limit stay.

### 3.3 Digest and cutover

The digest is SHA-256 over `auths.gateway-compiled-recipe/2`, a NUL byte, and
the RFC 8785 serialization of the validated source, with absent optional
fields omitted. Every recipe changes digest and needs a new approval and new
actions (053 §3.1). The three fixtures under `bindings/fixtures/gateway/`, the
north-star recipe, and the derivation corpus's thirteen expected recipes are
regenerated in the same change. `product/tools/auths-openapi-derive` writes
`/2` and emits none of the new optional blocks (056 §8.1). No reader accepts
`/1`.

### 3.4 Review output

`auths-gateway review` and `auths-node gateway recipe check`
(`product/runtime/auths-node/src/bin/auths.rs`) print
`auths.gateway-recipe-review/2`. It keeps every `/1` field and adds:

- the provider headers and the credential guard;
- the idempotency declaration, with "declared by the recipe author; the
  gateway cannot verify that the provider honors it";
- the observation locator (`verified-locator` or `response-locator`);
- the echo placement, with 059's disclosure;
- the pre-entry subjects, with "read after the credential lease and before
  the write; the write is not conditional";
- the recovery capability of §4.2 and `write_is_conditional: false`.

## 4. Recovery capability per recipe

### 4.1 What a recipe declares

**Idempotency** (`write.idempotency`):

| Kind | What the gateway does |
| --- | --- |
| `derived-header` | Sends #156's `Idempotency-Key` on the write and never on a read. The value and hostile cases are #156's: `auths-i1-` and the lowercase hex SHA-256 of `auths.gateway-idempotency-key/1`, NUL, namespace, NUL, logical operation ID. The object replaces #156's boolean `write.idempotency_key`. |
| `operation-id-field` | Nothing extra. It declares that the provider de-duplicates on the verified logical operation ID the body already carries at `location`: `{"json_pointer": ...}` for a JSON body, or `{"form_field": ...}` with an optional `pointer` into compiler-serialized JSON for a form body. |

`retention_seconds` is the provider's documented retention, declared by the
author and shown to the operator. The gateway can verify neither it nor
whether the provider honors the mechanism.

**Observation locator.** The locator is `verified-locator` when every
non-fixed segment of the observation path is a `field`, and `response-locator`
when any segment is a `response-field`. A `response-field` value comes from
the durably recorded write response, which must be complete, 2xx, inside the
65 536-byte write-response bound, and JSON, with the pointer present and no
version mismatch (§5.1). The value must be a JSON string of 1 to `max_bytes`
bytes, or a non-negative integer of at most 2^53 − 1 written in decimal, such
as GitHub's issue `number`. It is percent-encoded exactly as a `field` segment
(`build_path` in `recipe.rs`), so it cannot add a segment, query, or fragment.
Only the value is stored (`response_locator`, §4.3), never the body.

**Echo.** As 059, with a form placement (§5.4).

### 4.2 The derived capability

`recovery_capability` in `recipe.rs` is a pure, total function of the three
declarations and returns `auths.gateway-recovery-capability/1`:

```json
{
  "schema": "auths.gateway-recovery-capability/1",
  "class": "linked-after-response",
  "state_observation": "response-locator",
  "provider_link": "response-locator",
  "unknown_resolution": "none",
  "lost_claim_reentry": {"deduplication": "declared", "kind": "derived-header", "retention_seconds": 86400},
  "pre_entry_reread": false,
  "write_is_conditional": false
}
```

| Field | Rule |
| --- | --- |
| `state_observation` | The observation's locator, or `none` without an observation |
| `provider_link` | `state_observation` when an echo is declared, else `none` |
| `class` | `linked` for a `verified-locator` link, `linked-after-response` for a `response-locator` link, `observed` for an observation without echo, `recorded` otherwise |
| `unknown_resolution` | `gateway-reobservation` for `linked`, `none` otherwise |
| `lost_claim_reentry` | The declared kind and retention, or `{"deduplication": "none"}` |
| `pre_entry_reread` | Whether `pre_entry` is declared |
| `write_is_conditional` | Always `false` |

What each class can prove:

| Class | After a complete response | After `unknown` | What an auditor re-checks with their own provider access |
| --- | --- | --- | --- |
| `linked` | `observed-by-provider` when a read-back finds this action's token and the verified value; otherwise `observed` (`match`, `mismatch`, or `echo-mismatch`) | `observed-by-provider` through a later read-back (§4.4); otherwise stays `unknown` | The token in the record at the verified locator |
| `linked-after-response` | The same, at the locator from the recorded response | Stays `unknown`: the locator was in the lost response | The token in the record the response named |
| `observed` | `observed` (`match` or `mismatch`), never causation | Stays `unknown`; there is no `unknown → observed` edge (059 §7.1) | Provider state, unlinked to the action |
| `recorded` | `response-recorded` with status and digest | Stays `unknown` | Nothing from the gateway |

After Epic 2, the Airtable fixture is `linked`; the GitHub issue fixture,
given a response locator on its integer `/number`, is `observed`; and the
Todoist fixture is `recorded`, declaring `operation-id-field` at `commands`
`/0/uuid` only if its author can state Todoist's retention. After Epic 7 the
Stripe recipe is `linked-after-response` with `derived-header`.

### 4.3 Attempt record `/3` and its transitions

`GatewayAttempts` (`product/runtime/auths-gateway/src/store.rs`) owns the
format. `auths.gateway-attempt/3` replaces `/2`; a `/2` record is `Corrupt`.

| Field | Content |
| --- | --- |
| `schema`, `namespace`, `operation_id`, `action_commitment`, `recipe_digest`, `nonce` | As `/2` |
| `evaluated_at` | The gateway clock when native verification ran; used for the window index and the entry deadline |
| `stage` | See the transitions below |
| `refusal` | The stable code, exactly when `stage` is `not-entered` |
| `counters` | The sorted `{counter, slot}` pairs reserved with the claim (§6.3) |
| `response_status`, `response_digest` | As `/2` |
| `response_locator` | For a `response-locator` recipe after a qualifying response: pointer → value |
| `observation_plan` | Resolved segments, unresolved `response-field` pointers, the canonical expected value, and the echo flag; fixed at claim |
| `observation_match`, `observation_fact`, `provider_evidence` | As `/2` |
| `pre_entry` | Up to four signed pre-entry observations and their digest (§5.3) |

A record whose fields contradict its stage is `Corrupt`, as
`stage_fields_consistent` enforces for `/2`. The worst case is about 136 KB
(87 KB evidence, 22 KB pre-entry observations, 27 KB locators and expected
value, all encoded), so both stores raise the record bound to 262 144 bytes
(§9.1).

`valid_transition` in `store.rs` becomes this closed table, checked
exhaustively by Kani (§8.5):

| From | To | Condition |
| --- | --- | --- |
| `attempting` | `attempting` | Once, before transport entry, adding only `pre_entry` |
| `attempting` | `not-entered` | Before transport entry, with a "recorded" code of §10; may add `pre_entry` |
| `attempting` | `unknown` | Transport may have been entered; no complete response |
| `attempting` | `response-recorded` | A complete bounded response |
| `attempting`, `unknown` | `observed-by-provider` | `linked` recipe: a read-back from the stored plan found the token and the value |
| `response-recorded` | `observed`, `observed-by-provider` | A read-back from the stored plan and locator |

`not-entered`, `observed`, and `observed-by-provider` are terminal. Every
transition keeps the identity fields, `evaluated_at`, `counters`, and the
plan, and is a compare-and-swap on the exact stored bytes. A re-observation
records only positive evidence under that compare-and-swap, so it may run
while the original attempt is in flight. If it wins, the in-flight process
loses its own compare-and-swap and reports `unknown`; no second write happens
either way.

### 4.4 How `unknown` resolves

- **`linked`.** A replay (the same namespace and operation ID under any fresh
  valid proof) or the operator's `reobserve` (§7.7) performs one read-only
  observation from the stored plan when the recipe digest is unchanged. It
  records `observed-by-provider` on a token-and-value match and changes
  nothing otherwise. The token comes from the stored commitment
  (`Record::echo_token` in `store.rs`), never from the submission.
- **Every other class.** `unknown` stays `unknown`. The gateway never
  re-enters the provider and records no operator finding (§16).
- **Idempotency.** No declaration resolves `unknown` or licenses a second
  entry, even inside the retention; safe retry is a 053 §7 non-goal.

### 4.5 Lost claims and the retention rule

The durable claim is the guarantee, and it holds while the store is intact.
After a wipe, or a restore from an older backup, the gateway cannot tell a
lost claim from a first submission.

- **Declared de-duplication.** Re-entry of the same logical operation sends
  the same key or field, so a provider that honors it de-duplicates the
  repeat within its retention.
- **Retention rule.** For a recipe that declares `write.idempotency`, the
  gateway refuses before the claim any action whose validity window
  (`expires_at` minus `not_before`, from `ValidityWindow` in
  `core/crates/auths-model/src/lib.rs`) plus the 60-second entry deadline
  (§5.5) exceeds `retention_seconds`
  (`gateway.idempotency.window-exceeds-retention`). Every entry of one
  admitted action then falls within one retention period of its first. The
  approval-quorum default window of 24 hours plus 60 seconds exceeds a
  declared 86 400-second retention, so the north-star journey sets its window
  to at most 86 340 seconds (Epic 7).
- **After the retention lapses,** the action no longer verifies. A newly
  authored action for the same logical operation, submitted to a store that
  lost its claim, is not de-duplicated; it carries new signatures and is a
  new authorization.
- **After a loss,** the runbook directs the operator to reinstall under a new
  namespace. Every earlier action names the old namespace, fails projection
  against the new recipe (053 §3.1), and cannot enter. Counts restart (§1,
  "Not a claim").

### 4.6 The guarantee after this spec

Per logical operation and intact store: at most one provider write, on one
host for the file store and across every process sharing the PostgreSQL
store. Writes are never retried. An ambiguous write stays `unknown` unless a
read-back finds this action's token and value, which only `linked` recipes
can do.

## 5. Capabilities the Stripe vertical proved necessary

### 5.1 Provider version headers

The recipe-header allowlist of 053 §3.2 gains a closed registry,
`PROVIDER_VERSION_HEADERS` in `recipe.rs`:

| Name | Value grammar | Response rule | Vertical |
| --- | --- | --- | --- |
| `Stripe-Version` | 10–64 bytes of `[A-Za-z0-9.-]`, first byte a digit (`valid_api_version` in `product/integrations/auths-stripe/src/merchant.rs`) | Required: a response without the header, or with another value, has a version mismatch | `auths-stripe` |
| `X-GitHub-Api-Version` | Exactly 10 bytes, `YYYY-MM-DD` | None: responses are not checked | `auths-github` |

The gateway sends each declared header on every request to the origin (the
write, the observation, the pre-entry read, and the credential probe) and
nowhere else. A read with a version mismatch is unavailable: it is not
compared, signed, or recorded, and a pre-entry read with one refuses the
submission (§5.3). A write is recorded as usual, because the gateway never
interprets a write body; a mismatch only suppresses locator extraction.
Operator approval cannot widen the registry. A new entry needs an amendment
naming its vertical evidence and response rule, plus hostile fixtures.

### 5.2 Credential-mode guard

`credential.guard` states what the author says a permitted credential looks
like.

| Check | When | Failure |
| --- | --- | --- |
| Prefix: the secret starts with a declared prefix | At onboarding (`install`, `install --join`, admin `rotate`) before the secret is stored; at every lease before any header is built | Onboarding refused (`gateway.install.credential-guard`, `gateway.admin.credential-guard`); after a claim, recorded `not-entered` with `gateway.credential.mode-guard`; an observation request refused with `gateway.observer.credential-guard` |
| Probe: one GET with the candidate secret over the pinned transport with the provider headers, passing on a complete 2xx JSON response within `maximum_response_bytes` whose pointer holds `equals` | At onboarding, after the prefix check, under a 20-second deadline | Onboarding refused with nothing stored (`gateway.install.credential-probe`, `gateway.admin.credential-probe`) |

The guard reads the lease through #155's zeroizing types and never logs or
returns the secret. What a prefix or a probe field means is the provider's
convention, declared by the author and approved by the operator; the gateway
compares bytes and one JSON value.

### 5.3 Pre-entry evidence re-read

`pre_entry` makes the gateway re-read, after the credential lease and before
the write, provider fields that the grant's observation requirements already
constrain, and evaluate those requirements again on what it reads. It adds no
condition language. The conditions are the grant's 060 conditions, evaluated
by the shipping predicates `observation_fresh`, `observation_conditions_hold`,
and `requirement_verdict` (`core/crates/auths-model/src/observation.rs`), with
action facts from `mcp-arguments-v1` (`McpArgumentsPolicy` in
`auths-profile-mcp`).

**Selection, before the claim.** A requirement in a grant of an authorized
branch is selected when:

- its schema is `auths.gateway-readback/1`;
- the anchor it names is in the installed trusted context, has the gateway
  observer's principal (by identifier), lists that schema, and covers the
  subject;
- its subject resolves, as a literal or an action fact, to a pre-entry subject
  `<url>#<pointer>`, built from `pre_entry.path` and verified fields as
  `ClosedObservationRequest::subject` in `recipe.rs` builds read-back
  subjects.

A `pre_entry` recipe refuses an action with no selected requirement
(`gateway.pre-entry.requirement-missing`), and every action when no observer
key is provisioned (`gateway.pre-entry.observer-unavailable`). A production
gateway has no observer key until AP-SPEC-038 Epic 4, so production refuses
every action of a `pre_entry` recipe.

**Execution, after the lease.** The gateway takes `observed_at` from its
clock, performs one GET, builds each pointer's facts as 060 §14 reading 3
does, and signs one `auths.gateway-readback/1` observation per pointer.

| Result | Stage and code |
| --- | --- |
| Every selected requirement fresh after the read and satisfied | Observations recorded (`attempting → attempting`); continue |
| Otherwise, a selected requirement has a fresh observation that makes a condition false (a false condition dominates, as in 060 §4.1) | `not-entered`, `gateway.pre-entry.condition-false`; observations kept |
| Otherwise: transport failure, non-2xx, version mismatch, oversize, non-JSON, absent pointer, unrepresentable value, or stale | `not-entered`, `gateway.pre-entry.unavailable` |

`pre-entry-digest` is the SHA-256 of `auths.gateway-pre-entry/1`, a NUL byte,
and, for each observation in pointer order, its four-byte big-endian length
and bytes. The write stays unconditional. The settled non-claim "gateway
writes aren't conditional on the record being unchanged" stands, with its
window narrowed from the requirement's maximum age to the re-read-to-write
interval.

**Named scenario.** `pre-entry-replaced-after-observation` in
`attempt-scenarios.json` uses an Airtable recipe with `pre_entry` on
`/fields/DemoStatus` and a grant requiring `eq-action("value", "expected")`.
The agent attaches a fresh matching read-back, then another writer changes the
field. The gateway's re-read finds the new value and records `not-entered`
with `gateway.pre-entry.condition-false`: one lease, one read, zero writes.

**Why the Stripe recipe leaves it out.** The north-star profile carries no
approved expected state to compare, and the useful check (the refund amount
does not exceed the remaining refundable amount) compares two numbers, which
060's conditions cannot do (060 §2). It also could not run in production
without an observer key.

### 5.4 A provider link for form bodies

A form body may carry the echo in one new field. Its name matches
`[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`, optionally followed by one bracketed segment
of the same grammar (`metadata[auths_echo]`). It must not equal an existing
field name, and the form, echo included, keeps at most 16 fields. The compiler
adds the pair at serialization in sorted field order (`build_body` in
`recipe.rs`); an author-placed echo anywhere else stays
`gateway.recipe.echo-conflict`. The observe pointer, token, stages, and
evidence record are 059's, and the gateway still adds nothing else to any
body. In §3.1, the refund is read back at `/v1/refunds/<id>`, with `<id>` from
the recorded response, and the token is at `/metadata/auths_echo`.

### 5.5 Submission order

`GatewayEngine::submit` (`product/runtime/auths-gateway/src/engine.rs`)
follows this order. The last column names the epic that adds each new step.

| Step | Action | On failure | Epic |
| --- | --- | --- | --- |
| 1 | Read the gateway clock as `evaluated_at` | Indeterminate | today |
| 2 | Check input bounds; verify natively at `evaluated_at` (`verify_v1_sealed` in `verify_detailed`) | Denied or indeterminate | today |
| 3 | Admit: bounded policy (§6.1); projection; retention rule (§4.5); pre-entry selection (§5.3); per-proof observer check (§7.5) | `not-entered`, nothing stored | 4; today; 3; 3; 5 |
| 4 | Load the shared connection record; require this host to hold its current credential (§7.3) | `not-entered`, nothing stored | 5 |
| 5 | Prepare the pinned transport | `not-entered`, nothing stored | today |
| 6 | Claim atomically with every count slot (§6.3); a replay goes to §4.4 | Exhausted: recorded `not-entered`; store unavailable: nothing stored | 3; slots 4 |
| 7 | Continue in a task the application connection cannot cancel; it holds the capacity permit until the final stage (§7.1) | — | 5 |
| 8 | Reload the shared record and require it unchanged: the re-read AP-SPEC-040 §7.4 requires immediately before credential acquisition | Recorded `not-entered`, `gateway.connection.changed` | 5 |
| 9 | Lease the credential (30-second deadline); apply the prefix guard (§5.2) | Recorded `not-entered` | today; guard 3 |
| 10 | Run the pre-entry re-read when declared (§5.3) | Recorded `not-entered` | 3 |
| 11 | Increment the in-flight count; reload the shared record; require it unchanged | Recorded `not-entered`, `gateway.connection.changed` | 5 |
| 12 | Refuse entry after `evaluated_at + 60` seconds, on the gateway clock or the monotonic deadline started at step 1 | Recorded `not-entered`, `gateway.attempt.entry-deadline` | 3 |
| 13 | Send the one write, with provider headers, the key or declared field, and the echo | Before network entry: recorded `not-entered`, `gateway.transport.not-entered` | today; additions 3 |
| 14 | Record the response (status, digest, locator), or `unknown` | — | today; locator 3 |
| 15 | Decrement the in-flight count; perform at most one read-back | — | 5; today |

Until Epic 5 lands, steps 4, 8, and 11 read today's per-process connection
store (`prepare_entry` and `reread_before_lease` in `engine.rs`).

## 6. One spend limit

### 6.1 Semantics

025 §25 reading 10 stays: one authorized branch may carry bounds, and two
bounded branches are refused (`gateway.policy.multiple-branches`). In that
branch, every grant from the first bounded grant to the terminal grant carries
a `bounded-policy-commitment-v1` extension, because 060 §17.1 requires a child
to keep its parent's identifiers. Each such grant contributes one **link**:
its subject and its decoded policy. The action is admitted when:

- the chain has at most 16 links (`gateway.policy.too-many-bounds`);
- every link's evaluator is the registered
  `auths.gateway.argument-ceiling-window-count/2`
  (`gateway.policy.evaluator-unregistered`, `gateway.policy.evaluator-mismatch`);
- the first link has no parent link (`gateway.policy.dangling-link`);
- every linked pair passes the unchanged decider (`gateway.policy.expanded`);
- the verified argument is within every ceiling
  (`gateway.policy.above-ceiling`, `gateway.policy.argument-unavailable`);
- one slot is reserved, all or none and with the claim, in the counter of
  every distinct link subject (§6.3). A counter shared by several links of one
  chain takes the smallest of their counts as its capacity.

A link's counter therefore counts every admitted action of its subject and of
every delegate below it. Siblings, and delegation to the parent's own key
under another method, no longer get fresh counters. Each admitted action is
within every ceiling of its chain, so the argument sum over one link's actions
in one window is at most that link's ceiling times its count; for the root
link, that bounds the whole tree. The bound holds per namespace and per store:
counters are keyed by namespace (§6.2) and live in one store, so a namespace
served from two stores, or a store that loses its records, counts separately.

Count meaning changes, so the evaluator identifier becomes `/2` (025 §6, rule
7). The policy type and bytes stay. A grant naming `/1` is refused as
unregistered, and `auths-gateway bound-extension` prints `/2`.

### 6.2 Counters and slots

| Item | Definition |
| --- | --- |
| Counter key | SHA-256 of `auths.gateway-bounded-count/2`, NUL, then namespace, link subject identifier, and evaluator identifier, each with an eight-byte big-endian length prefix, then eight-byte big-endian `window_seconds` and window index |
| Slot key | SHA-256 of `auths.gateway-bounded-count-slot/2`, NUL, the counter key, and the eight-byte big-endian slot number |
| Slot record `auths.gateway-bounded-count/2` | `counter`, `slot`, `window_seconds`, `window_index`, `window_end`, `namespace`, `operation_id`, and the claim key |

As today, the counter omits grant and root identity, so one subject's grants
from different roots share a counter, which is conservative. Subjects are
keyed by identifier. Two identifiers for one key can exist only as the
subjects of two grants their issuer created, and a shared ancestor link
charges both. A gateway's trusted context cannot anchor one key twice (§7.5).

### 6.3 Atomic claim and reservation

One store operation, `insert_all` (§9.2), replaces `BoundedCountStore` and the
separate `reserve_window` step in `product/runtime/auths-gateway/src/bounds.rs`.

1. For each distinct counter, find the lowest free slot below its capacity by
   binary search over the occupied prefix, as `reserve_window` does.
2. If a counter is full, insert the claim alone as `not-entered` with
   `gateway.policy.window-exhausted`; the operation ID is consumed, as today.
   An existing claim key goes to §4.4's replay path.
3. Otherwise, insert the claim (`attempting`, with `counters`) and one slot
   record per counter in one `insert_all`.
4. If the claim key exists, take the replay path. If slot `s` of counter `c`
   exists, advance `c` to `s + 1`, return to step 2 if that reaches capacity,
   and retry step 3. After 32 rounds, store nothing and return `not-entered`
   with `gateway.policy.count-unavailable`.

Slots are inserted only at an observed frontier and are not deleted inside
their window, so a counter's slots form a prefix, and a search that reaches
capacity proves it full. Work is one binary search per counter plus at most 32
inserts. Slots are never released (§13, reading 2), and a replay consumes
nothing.

### 6.4 Fixed windows

The window index is `floor(evaluated_at / window_seconds)` on the gateway
clock (`window_index` in `product/policy/auths-bounded-policy/src/kernel.rs`).
Windows align to the Unix epoch, so an 86 400-second window is a UTC day, and
up to twice a count can be admitted in any `window_seconds`-long interval that
spans a boundary. Every description of the window MUST say fixed and
epoch-aligned. Epic 4 updates each one:

- 025 §25 readings 5, 7, and 10;
- the `CeilingCount` claim texts in `formal/assurance-manifest-v1.toml`;
- the module comments of `bounds.rs` and `CeilingCount.lean`;
- the claim ledger's per-principal section;
- the north-star README, whose "two refunds a day" becomes "two refunds per
  UTC day".

### 6.5 Collection

- **Count slots.** A slot's `expires_at` is `window_end + window_seconds`, so
  it outlives its window by one full window. `serve` deletes expired slots on
  a 60-second tick, at most 1 024 per tick. A process whose clock lags by more
  than one window could admit an action its deleted counter no longer
  charges; that falls under the unauthenticated-clock non-claim (§1).
- **Claims.** Never collected, because deleting a claim reopens its logical
  operation at the provider (053 §3.1). The store grows by one bounded record
  per logical operation. A full store fails the insert
  (`gateway.attempt.unavailable`, nothing stored) and evicts nothing.

### 6.6 Formal model and decider

`formal/Auths/Product/CeilingCount.lean` changes as follows.

- `Context.count : Nat → Nat` (the actor's count per window length) becomes
  `count : CounterKey → Nat` over `CounterKey := (subject, window)`. With
  `Link := (subject, Policy)`, `linkAdmits` is today's `admits` at the link's
  counter, and `chainAdmits` requires every link, each shared counter taking
  the smallest count.
- `reserve : List Link → (CounterKey → Nat) → Option (CounterKey → Nat)`
  increments every distinct key of an admitted chain once, and returns `none`
  otherwise.
- New theorems:
  - `reserve_all_or_none`: either every count is unchanged, or each distinct
    key rises by exactly one and every other key is unchanged.
  - `aggregate_count_bound`: for every arrival order in one window, the
    admitted chains containing a link number at most its count.
  - `aggregate_spend_bound`: their argument sum is at most the link's ceiling
    times its count.
  - `delegation_never_multiplies`: the corollary for a root link.
- `decider_sound`, `tightening_never_admits_more`, and
  `bounded_policy_law_lawful` are re-proved with unchanged statements.

The decider does not change: `ceiling_count_tightens` still requires the same
argument and window, and a ceiling and count no larger than the parent's. It
no longer carries the aggregate bound, which the parent's counter now
enforces, but it keeps each child's own bound no wider than its parent's (025
§15), and one shared window keeps a chain's counters on the same boundaries. A
new pure leaf `chain_counts_admit(counts: &[u64], capacities: &[u64]) -> bool`
in `kernel.rs` is translated through the pinned Aeneas route, with a
refinement theorem to the count part of `chainAdmits`. The atomicity of
`insert_all` stays a residual assumption (025 §23), tested by conformance and
not proved.

### 6.7 Audit recount

`audit_bundle` (`product/runtime/auths-gateway/src/audit.rs`) re-verifies
each entry at the outcome's `evaluated-at` (§8.1) and derives its links'
counters at that time.

- **Counter set.** For an entered entry, the derived counters MUST digest to
  the outcome's `counters-digest` (`audit.counters-mismatch`).
- **Bound.** For each counter and window, let E be the entered entries that
  charge it, and m_e each entry's capacity for it. The gateway gave each
  entry a distinct slot below m_e, which is possible exactly when, for every
  k, at most k entries of E have m_e ≤ k. The auditor checks that condition,
  which uses no times and no order. At the smallest failing k, every entry of
  E with m_e ≤ k is `inconsistent` (`audit.bound-exceeded`). The condition is
  necessary and sufficient for some arrival order to have produced E, so the
  check never flags a valid bundle and flags every over-admission among the
  bundle's entries.
- **Exhaustion.** An entry refused with `gateway.policy.window-exhausted` is
  `refused` with that code. When the bundle shows, for each of its counters,
  fewer entered entries than its capacity, `provider_result.recount` is
  `not-shown-by-bundle`, because a bundle may be incomplete.

### 6.8 Fixtures

`bindings/fixtures/gateway/bounds-aggregate.json`
(`auths.gateway-bounds-aggregate/1`) runs through both stores:

- siblings whose combined actions exceed the parent's count, refused at it;
- a parent and a child sharing a counter;
- self-delegation to the parent's own key under the other method, still
  charged to the parent;
- an exhausted ancestor refusing without consuming the descendant's slot;
- a burst across a window boundary, admitted as documented;
- evaluator `/1`, and 17 links, both refused;
- two PostgreSQL processes racing for the last slots, admitting exactly the
  capacity;
- an audit bundle with one capacity-3 and two capacity-1 entries on one
  counter, flagged.

`bounds-hostile.json` keeps its eight cases under evaluator `/2`; "sub-agent
narrower inside" now also consumes its parent's slot. Every refused case has
zero provider entries and zero leases.

### 6.9 Relationship to Stripe profile budgets

`auths-stripe` keeps its own budgets (012 §6): per-currency amount sums over
fixed or rolling windows, released on proven non-effect and held while the
outcome is unknown. They need provider-specific recovery evidence, so the
gateway does not import them (§16), and the two limits never count each
other's effects. Under §12's decision (option A), the gateway bound is the
only production spend limit, and the vertical's evaluator is a test-only
reference and a demo. Until epic 8 lands, a Stripe account reachable through
both paths has two unrelated limits. The runbook and the claim ledger MUST
say so, and an operator MUST NOT rely on either limit to bound the other
path.

## 7. Operator plane

### 7.1 Listeners, capacity, and deadlines

`serve` (`product/runtime/auths-gateway/src/bin/auths-gateway.rs`) runs two
listeners with separate capacity.

| Listener | Capacity | Deadlines |
| --- | --- | --- |
| Application | `--app-capacity`, 1–1 024, default 64; the permit moves to the detached execution (§5.5 step 7) | Frame read 5 s and response write 5 s; the session waits at most 90 s for its result and never cancels a claimed execution |
| Admin | 4 permits no application connection can take. Before reading a frame, the peer's effective UID (`SO_PEERCRED` or `getpeereid`) must be the gateway's or root; any other peer is closed without a response (`gateway.admin.peer-refused`, logged) | Frame read 5 s; the probe of `rotate` at most 20 s (§5.2); the commit within the store's statement timeout; the drain at most 20 s (§7.2); response write 5 s |

An accept error on either listener is logged (`gateway.serve.accept-failed`)
and followed by a 100-millisecond back-off; it never ends `serve`. `serve`
refuses to start when `RLIMIT_NOFILE` is below both capacities plus the store
pool plus 32 (`gateway.serve.descriptor-limit`).

### 7.2 Admin mutations

- An admin mutation MUST commit its change to the shared connection record
  (§7.3) by compare-and-swap without waiting for any submission or provider
  call. The engine holds no lock that a submission could keep it waiting on.
- Each process keeps an in-flight count. A submission increments it before
  its final reload (§5.5 step 11) and decrements it after recording.
- After committing, the mutation waits at most 20 seconds for this process's
  count to reach zero, then reports `drained` and any remaining count.
- A submission that increments after the commit reloads the committed state
  and refuses. Only entries already past their final reload can still enter,
  and each finishes within the transport's 15-second total timeout, in this
  process and every other.

This relies on both stores returning a committed write to every later read.

### 7.3 Connection state across processes

The connection record moves into the shared store as record kind `connection`
(§9.1): the canonical `auths.provider-connection/1` bytes that
`auths-connections` defines, keyed by SHA-256 of `auths.gateway-connection/1`,
NUL, provider, NUL, alias. Admin mutations replace it by compare-and-swap
through `auths-connections`' own transition functions, so its format and
rules stay the registry's (053 §4). Every process reloads it at §5.5 steps 4,
8, and 11, so a disable or revocation committed through any process stops new
leases and entries in every process at its next reload. The per-process
`PersistentConnectionStore` copy (`connections.cbor`) leaves the state
directory.

Credential bytes stay in each host's local credential store
(`credentials.cbor`), and nothing secret enters the shared store. A process
leases only the generation the shared record names, and only if its local
store holds a secret whose reference commitment equals the record's.
Otherwise it refuses before the claim
(`gateway.connection.credential-generation-missing`).

| Operation | Behavior |
| --- | --- |
| `install` (first host) | Inserts the record once (`gateway.install.connection-exists` if present) and stores the secret locally |
| `install --join` (each further host, with the same recipe, trust, lock, provider, alias, deployment, and store) | Loads the record (`gateway.install.join-record-missing` if absent); applies the credential guard; computes the reference commitment the local store would record for the secret under the record's connection ID and generation; compares it with the record's in constant time; stores the secret only on a match (`gateway.install.join-commitment-mismatch` otherwise) |
| `rotate` | Committed to the record through one process; each other process then accepts the same secret through its own `rotate` only when the secret's commitment equals the record's (`gateway.admin.generation-conflict` otherwise) |

A process that cannot confirm the record's current state refuses new entries.

### 7.4 Revocation

Disable and revocation semantics are AP-SPEC-040 §7.4's.

### 7.5 Key identity in separation of duties

A gateway function, `key_identity(principal) -> Option<[u8; 32]>` in
`product/runtime/auths-gateway/src/separation.rs`, returns the SHA-256 of the
canonical `raw-key-v1` descriptor of the one key an identifier names.

| Identifier | Key identity |
| --- | --- |
| `key:sha256:<base64url>` (`raw-key-v1`) | The 32 bytes the identifier encodes |
| `did:key:<multikey>` | Parse the Multikey (`auths-multikey`), whose Ed25519 and P-256 forms are `raw-key-v1`'s two key types, and hash its `raw-key-v1` descriptor (`encode_v1` in `core/crates/auths-raw-key-core/src/lib.rs`) |
| Any other method | `None`. `raw-key-v2` commits to another encoding, `did:keri` keys rotate, and keyless methods use a new key per signature, so they keep identifier comparison (settled.md) |

The function lives in the gateway, its only consumer, and uses the core
crates `auths-multikey` and `auths-raw-key-core` as direct dependencies, which
`architecture.toml` permits. Two principals **overlap** when their
identifiers are equal or their key identities are equal. The gateway applies
overlap in three places:

1. **Static separation.** `check_principal_separation` compares the operator,
   roots, and observers by overlap and keeps its four codes.
   `gateway.trust.observer-not-anchored` keeps identifier equality, mirroring
   the kernel's requirement that an observation's observer equal its anchor.
2. **Aliased anchors.** `install` and `serve` refuse a trusted context in
   which two distinct identifiers among its trust and observer anchors overlap
   (`gateway.trust.key-aliased`). One key under two methods would otherwise
   count twice toward a composition requirement, such as the north star's
   quorum of distinct roots.
3. **Per proof.** Before the claim, for each observation that satisfied a
   requirement (`VerifiedAction::observation_satisfactions` in
   `core/crates/auths-verifier/src/lib.rs`), the gateway refuses when its
   observer overlaps the trust anchor, a grant issuer or subject, or the actor
   of an authorized branch (`gateway.trust.observer-key-in-authority-chain`).
   The kernel already refuses identifier equality.

`bindings/fixtures/gateway/key-identity.json` pins `did:key` and `raw-key-v1`
pairs for Ed25519 and P-256 keys, plus principals of other methods that
return `None`.

### 7.6 The authenticated operator

A production installation names its operator only through a signed
`auths.gateway-operator-attestation/1`, canonical under RFC 8785:

```json
{
  "schema": "auths.gateway-operator-attestation/1",
  "operator_principal": "<principal>",
  "principal_method": "did-key-v1",
  "verification_method": "<verification method>",
  "signature_suite": "ed25519-v1",
  "installation": {
    "recipe_digest": "<64 lowercase hex>",
    "profile_lock_sha256": "<64 lowercase hex>",
    "trusted_context_sha256": "<64 lowercase hex>",
    "provider": "stripe",
    "alias": "refunds",
    "deployment": "production"
  },
  "issued_at": 1790000000
}
```

- **File.** `operator-attestation.json` (mode 0600, at most 16 KiB) holds the
  statement, the base64url signature, and at most four control-evidence
  objects. The preimage is `auths.gateway-operator-attestation/1`, a NUL byte,
  and the canonical statement. It starts with lowercase `auths.`, and every
  core signing preimage starts with `AUTHS` (`signing_preimage` in
  `core/crates/auths-codec/src/hash.rs`), so the two can never be equal.
- **Flow.** `auths-gateway operator-request` prints the preimage for the
  operator's own signer, and `install --operator-attestation <file>` takes the
  result. The `--operator-principal` flag is removed.
- **Verification**, at `install` and every `serve` start, is the kernel's way
  of verifying a signed object: the registered method named by
  `principal_method` (`raw-key-v1`, `did-key-v1`, or `did-keri-v1`; any other
  is refused) establishes the key from the control evidence with purpose
  `Assertion`, and the named suite verifies the signature. `issued_at` is the
  asserted signing time and may be at most 300 seconds ahead of the gateway
  clock. The installation block MUST equal the manifest. Refusals are
  `gateway.install.operator-attestation-required` and
  `gateway.install.operator-attestation-invalid`.
- **Manifest.** `auths.gateway-installation/3` holds the attestation's
  SHA-256. A development installation MAY omit the attestation and then has
  no operator.
- **Replacement.** `auths-gateway operator-attest --replace` runs offline with
  every process stopped, and the new principal must pass §7.5.

An authenticated operator holds the key it names. Separation of persons stays
AP-SPEC-038 §9.3's second-operator gate.

### 7.7 Admin commands

Frames become `auths.gateway-admin-request/1` (`schema`, `command`, and
arguments) and `auths.gateway-admin-response/1` (`ok`, `code`, and `drained`
with `in_flight` for mutations). A secret travels in a second frame, as
`rotate` does today. The peer check of §7.1 alone authorizes every command, so
custody unavailability can never block the kill switch.

| Command | Effect | Codes |
| --- | --- | --- |
| `disable`, `revoke`, `rotate` | §7.2–§7.4 | `gateway.admin.disabled`, `.revoked`, `.rotated` |
| `status` | Connection state and generation, in-flight count, last sweep, gateway clock | `gateway.admin.status` |
| `reobserve {operation_id}` | §4.4, read-only; answers with a submit result | `gateway.admin.reobserved`, `gateway.reobserve.not-observable` |

## 8. Evidence and assurance

### 8.1 `auths.gateway-outcome/2`

The outcome keeps its subject
(`auths-gateway://<namespace>/operations/<operation-id>`) and observer. Its
fact set changes meaning, so the schema becomes `/2` and `/1` is removed
(§13, reading 1). The kernel treats schema identifiers and fact names as
opaque, so the core CDDL, codec, registry, and corpus stay (060 §3.1).

| Fact | Type | Present when |
| --- | --- | --- |
| `commitment` | text, 64 lowercase hex | Always |
| `stage` | text | Always: `not-entered`, `unknown` (also for a stored `attempting`, as 060 §14 reading 4), `response-recorded`, `observed`, or `observed-by-provider` |
| `evaluated-at` | uint | Always |
| `recipe-digest` | text, 64 lowercase hex | Always |
| `counters-digest` | bytes (32) | At least one counter was reserved |
| `refusal` | text, at most 128 bytes | `not-entered` |
| `http-status` | uint, 100–599 | A complete response was recorded |
| `response-digest` | bytes (32) | With `http-status` |
| `observation` | text: `match`, `mismatch`, `echo-mismatch` | `observed` |
| `evidence-digest` | bytes (32) | `observed-by-provider` |
| `pre-entry-digest` | bytes (32) | Pre-entry observations were recorded |

`counters-digest` is the SHA-256 of `auths.gateway-counter-set/1`, a NUL byte,
and the sorted counter keys. At most 11 of an observation's 16 facts are used.
`observed_at` stays the signing time, which 060 freshness needs.
`evaluated-at` is the time the audit re-verifies at, so an outcome requested in
a later window no longer moves its entry into that window. A chained step's
`member("stage", ["observed-by-provider"])` (060 §5) works unchanged.

**Consumers**, all changed in one cutover:

- in the gateway: `observer.rs` (`OUTCOME_SCHEMA`, `outcome_facts`,
  `verify_outcome`, `ObserverAnchorTemplate`), `engine.rs`, `audit.rs`,
  `harness.rs`, and `observed_tests.rs`;
- the custody test in `product/integrations/auths-custody/src/lib.rs`;
- the Python and TypeScript gateway clients, their tests, and their public-API
  inventories;
- the north-star example and every trusted context's observer anchors;
- `compliance.toml`, 060, the claim ledger, and the runbook.

**Fixtures.** `bindings/fixtures/gateway/outcome-v2.json` holds, for each stage
and fact combination, the canonical outcome signed by a fixed test observer
and its expected facts. Rust verifies every entry. The Python (native) and
TypeScript (WASM) SDKs accept every entry and, through local verification,
reach the gateway's verdict on a grant requiring `member("stage",
["observed-by-provider"])`. Go consumes no gateway schema, so no Go vector is
added.

### 8.2 Observe request `/2`

`auths.gateway-observe/2` keeps `read-back`, which is refused for a path with
a `response-field` segment, and `outcome`. It adds `pre-entry
{operation_id}`, which returns one operation's stored signed pre-entry
observations as `{"outcome": "pre-entry", "operation_id", "observations_b64":
[...]}`. It signs nothing new and contacts no provider. The clients add
`observe_pre_entry` and `observePreEntry`.

### 8.3 Audit bundle and report `/2`

`auths.gateway-audit-bundle/2` entries add an optional `pre_entry_b64`.
`auths.gateway-audit-report/2` adds the recipe's `recovery` object to its
header and a `provider_result` to each entry:

```json
"provider_result": {
  "stage": "response-recorded", "http_status": 400, "response_digest": "<hex>",
  "observation": null, "evidence_digest": null, "refusal": null,
  "pre_entry": {"observations": 1, "verified": true}, "recount": null
}
```

`verified` keeps its meaning, authorized and entered (`audit.rs`). A refund
the provider rejected is `verified` with `http_status` 400 beside it, because
one verdict covering both authorization and acceptance is what the boundary
plan's UX contract forbids. The audit also:

- re-verifies at `evaluated-at` and recounts as §6.7 specifies;
- reports an authorized entry the gateway refused with the outcome's
  `refusal`, instead of `audit.gateway-not-entered`;
- for a `pre_entry` recipe, requires each entered entry's observations to
  digest to `pre-entry-digest`, verify under the pinned observer, carry the
  recipe's subjects built from the verified arguments, have `observed_at` in
  `[evaluated-at, evaluated-at + 60]`, and satisfy the selected requirements
  through the same predicates (`audit.pre-entry-missing`,
  `audit.pre-entry-invalid`, `audit.pre-entry-unsatisfied`, all
  `inconsistent`).

### 8.4 Offline echo verification

```text
auths-gateway echo-verify --record <record.json> --pointer /metadata/auths_echo \
  (--bundle <bundle.json> --operation-id <id> | \
   --namespace <ns> --operation-id <id> --action <action.cbor>)
```

The command reads no network and no gateway state. It refuses a non-canonical
action, computes the commitment as `verify_detailed` does
(`auths.canonical-action.v1`) and the token with `echo_token`, and reads the
record (JSON, at most 1 MiB) at the pointer. It prints
`auths.gateway-echo-verification/1`: the token, `result` (`match`,
`mismatch`, or `absent`), the record's SHA-256, the pointer, and "a match
shows the record is consistent with this action; it does not show who wrote
it". It exits 0 only on `match`. The codes are `gateway.echo-verify.match`,
`.mismatch`, `.absent`, `.record-invalid`, `.action-invalid`, and
`.pointer-invalid`. Python `auths.gateway.echo_token` and TypeScript
`echoToken` project the native function, replacing the TypeScript SDK's
shape-only check.

### 8.5 Fuzz, property, and Kani coverage

**Fuzz.** A new crate `product/runtime/auths-gateway/fuzz`
(`auths-gateway-fuzz`) is registered as `auths-bounded-policy-fuzz` is: in
`architecture.toml`, in `PRODUCT_FUZZ_TARGETS` (`xtask/src/fuzz.rs`), and in
the scheduled matrix, seeded from `bindings/fixtures/gateway/`. It depends on
the scheduled Fuzz job passing first (Epic 6 step 1).

| Target | Property |
| --- | --- |
| `target_gateway_recipe` | `compile` never panics; an accepted digest equals the digest of the re-serialized canonical source; `review` and `recovery_capability` are total |
| `target_gateway_request` | On the fixture recipes and arbitrary arguments, `closed_request_from_arguments` never panics; accepted URLs stay in the origin with no query or fragment and the recipe's segment count; bodies stay in bound; form keys are the recipe's plus the echo; the token and the key match their derivations |
| `target_gateway_attempt` | Decoding and `snapshot` never panic; `valid_transition` agrees with §4.3 on any two records |
| `target_gateway_outcome` | `verify_outcome` never panics, accepts only canonical bytes from the pinned test observer, and every accepted fact set matches §8.1 |
| `target_gateway_app_frame` | Application and admin frame parsing never panic and accept only the closed schemas |

**Property tests** (proptest):

- key order never changes a digest;
- the echo token and the idempotency key are injective over their
  NUL-separated inputs, and the key ignores the commitment;
- every verified path value decodes back from its segment and never adds `/`;
- a model-based test runs random claims, crashes, responses, timeouts,
  read-backs, replays, `reobserve`, and restarts against both stores and a
  pure model: at most one write per logical operation, terminal stages never
  change, and `not-entered` never follows a write;
- random delegation trees submitted by two engines on one store never exceed a
  link's count and leave no slot behind a refusal;
- every reachable record's outcome facts round-trip through signing and
  verification.

**Kani** harnesses, exhaustive over their finite domains, cover
`stage_transition_allowed`, `recovery_capability`, the §8.1 presence rule, and
`chain_counts_admit` for up to four counters. They join the Kani closure, so
the planner schedules them when it changes.

### 8.6 Codes and identities

Gateway codes live in their owning Rust enums (`GatewayRecipeError`,
`ReserveRefusal`, and the engine, admin, audit, and echo-verify code
functions). `bindings/fixtures/gateway/codes.json` (`auths.gateway-codes/1`)
lists every code with its owner, stage, and a fixture case that produces it,
and `gateway_codes_inventory_is_closed` fails on any code or case the two
sides do not share.

Every new identity MUST be registered in the gateway's `compliance.toml`
entry, with its test evidence, in the change that introduces it:

| Kind | Identities |
| --- | --- |
| Recipe | `auths.gateway-recipe-source/2`, `auths.gateway-compiled-recipe/2`, `auths.gateway-recipe-review/2`, `auths.gateway-recovery-capability/1` |
| Store | `auths.gateway-attempt/3`, `auths.gateway-bounded-count/2`, `auths.gateway-connection/1`, `auths.lifecycle.postgresql/5` |
| Policy | `auths.gateway.argument-ceiling-window-count/2`, `auths.gateway-counter-set/1` |
| Evidence | `auths.gateway-pre-entry/1`, `auths.gateway-outcome/2`, `auths.gateway-observe/2`, `auths.gateway-audit-bundle/2`, `auths.gateway-audit-report/2`, `auths.gateway-echo-verification/1`, `auths.gateway-codes/1` |
| Operator | `auths.gateway-operator-attestation/1`, `auths.gateway-installation/3`, `auths.gateway-admin-request/1`, `auths.gateway-admin-response/1` |

## 9. Store contract

### 9.1 Record kinds

The store stays a mechanism over opaque bounded bytes; the gateway owns every
format.

| Kind | Key (SHA-256 of) | Record |
| --- | --- | --- |
| `attempt` | `auths.gateway-logical-operation/1`, NUL, namespace, NUL, operation ID (unchanged) | `auths.gateway-attempt/3` |
| `count-slot` | §6.2 | `auths.gateway-bounded-count/2` |
| `connection` | §7.3 | `auths.provider-connection/1` |

Every record is at most 262 144 bytes, the connection record's maximum under
AP-SPEC-040 §7.4. `MAX_GATEWAY_ATTEMPT_BYTES` in
`product/stores/auths-stores/src/gateway_attempt.rs` becomes that value.

### 9.2 Trait

`GatewayAttemptStore` keeps `load` and `replace`, and gains:

- `insert(kind, key, record, expires_at)`, with `expires_at` present exactly
  for `count-slot`;
- `insert_all(entries) -> Inserted | Exists { index }` over entries of the
  same four values, all or none;
- `sweep_expired(now, limit) -> deleted`, for `count-slot` only.

Every method fails closed and never reports unreadable state as absent.

### 9.3 File store

`FileGatewayAttemptStore` names files by kind (`claim-`, `slot-`, `conn-`,
then the hex key and `.json`). Mutations hold the existing host-wide exclusive
`flock` on `.replace.lock`, and loads hold it shared. Under the exclusive
lock, `insert_all`:

1. checks that no target exists;
2. writes `.batch.json`, listing each target and its bytes, and syncs it and
   the directory;
3. creates each target without clobbering, and syncs the directory;
4. deletes `.batch.json`, and syncs the directory;
5. returns.

Because every mutation holds the exclusive lock, at most one batch exists. At
`open`, before every mutation, and before every load, a process checks for
`.batch.json`. If it exists, the process takes the exclusive lock, deletes each
listed target whose bytes equal the listed bytes, deletes the batch file, and
continues. Rolling back is sound because `insert_all` returns only after step
4 is durable, so a batch file means the engine never received the claim and
nothing was leased or sent.

### 9.4 PostgreSQL schema 5

`auths.lifecycle.postgresql/5` replaces `/4`; a `/4` database is refused, not
migrated. `auths_gateway_attempts` is replaced by:

```sql
CREATE TABLE auths_gateway_records (
    record_key BYTEA PRIMARY KEY CHECK (octet_length(record_key) = 32),
    record_kind TEXT NOT NULL CHECK (record_kind IN ('attempt', 'count-slot', 'connection')),
    expires_at BIGINT NULL,
    record_bytes BYTEA NOT NULL CHECK (octet_length(record_bytes) BETWEEN 1 AND 262144),
    record_sha256 BYTEA NOT NULL CHECK (octet_length(record_sha256) = 32),
    CHECK ((record_kind = 'count-slot') = (expires_at IS NOT NULL))
);
CREATE INDEX auths_gateway_records_expiry
    ON auths_gateway_records (expires_at) WHERE record_kind = 'count-slot';
```

`insert_all` is one transaction that inserts in ascending key order, each row
with `ON CONFLICT DO NOTHING RETURNING record_key`. A missing row rolls the
transaction back and reports that entry's index, and the fixed order prevents
deadlock. `sweep_expired` deletes at most `limit` rows through the expiry
index. The pool and statement timeout are the lifecycle store's
(`PostgresStoreConfig`).

### 9.5 Conformance

The suite both stores already run (`file_store_passes_attempt_store_conformance`
and `postgres_store_passes_attempt_store_conformance` in `engine.rs`) adds:

- `insert_all` all or none under two racing processes;
- a crash at every step of the file batch;
- sweep bounds;
- shared-connection-record visibility across two processes.

The PostgreSQL variants run in the PostgreSQL lifecycle workflow, as today.

## 10. Stable codes

Codes marked "recorded" appear as an attempt's `refusal`; codes marked
"before claim" return `not-entered` with nothing stored.

| Code | Where |
| --- | --- |
| `gateway.recipe.invalid-provider-header`, `.invalid-credential-guard`, `.invalid-idempotency`, `.response-locator-conflict`, `.invalid-pre-entry` | compile |
| `gateway.idempotency.window-exceeds-retention`, `gateway.policy.too-many-bounds`, `gateway.pre-entry.requirement-missing`, `gateway.pre-entry.observer-unavailable`, `gateway.connection.credential-generation-missing`, `gateway.trust.observer-key-in-authority-chain` | before claim |
| `gateway.policy.count-unavailable` | before claim, after 32 contended rounds |
| `gateway.policy.window-exhausted` | recorded, atomically with the claim |
| `gateway.pre-entry.condition-false`, `gateway.pre-entry.unavailable`, `gateway.credential.mode-guard`, `gateway.attempt.entry-deadline`, `gateway.transport.not-entered` | recorded |
| `gateway.trust.key-aliased` | install and serve |
| `gateway.install.operator-attestation-required`, `.operator-attestation-invalid`, `.credential-guard`, `.credential-probe`, `.connection-exists`, `.join-record-missing`, `.join-commitment-mismatch` | install |
| `gateway.serve.descriptor-limit`, `gateway.serve.accept-failed` (logged) | serve |
| `gateway.admin.peer-refused` (logged), `.status`, `.reobserved`, `.generation-conflict`, `.credential-guard`, `.credential-probe`; `gateway.reobserve.not-observable` | admin |
| `gateway.observer.credential-guard` | observe |
| `audit.counters-mismatch`, `.bound-exceeded`, `.pre-entry-missing`, `.pre-entry-invalid`, `.pre-entry-unsatisfied` | audit |
| `gateway.echo-verify.match`, `.mismatch`, `.absent`, `.record-invalid`, `.action-invalid`, `.pointer-invalid` | echo-verify |

Four existing codes change meaning:

| Code | Today | After this spec |
| --- | --- | --- |
| `gateway.policy.count-unavailable` | A store failure during reservation; the claim is recorded `not-entered` | 32 contended rounds, nothing stored; a store failure is `gateway.attempt.unavailable` |
| `gateway.connection.changed` | Refused before the claim | Also recorded after the claim, at steps 8 and 11 |
| `gateway.credential.unavailable` | Returned for a lease failure and for a write that failed before network entry | Recorded for a lease failure only; the other case is `gateway.transport.not-entered` |
| `gateway.policy.window-exhausted` | Recorded after a separate claim insert | Recorded in the same atomic step as the claim |

## 11. Formal obligations

- **Lean.** §6.6's model changes and theorems are registered in
  `formal/assurance-manifest-v1.toml` under new claim identifiers, with claim
  text that says "fixed window" and "a link's count bounds its subject and
  delegates". The translated `chain_counts_admit` leaf and its refinement
  theorem are `qualified`, citing the translation and the source closure.
  Axioms stay `propext`, `Quot.sound`, and `Classical.choice`.
- **Kani.** The four harnesses of §8.5.
- **Residual assumptions,** recorded in the manifest and the claim ledger:
  store atomicity and linearizability, the unauthenticated gateway clock, and
  provider behavior.

## 12. Owner decision: the single provider-write path

**Decided 2026-09-27: option A.** The gateway becomes the single
provider-write path, and epic 8 retires the hand-built local-agent effect
profiles. The table keeps option B as the record of what was not chosen. Its
A column is the list of what production gives up, and every other section
stands as written.

The local agent (`product/runtime/auths-node`) serves five effect profiles,
all `unqualified` in
`product/runtime/auths-node/src/generated/profile_launch_projection.json`, so
none runs in production: `auths.stripe.refund/1`,
`auths.postgresql.bounded-update/1`, `auths.postgresql.update-preflight/1`,
`auths.opentofu.saved-plan-apply/1`, and `auths.opentofu.plan-preflight/1`.

**Why consolidation is recommended.** The public record shows defects
clustering in mechanisms each vertical re-implements and the gateway
centralizes: #145 (Stripe refund recovery), #147 (receipt clocks in the
PostgreSQL and OpenTofu verticals), and #160 (provider clients' proxy and
redirect settings). The north star already runs on the gateway, and no
vertical is qualified, so consolidating loses no qualified claim.

| Topic | A: consolidate | B: keep both |
| --- | --- | --- |
| Production writes | HTTPS provider writes go only through the gateway; the Stripe refund becomes §3.1's recipe | Two paths and two Stripe stacks |
| Local-agent effect profiles | All five removed in one cutover (routes, the journal executor's effect path, their generated clients, and their connection administration), with no switch | Kept. Each mechanism this spec centralizes (recovery records, hardened clients, shared connection state, §7's operator plane, key-identity separation) MUST reach the local agent before any profile is qualified |
| Domain crates | Pure evaluators, fixtures, Kani harnesses, and demos stay as test-only references (plan, "Phase 1" and "Domain to shared product") | Unchanged |
| PostgreSQL and OpenTofu | Not HTTP, so no gateway equivalent. Their production paths end, and with them the PostgreSQL serializable row-version write and OpenTofu's stale-plan refusal | Unchanged |
| Stripe checks | Production loses or only partly keeps: relative ceilings (012 §5 basis points over payment evidence; the gateway has absolute ceilings, and 060 has no arithmetic); account-substitution checks (the vertical binds the account at onboarding and at every lease; a recipe probe compares one field at onboarding only); the restricted-key guard (a recipe prefix can require `rk_test_`, but nothing checks the key's scopes); Connect scope (012 §7; the header registry has no `Stripe-Account`); amount-sum budgets (§6.9) | Kept in the vertical |
| Architecture documents | The boundary plan's vertical-package rule and its ADR 0012 paragraph, and ADR 0012's decision and consequences, are rewritten: production writes become data-only recipes; verticals stay the source of reviewed semantics and evidence but not the production executor; and ADR 0013 states whether and how a recipe earns a qualified claim. AP-SPEC-040 is superseded for provider writes, and AP-SPEC-041–044 and AP-SPEC-038 Epic 6 move to gateway recipes | Unchanged |
| Authoring paths | Two (self-hosted adapter, gateway recipe), compared in the developer docs | Three, compared on one page by credential isolation, schema, recovery, and qualification |
| Spend limits | The gateway bound only | Independent per path (§6.9) |

## 13. Readings and decisions (PROVISIONAL)

Board rule 8: each pick is the narrower reading (fail closed, smaller claim)
unless noted, and none widens a claim or a credential scope. §12 is an owner
decision (option A, 2026-09-27) and is not listed.

| # | Question | Readings | Pick |
| --- | --- | --- | --- |
| 1 | The owner's text says status and digest "become signed fields of `auths.gateway-outcome/1`" | (a) add facts to `/1`; (b) bump to `/2` and remove `/1` | (b): the fact set changes meaning, so requirements and clients expecting `/1` fail closed |
| 2 | A slot whose attempt later records `not-entered` | (a) stays consumed; (b) released | (a): release widens |
| 3 | The operation ID of a window-exhausted submission | (a) consumed; (b) left free | (a), as today |
| 4 | Collecting claims | (a) never; (b) by age | (a): (b) reopens logical operations |
| 5 | An idempotency recipe whose action window plus 60 seconds exceeds its retention | (a) refused; (b) admitted with the gap published | (a) |
| 6 | A `pre_entry` recipe with no selected requirement | (a) refused; (b) written without a re-read | (a) |
| 7 | Admin authorization | (a) the peer check; (b) signed commands | (a): signed kill switches could be blocked by custody unavailability, which fails open |
| 8 | Key identity in the kernel | (a) gateway checks only; (b) change the kernel now | (a): a kernel change needs Go and TypeScript parity |
| 9 | What a response locator stores | (a) the value; (b) the response body | (a) |
| 10 | Recipe source schema | (a) `/2` with re-approval; (b) optional fields in `/1`, as #156 did | (a): the idempotency field and the echo rule change the grammar |
| 11 | Fixed or rolling windows (the owner delegated the pick) | (a) fixed, epoch-aligned; (b) rolling | (a): it matches the code, `window_index`, the Lean model, and settled.md, makes the smaller claim, and lets slots expire at a known time |

## 14. Conflicts with committed documents

Each amendment lands with the code that causes it.

| Document | Conflict | Resolution |
| --- | --- | --- |
| 053 §1 | First scope: one write plus an optional read-only observation per operation | `/2` adds at most one pre-entry read per submission and one probe per onboarding, both read-only and gateway-performed |
| 053 §3 | The first installation may run offline | A recipe with a probe needs egress at `install`, `install --join`, and `rotate`, and a join reads the shared store; recipes without a probe keep the offline first install |
| 053 §3.2 | Path segments only from verified fields; a fixed header allowlist | `response-field` segments from the recorded response (§4.1); the version-header registry (§5.1) |
| 053 §3.3 and its Epic 3 acceptance | The ordered path claim → credential → transport, and its acceptance cases | The path becomes §5.5, with the reloads, the atomic slots, and a pre-entry read between credential and transport. Epic 3's acceptance gains the pre-entry, guard, and shared-record cases. `unknown` still resolves only through provider evidence |
| 059 §3.2 | JSON-only echo | Form placement (§5.4); the echo stays the only added body value |
| 059 §7.1 | Re-observation only by replay, from a locator fixed at claim; a stored `attempting` record never re-observed | Also by admin `reobserve`; response locators fixed at response time; `attempting` re-observable for `linked` recipes (§4.3) |
| 060 §14 reading 4 | Outcome facts `commitment` and `stage` | §8.1 |
| 025 §25 readings 5, 7, and 10 | The count per actor, reserved after the claim, keyed to the bounded branch's actor | Superseded by §6 |
| Board §4, 2026-09-24, readings 1 and 4 | (1) The count keyed to the bounded branch's actor; (4) the audit evaluated at the outcome's signing time and recounted in that order | (1) Keyed to each link's subject; (4) evaluated at `evaluated-at`, with §6.7's order-free test |
| #156 | The boolean `write.idempotency_key`; its state-loss journey | The object form of §4.1. The journey stays valid, since a wiped store forgets claims and counts (§1), once its approval window fits §4.5's retention rule |
| settled.md | "Stripe metadata doesn't carry an action-derived echo"; single-host connection state | Scoped to `auths-stripe`, because the gateway recipe gains a form echo with the same non-claims; connection state is shared through the store |
| ADR 0012 and the boundary plan | — | Rewritten in epic 8, under §12's decision (option A) |
| Board rule 3 | Specs are written when an epic starts | The owner directed this one ahead, as with 059–061 (board §4, 2026-09-22) |

## 15. Epics and done gates

Order: 1, 2, 3, then 4 and 5 in either order, then 6, then 7, then 8 (§12
option A). Board rules 1, 2, 7, and 10 apply. Done means an artifact: hosted CI
on the exact revision, or a commit whose diff holds the evidence.

| Epic | Work | Done |
| --- | --- | --- |
| 1. Case file and fixtures | ADR 0013 and the case 0007 comparisons (§2); hostile recipe cases for every new construct; attempt scenarios `/3`, including `pre-entry-replaced-after-observation`; `bounds-aggregate.json`, `outcome-v2.json`, `key-identity.json`, and `codes.json` | The vectors exist and fail against current code; the ADR and case file are reviewed |
| 2. Recipe `/2` | The compiler, `recovery_capability`, and review `/2` in both CLIs; derivation emits `/2`; the fixtures, north-star recipe, and derivation corpus are regenerated | Every fixture compiles to its documented class; every hostile case fails with its code; both packaged CLIs pass the corpus |
| 3. Store and engine | §9 (kinds, `insert_all`, sweep, the file batch, schema 5, record `/3`); the §5.5 steps marked 3; re-observation of `attempting` | Conformance passes on both stores (PostgreSQL in its workflow); the scenario corpus drives the counting provider; every hostile suite has zero unauthorized entries, and every pre-claim refusal zero leases |
| 4. One spend limit | Formal first (the Lean model, theorems, and translated leaf, with `cargo xtask formal` green); then evaluator `/2`, the slot part of §5.5 step 6, §6.5's sweep, §6.7, and every §6.4 description | `bounds-aggregate.json` passes on both stores, including the race; no slot leaks; the audit flags the capacity-3 and capacity-1 bundle and passes every valid one |
| 5. Operator plane | §7, and the §5.5 steps marked 5 | With the application at full capacity, every admin command answers within its deadline; a disable or revoke through process A stops new entries in process B at B's next reload, on PostgreSQL; a second host joins only with the matching secret; `did:key` and `raw-key-v1` aliasing is refused at install and per proof; an invalid attestation is refused |
| 6. Evidence and assurance | Step 1: repair the scheduled Fuzz job (`.github/workflows/fuzz.yml`) so a scheduled campaign can pass, with a unit test on a captured libFuzzer log. Then §8: outcome `/2` and its consumers, observe `/2`, audit `/2`, `echo-verify`, the SDK projections, the fuzz crate, property tests, Kani harnesses, and the code inventory | A scheduled Fuzz run is green with the gateway targets; Rust, Python, and TypeScript agree on `outcome-v2.json`; the north-star audit shows `http_status` for every entered refund, including a rejected one |
| 7. North-star recipe | The Stripe recipe moves to §3.1 with an approval window of at most 86 340 seconds; the counting double returns refunds with metadata, requires `Stripe-Version`, and honors the key; `journey.py` checks `observed-by-provider` and the guard refusing a non-test key; the README non-claims and the claim ledger are updated; the test-mode command stays the developer's own step (board §0 step 4) | `stripe-refund-journey` is green from the packed wheel; the ledger entry uses §1's claim and non-claim wording |
| 8. Consolidation | §12 A's removals and rewrites in one pull request | The profiles and routes are gone; the specs, ADRs, and plan are amended, and `AGENTS.md`'s summary of the boundary plan is checked against the rewrite; the board is updated; CI is green |

## 16. Non-goals

| Non-goal | Reason |
| --- | --- |
| A conditional provider write | Profile-owned, and settled |
| Automatic retry or re-entry after `unknown`, even within a declared retention | Safe retry is provider semantics (053 §7; plan, "What must not be shared early") |
| Recording an operator's resolution of `unknown` | An out-of-band finding is an assertion the gateway cannot check, and recording it beside provider evidence in the signed outcome would blur the two. Outside `linked`, `unknown` is the honest terminal answer (053 §3.3) |
| Fencing or detecting a lost or restored store | Reinstalling under a new namespace voids every earlier action (§4.5); the count reset is a stated non-claim |
| Amount-sum budgets in the gateway | Release on proven non-effect needs provider-specific recovery evidence the gateway does not qualify; ceiling times count already caps spend per link and window |
| Rolling windows | They need timestamped slots counted under a per-counter lock, a new evaluator, and a new Lean model |
| A non-HTTP transport (the PostgreSQL wire protocol, process execution) | A different mechanism, needing its own ADR and case file |
| Webhook ingress | A new credential and deployment surface (059 §3.5) |
| Query segments, pagination, and search locators | Board §3 keeps these for the vendor corpus's measured needs; response locators cover creates whose ID is in the response |
| Kernel key identity; observer quorum | The kernel change alters verdicts and needs Go and TypeScript parity; 060 §16 is demand-gated |
| Credential-store encryption at rest | An owner decision under 038 §9 (#148) |
| Custody clients in the binary | 038 Epic 4. Until then production signs no outcomes, so every authorized entry audits as `refused` with `audit.outcome-missing`, and `pre_entry` recipes are refused |
| Audit completeness, recipe qualification, human gates | The store is the complete record; qualification needs its own review (§12); 038 §9.3 and board §0 |

Review fixes that need no design, such as asynchronous DNS in the transport,
doctor checks, and the "qualified" wording for the PostgreSQL store, go to fix
pull requests rather than this spec.

## 17. Verification and release boundary

Hosted CI on the exact revision is the gate; this spec runs no checks and
asserts no outcome. Until Epic 6 is green, no document may say the audit shows
the provider's response. Until Epic 4 is green, no document may say a parent's
count bounds its delegates. Until Epic 5 is green, no document may say admin
changes reach every process. Until Epic 7's ledger entry exists, no document
may say refunds made through the gateway carry a provider link.
