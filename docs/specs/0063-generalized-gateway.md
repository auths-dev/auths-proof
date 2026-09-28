# AP-SPEC-063: The generalized gateway: recovery capability, provider capabilities, one spend limit, operator plane, and evidence

- **Status:** Draft, written on owner direction on 2026-09-25 before its epic
  starts. Nothing here is implemented except what #166 and #168 merged on
  2026-09-26: §5.5 step 7, part of §7.1, and Epic 6 step 1. Writing it does
  not start an epic, and the WIP limit (program board rule 1) still governs
  implementation. §13's readings are PROVISIONAL until the owner reviews
  them. On 2026-09-27 the owner chose §12 option A: the gateway becomes the
  single provider-write path. On the same day the owner decided that
  production keeps the `auths-stripe` vertical's five checks, as the
  provider-neutral capabilities of §5.6–§5.9 and §6.10. This change adds this
  file and its program board entries.
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
  `auths.gateway.argument-ceiling-window-count/1` and policy type
  `auths.gateway.argument-ceiling-policy/1`; connection record
  `auths.provider-connection/1`; declared operator principals; and, under
  §12's decision, the five local-agent effect
  profiles.
- **Scope:** product layer only: `product/runtime/auths-gateway`,
  `product/stores/auths-stores`, `product/policy/auths-bounded-policy`,
  `product/tools/auths-openapi-derive`, `auths-node gateway recipe check` in
  `product/runtime/auths-node`, the connection record in
  `product/runtime/auths-connections` (§7.3), the Python and TypeScript
  gateway clients,
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
  re-read, and a provider-held link to the action. Under §12's decision it
  would also lose five checks the vertical makes: a ceiling relative to
  payment evidence, the account binding at every lease, a check on the key's
  permissions, the Connect account scope, and amount-sum budgets.
- Window counts are kept per actor, so delegation multiplies a parent's count.
- The operator plane needs admin mutations that never wait on provider calls,
  connection state that holds in every process sharing a store, separation
  checks that compare keys, and an authenticated operator. Its own capacity
  and deadlines, which the review also found missing, merged in #166 (§7.1).
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
| 2 | Capabilities the Stripe vertical proved necessary, including the relative ceiling, the lease-time account binding, denied reads, and account-scope headers | §5 |
| 3 | One spend limit: a count and a sum budget that delegation cannot multiply | §6 |
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
  over those actions. A grant that also carries a sum limit bounds that sum
  directly, per declared partition value, and the grant lists every partition
  value it allows.
- For a recipe that declares them, the gateway sends no write unless, after
  the lease: the credential still resolves to the connection's account; each
  declared denied read was refused with a declared status; and the bounded
  argument is at most the declared basis points of the integer just read from
  the provider. An account-scope header carries only a value the grant lists,
  and a recipe that declares none never sends one.
- Admin mutations commit without waiting for provider calls and reach every
  process sharing the store at that process's next reload.
- The offline audit shows the provider result beside `verified`, which still
  means authorized and entered.
- The admission order, the relative ceiling, the count and sum bounds,
  recovery transitions, the credential-generation rule, and request
  construction are machine-checked against Lean models over every trace,
  under §11.7's residual assumptions.

**Not a claim.**

- Provider effect, acceptance, or settlement (053 §3.3).
- Authorship. The echo is unkeyed and shows consistency, not who wrote a
  record (059 §1).
- Observer honesty. Observer trust is operator trust.
- A conditional write. A pre-entry re-read or a relative-ceiling read narrows
  the window; it does not close it.
- That a credential lacks any permission beyond the refusals observed. A
  denied read shows only that the declared requests were refused at that
  lease.
- That the provider's basis value or account identity is still current at
  the write.
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
| Relative ceiling (§5.6) | One integer read at one pointer, optionally minus a second, and one exact integer comparison | 012 §5; `RelativeRefundLimit` and the basis-point check in `product/integrations/auths-stripe/src/bounded.rs` | Which record and pointer are the basis, and what the ratio means |
| Account binding at every lease (§5.7) | One JSON string read, hashed under the install's account domain and compared in constant time | `verify_account_response` (`onboarding.rs`); the `account_commitment` lookup in `lease_credential` (`credentials.rs`) | What an account is |
| Denied reads (§5.8) | Up to four safe requests whose status must be in a declared set | 012 §13's restricted credential; the vertical checks only the `rk_test_` prefix (`valid_static_secret`) | Which permissions a key should lack |
| Account-scope headers (§5.9) | A second registry class whose value is a grant-listed verified field | 012 §7; `ConnectScope` (`bounded.rs`); `MerchantConnectAccount` (`product/integrations/auths-stripe/src/merchant/policy.rs`) | What the account context means |
| Recovery capability (§4) | Derived from the declarations | 059 §3.3; the claim ledger's Todoist limit | — |
| Aggregate counts and sums (§6, §6.10) | New evaluator identifier and policy type (025 §6) | 025 §24–§25; 012 §6; `AggregateRefundBudget` (`bounded.rs`) | Release on proven non-effect; rolling windows |
| Operator plane (§7) | Runtime mechanism | `serve`, `admin_session` (`product/runtime/auths-gateway/src/bin/auths-gateway.rs`); `separation.rs`; 038 §9.2 | — |
| Outcome and audit `/2` (§8) | Evidence record, not a qualified receipt (053 §3.3) | Board §0 step 2; `audit.rs` | Settlement meaning |

The ten recipe capabilities each rest on fewer than three merged consumers
across two domains; the four of §5.6–§5.9 rest on `auths-stripe` alone. Each
is therefore a smaller promotion that needs an ADR (plan, "Domain to shared
product"). Epic 1 writes ADR 0013, which amends ADR 0012 for all ten and for
§6.10's sum budget, and adds each comparison to case 0007. A reviewer may
reject any one of them without blocking the others; rejecting one of the five
Stripe checks reopens §12's row for it.

## 3. Recipe source `/2`

### 3.1 Shape

The north-star Stripe recipe after Epic 7 shows most new fields, including
the five Stripe checks (§5.6–§5.9, §6.10). The header values, probe and read
endpoints, pointers, refused statuses, ratio, and retention are examples the
author confirms against the provider's documentation; this repository makes
no provider calls. The recipe declares no `pre_entry`, for the reason in
§5.3. Its profile gains the fields `connect_account` and `currency`.

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
      "prefixes": ["rk_test_"],
      "probe": {
        "path": [{"kind": "fixed", "value": "v1"}, {"kind": "fixed", "value": "balance"}],
        "json_pointer": "/livemode",
        "equals": false,
        "maximum_response_bytes": 16384
      },
      "account": {
        "path": [{"kind": "fixed", "value": "v1"}, {"kind": "fixed", "value": "account"}],
        "json_pointer": "/id",
        "maximum_response_bytes": 65536
      },
      "denied_reads": [
        {"method": "GET", "path": [{"kind": "fixed", "value": "v1"}, {"kind": "fixed", "value": "customers"}], "refused_status": [403]},
        {"method": "GET", "path": [{"kind": "fixed", "value": "v1"}, {"kind": "fixed", "value": "payouts"}], "refused_status": [403]}
      ]
    }
  },
  "origin": "https://api.stripe.com",
  "provider_headers": {"Stripe-Version": "<pinned version>"},
  "account_scope": {"header": "Stripe-Account", "field": "connect_account"},
  "bounds": {"sum": {"argument": "amount", "partition": "currency"}},
  "relative_ceiling": {
    "argument": "amount",
    "basis_points": 5000,
    "path": [
      {"kind": "fixed", "value": "v1"},
      {"kind": "fixed", "value": "payment_intents"},
      {"kind": "field", "name": "payment_intent"}
    ],
    "json_pointer": "/amount_received",
    "bind": [{"pointer": "/currency", "field": "currency"}],
    "maximum_response_bytes": 65536
  },
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
| `credential` | yes | As `/1`; a `header-api-key` header may not be `Idempotency-Key` or any name in §5.1's registry | `gateway.recipe.invalid-credential` |
| `credential.guard.prefixes` | with `guard` | 1–4 unique strings of 1–32 bytes in `0x21..=0x7e` | `gateway.recipe.invalid-credential-guard` |
| `credential.guard.probe` | no | `path` of 1–16 `fixed` segments; `json_pointer` under the observation pointer rules; `equals` a JSON string of at most 256 bytes, an integer of magnitude at most 2^53 − 1, or a boolean; `maximum_response_bytes` 1–65 536 | `gateway.recipe.invalid-credential-guard` |
| `credential.guard.account` | no | `path` of 1–16 `fixed` segments; `json_pointer` under the observation pointer rules; `maximum_response_bytes` 1–65 536 (§5.7) | `gateway.recipe.invalid-credential-guard` |
| `credential.guard.denied_reads` | no | 1–4 entries; `method` exactly `GET` or `HEAD`; `path` of 1–16 `fixed` segments, unique among the entries and unequal to the probe path, the account path, and every declared path made only of `fixed` segments; `refused_status` 1–3 unique integers in 400–499 other than 408 and 429 (§5.8) | `gateway.recipe.invalid-credential-guard` |
| `provider_headers` | no | At most 2 entries, each a `version`-class name of §5.1's registry with a value its grammar allows; an `account-scope` name is refused here | `gateway.recipe.invalid-provider-header` |
| `account_scope` | no | `header` an `account-scope`-class name of §5.1's registry; `field` a top-level string field of the profile schema that no body, path, or other header consumes (§5.9) | `gateway.recipe.invalid-account-scope` |
| `bounds.sum` | no | `argument` a top-level integer field that the write body consumes; optional `partition` a top-level string field, unequal to `argument`, that the write body or the account-scope header consumes or a `relative_ceiling.bind` entry names (§6.10) | `gateway.recipe.invalid-bounds`, `gateway.recipe.unbound-partition` |
| `relative_ceiling` | no | `argument` a top-level integer field that the write body consumes; `basis_points` an integer in 1–10 000; `path` of 1–16 `fixed` or `field` segments under the write path's rules; `json_pointer` and optional `subtract_pointer`, distinct, under the observation pointer rules; `bind` of 0–2 entries with distinct pointers under the same rules, each naming a top-level profile field other than `argument`; `maximum_response_bytes` 1–65 536 (§5.6) | `gateway.recipe.invalid-relative-ceiling`, `gateway.recipe.unsafe-path` |
| `write.path` | yes | As `/1`; no `response-field` segment | `gateway.recipe.response-locator-conflict` |
| `write.idempotency` | no | §4.1; `retention_seconds` 1–2 592 000; an `operation-id-field` location must resolve to a field reference to `operation_id` | `gateway.recipe.invalid-idempotency` |
| `observation.path` | with `observation` | As `/1`, plus at most 2 `response-field` segments, each with an observation pointer and `max_bytes` 1–255 | `gateway.recipe.response-locator-conflict` |
| `echo.write` | with `echo` | `{"kind": "json-pointer", "pointer": ...}` for a JSON body (059 §7.1) or `{"kind": "form-field", "name": ...}` for a form body (§5.4), matching the body; `echo` still requires `observation` | `gateway.recipe.echo-conflict`, `gateway.recipe.echo-without-observation` |
| `pre_entry` | no | `path` of 1–16 `fixed` or `field` segments under the write path's rules; 1–4 unique `pointers` under the observation pointer rules; `maximum_response_bytes` 1–65 536 | `gateway.recipe.invalid-pre-entry`, `gateway.recipe.unsafe-path` |
| `preconditions.read_back_subject` | no | As `/1`; refused when the observation path has a `response-field` segment | `gateway.recipe.precondition-conflict` |

Every profile field is still consumed, now by the write, the observation, the
pre-entry path, the preconditions, the account-scope header, or a
relative-ceiling path or `bind` entry (`gateway.recipe.unsafe-template`
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
- the account read and denied reads, with "run at onboarding and at every
  lease; a denied read shows only the refusals observed";
- the account-scope header and its field, with "sent only with a value the
  grant lists";
- the relative ceiling as `argument ≤ floor(basis × basis_points / 10 000)`,
  its basis and bind pointers, and the sum requirement with its partition;
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
| `counters` | The sorted `{kind, counter, slot}` entries reserved with the claim, `kind` `count` or `sum` (§6.3, §6.10) |
| `response_status`, `response_digest` | As `/2` |
| `response_locator` | For a `response-locator` recipe after a qualifying response: pointer → value |
| `observation_plan` | Resolved segments, unresolved `response-field` pointers, the canonical expected value, and the echo flag; fixed at claim |
| `observation_match`, `observation_fact`, `provider_evidence` | As `/2` |
| `pre_entry` | Up to four signed pre-entry observations and their digest (§5.3), and the relative-ceiling basis `{value, response_digest, read_at}` when one was read (§5.6) |

A record whose fields contradict its stage is `Corrupt`, as
`stage_fields_consistent` enforces for `/2`. The worst case is about 136 KB
(87 KB evidence, 22 KB pre-entry observations, 27 KB locators and expected
value, all encoded), so both stores raise the record bound to 262 144 bytes
(§9.1).

`valid_transition` in `store.rs` becomes this closed table, checked
exhaustively by Kani (§8.5):

| From | To | Condition |
| --- | --- | --- |
| `attempting` | `attempting` | Once, before transport entry, adding only `pre_entry` (observations and basis together) |
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

§5.1–§5.4 carry the vertical's request mechanisms. §5.6–§5.9, with §6.10's
sum budget, keep in production the five checks that §12 option A would
otherwise remove (012 §5–§7). Each check is recipe data that the author
writes, the compiler bounds (§3.2), the review shows (§3.4), and the operator
approves by digest. The gateway compares bytes, integers, and HTTP statuses,
and interprets no provider field. §5.5 places every check in the submission
order.

Requests are of two kinds. **Credential reads** (the probe, the account read,
and denied reads) test the credential and carry no action value. **Action
reads** (the pre-entry read, the relative-ceiling read, and the observation)
and the write carry verified action values. With every capability declared, a
submission makes at most seven reads before its write, and each later
read-back lease adds up to five credential reads (§5.7, §5.8).

### 5.1 Provider headers

The recipe-header allowlist of 053 §3.2 gains a closed registry,
`PROVIDER_HEADERS` in `recipe.rs`, with two classes:

| Name | Class | Value grammar | Response rule | Vertical |
| --- | --- | --- | --- | --- |
| `Stripe-Version` | `version` | 10–64 bytes of `[A-Za-z0-9.-]`, first byte a digit (`valid_api_version` in `product/integrations/auths-stripe/src/merchant.rs`) | Required: a response without the header, or with another value, has a version mismatch | `auths-stripe` |
| `X-GitHub-Api-Version` | `version` | Exactly 10 bytes, `YYYY-MM-DD` | None: responses are not checked | `auths-github` |
| `Stripe-Account` | `account-scope` | `acct_` then 8–59 bytes of `[A-Za-z0-9_]` (`valid_account` in `product/integrations/auths-stripe/src/types.rs`) | None: responses are not checked | `auths-stripe` |

A `version` header has a fixed value in `provider_headers`. The gateway sends
it on every request to the origin (the write, every action read, and every
credential read) and nowhere else. An `account-scope` header takes its value
from a verified action field under §5.9's rules, and is sent on the write and
every action read and never on a credential read.

A read with a version mismatch is unavailable: it is not compared, signed, or
recorded. A pre-entry read, a relative-ceiling read, or a lease-time
credential read with one refuses the submission (§5.3, §5.6–§5.8); a denied
read is no exception, although only its status is compared. A write is
recorded as usual, because the gateway never interprets a write body; a
mismatch only suppresses locator extraction. Operator approval cannot widen the registry. A new entry needs an amendment
naming its class, vertical evidence, and response rule, plus hostile
fixtures.

### 5.2 Credential-mode guard

`credential.guard` states what the author says a permitted credential looks
like.

| Check | When | Failure |
| --- | --- | --- |
| Prefix: the secret starts with a declared prefix | At onboarding (`install`, `install --join`, admin `rotate`) before the secret is stored; at every lease before any header is built | Onboarding refused (`gateway.install.credential-guard`, `gateway.admin.credential-guard`); after a claim, recorded `not-entered` with `gateway.credential.mode-guard`; an observation request refused with `gateway.observer.credential-guard` |
| Probe: one GET with the candidate secret over the pinned transport with the provider headers, passing on a complete 2xx JSON response within `maximum_response_bytes` whose pointer holds `equals` | At onboarding, after the prefix check | Onboarding refused with nothing stored (`gateway.install.credential-probe`, `gateway.admin.credential-probe`) |
| Account (§5.7) | At onboarding, after the probe; at every lease, after the prefix | Onboarding refused (`gateway.install.credential-account`, `gateway.admin.credential-account`); after a claim, recorded `not-entered` (§5.7) |
| Denied reads (§5.8) | At onboarding, after the account read; at every lease, after the account read | Onboarding refused (`gateway.install.credential-capability`, `gateway.admin.credential-capability`); after a claim, recorded `not-entered` (§5.8) |

Every onboarding read shares one 20-second deadline. Every lease-time check
also runs for a read-back, `reobserve`, or observation request lease: a
failure there makes the read unavailable, records nothing, and refuses an
observation request with `gateway.observer.credential-guard`.

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
does not exceed a share of the payment) compares two numbers, which 060's
conditions cannot do (060 §2). It also could not run in production without an
observer key. §5.6's relative ceiling makes that comparison as a gateway
refusal rule, without an observer key.

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
| 3 | Admit: bounded policy (§6.1), with the sum requirement and partition (§6.10) and the account-scope binding (§5.9); projection; retention rule (§4.5); pre-entry selection (§5.3); per-proof observer check (§7.5) | `not-entered`, nothing stored | 4; today; 3; 3; 5 |
| 4 | Load the shared connection record; require this host to hold its current credential (§7.3) | `not-entered`, nothing stored | 5 |
| 5 | Prepare the pinned transport | `not-entered`, nothing stored | today |
| 6 | Claim atomically with every count and sum slot (§6.3, §6.10); a replay goes to §4.4 | Exhausted: recorded `not-entered`; store unavailable: nothing stored | 3; slots 4 |
| 7 | Continue in a task the application connection cannot cancel; it holds the capacity permit until the final stage (§7.1) | — | today (#166) |
| 8 | Reload the shared record and require it unchanged: the re-read AP-SPEC-040 §7.4 requires immediately before credential acquisition | Recorded `not-entered`, `gateway.connection.changed` | 5 |
| 9 | Lease the credential (30-second deadline); apply the prefix guard (§5.2); when declared, the account read (§5.7), then each denied read in order (§5.8) | Recorded `not-entered` | today; guard, account, and denied reads 3 |
| 10 | When declared, run the pre-entry re-read (§5.3), then the relative-ceiling read and check (§5.6); record their observations and basis in one `attempting → attempting` | Recorded `not-entered`, keeping what was read | 3 |
| 11 | Increment the in-flight count; reload the shared record; require it unchanged | Recorded `not-entered`, `gateway.connection.changed` | 5 |
| 12 | Refuse entry after `evaluated_at + 60` seconds, on the gateway clock or the monotonic deadline started at step 1 | Recorded `not-entered`, `gateway.attempt.entry-deadline` | 3 |
| 13 | Send the one write, with provider headers, the account-scope header, the key or declared field, and the echo | Before network entry: recorded `not-entered`, `gateway.transport.not-entered` | today; account scope 2; other additions 3 |
| 14 | Record the response (status, digest, locator), or `unknown` | — | today; locator 3 |
| 15 | Decrement the in-flight count; perform at most one read-back | — | 5; today |

Steps 4, 8, and 11 read the shared connection record (§7.3); steps 8 and 11
require its exact stored bytes unchanged since step 4.

### 5.6 Relative ceiling

`relative_ceiling` bounds the verified argument by a declared ratio of one
integer the gateway reads from the provider after the lease. It keeps 012
§5's relative limit in production, with the ratio in the recipe (§13,
reading 23).

- **Read.** At step 10, after any pre-entry re-read, one GET to `path`, built
  from `fixed` segments and verified fields as the write path is (`build_path`
  in `recipe.rs`), with the version headers and the account-scope header,
  under the transport's bounds and `maximum_response_bytes`. It reuses
  §5.3's read mechanics (pinned transport, version response rule, pointer
  resolution) but not its requirement selection or observer signing, so it
  runs without an observer key (§13, reading 21).
- **Basis.** The value at `json_pointer` must be a JSON integer in
  0..=2^53 − 1, with no fraction or exponent. With `subtract_pointer`, the
  second value must meet the same rule, and the basis is the first minus the
  second. A negative difference is unavailable, never zero. The leaf
  `relative_basis(value: u64, subtrahend: Option<u64>) -> Option<u64>`, in a
  new pure module `product/runtime/auths-gateway/src/ratio.rs`, computes it.
- **Bind.** Each `bind` pointer must hold a JSON string byte-equal to the
  verified field's string, or a JSON integer equal to its integer. A bind
  ties the basis record to the action, such as its currency to §6.10's
  partition field.
- **Check.** `relative_ceiling_admits(argument: u64, basis: u64,
  basis_points: u16) -> bool` in `ratio.rs` returns
  `argument × 10 000 ≤ basis × basis_points`, computed in `u128`. Both
  products are below 2^67, so nothing overflows. The test equals
  `argument ≤ floor(basis × basis_points / 10 000)`: the ceiling rounds toward
  zero, the boundary is inclusive, and a zero basis admits only a zero
  argument (012 §5).

| Result | Stage and code |
| --- | --- |
| Every value valid, every bind equal, and the check passes | Basis recorded with any pre-entry observations (`attempting → attempting`); continue |
| Every value valid and a bind unequal | `not-entered`, `gateway.relative-ceiling.binding-mismatch`; basis recorded |
| Every value valid and every bind equal, and the check fails | `not-entered`, `gateway.relative-ceiling.above`; basis recorded |
| Transport failure, non-2xx, version mismatch, oversize, non-JSON, an absent pointer, a value outside the rules, or a negative difference | `not-entered`, `gateway.relative-ceiling.unavailable`; only the code recorded |

The basis record is `{value, response_digest, read_at}`: the basis, the
SHA-256 of the response body, and the gateway clock at the read. A signed
outcome carries the first two as `relative-basis` and
`relative-basis-digest` (§8.1). The check runs after the claim because the
read needs a lease, and a lease needs the claim (§11.2). A refused action
therefore consumes its operation ID and its count and sum slots (§13,
readings 2, 13, and 17). **Cost:** one read per submission.

012 §5's `captured-amount` denominator maps to the PaymentIntent's
`/amount_received`, which §3.1 uses. `remaining-refundable-amount` maps to a
Charge's `/amount_captured` with `subtract_pointer` `/amount_refunded`, which
needs a charge field in the profile.

**Non-claims.** The basis is what the provider returned at `read_at`, and the
write is not conditional on it. The ratio and what the basis means are the
author's, approved by the operator. The gateway records the basis itself; it
is not a 060 observation and satisfies no grant condition.

### 5.7 Account binding at every lease

`credential.guard.account` reads the credential's own account identity and
compares it with the connection record's `account_commitment`
(`ConnectionRecord::account_commitment` in
`product/runtime/auths-connections/src/model.rs`). It keeps the vertical's
lease-time account check (`lease_credential` in `credentials.rs`), and makes
it stronger by asking the provider at every lease.

- **Commitment.** `install` already sets `account_commitment` to the SHA-256
  of `auths.gateway-account/1`, a NUL byte, and `--account-label` (`install`
  in `product/runtime/auths-gateway/src/bin/auths-gateway.rs`). The account
  read hashes the value it reads the same way and compares the two 32-byte
  values in constant time.
- **Read.** One GET to `path` with the leased or candidate secret, the version
  headers, and no account-scope header. The value at `json_pointer` must be a
  JSON string of 1–256 bytes, the account label's bound.
- **When.** At onboarding, after the probe: `install` requires the read value
  to equal `--account-label`, and `install --join` and `rotate` require its
  hash to equal the record's commitment. At every lease (step 9), after the
  prefix guard and before any denied read (§13, reading 14).

| Result at a submission lease | Stage and code |
| --- | --- |
| Equal commitments | Continue |
| A complete 2xx JSON response holding a valid string whose hash differs | `not-entered`, `gateway.credential.account-mismatch` |
| Anything else | `not-entered`, `gateway.credential.account-unavailable` |

Only the code is recorded; a credential read never enters the attempt record.
**Cost:** one read per lease, so one per write and one per read-back.

**Non-claims.** It shows which account the provider reported for the
credential at that read, not at the write, and not that the identifier names
one legal entity.

### 5.8 Denied reads

Neither the vertical nor the gateway can read a key's permissions:
`valid_static_secret` (`onboarding.rs`) and `lease_credential`
(`credentials.rs`) check only the `rk_test_` prefix, and HTTP has no
provider-neutral permission introspection. `credential.guard.denied_reads`
instead declares up to four safe requests that the provider must refuse. It
replaces 012's restricted-key requirement with an observed check.

- **Requests.** One `GET` or `HEAD` per entry, to a path of `fixed` segments
  only, so no action value or agent input reaches it. It carries the
  credential and the version headers, and no account-scope header, body, or
  idempotency key. A response body is read and discarded up to 16 384 bytes
  (more is oversize) and never recorded.
- **Pass.** A complete response whose status is in `refused_status`, with no
  version mismatch (§5.1).
- **When.** At onboarding after the account read, and at every lease (step 9)
  after the account read (§13, readings 15 and 16). Entries run in
  declaration order and stop at the first failure.

| Result at a submission lease | Stage and code |
| --- | --- |
| Every entry refused with a declared status | Continue |
| An entry answered 2xx | `not-entered`, `gateway.credential.capability-excess` |
| Anything else: another status, a 3xx (never followed), transport failure, oversize, or version mismatch | `not-entered`, `gateway.credential.capability-unavailable` |

The compiler refuses 408 and 429, because a timeout or throttling status
would pass without any permission refusal. Only the code is recorded.
**Cost:** up to four reads per lease.

**Non-claims.** A pass shows only that the declared requests were refused
when made. It does not show that the key lacks any other permission, that a
refusal had a permission reason rather than another the provider maps to the
same status, or that the key's permissions did not change before the write.

### 5.9 Account-scope headers

`account_scope` names an `account-scope` header of §5.1 and the profile field
that supplies its value. It keeps 012 §7's Connect scope in production.

- **Binding.** The value comes only from the verified action field. At step
  3, the action MUST have a bounded branch (§6.1) in which every link's
  policy carries a `scope` whose argument is that field, and the verified
  value MUST be in every link's scope values (§6.10). Otherwise it is refused
  before the claim: `gateway.account-scope.unbound` when there is no bounded
  branch or a link carries no such scope, and `gateway.policy.scope-denied`
  when a link's values exclude the value (§13, reading 22).
- **Grammar.** The value must match the header's registry grammar
  (`gateway.account-scope.invalid-value`, before the claim), so it cannot
  add a header line.
- **Sending.** The header, with exactly that value, goes on the write and
  every action read, and never on a credential read, which tests the
  credential's own account (§5.7).
- **Absence.** A recipe without `account_scope` sends no `account-scope`
  header on any request, and no recipe can place one in `provider_headers`,
  the credential header, or a body (§3.2). §11.5 proves both.
- **One scope kind per recipe.** A recipe with `account_scope` always sends
  the header. A write the provider scopes by the header's absence, such as a
  Stripe platform-account refund, needs a recipe without it (§13, reading
  19).

Until Epic 4 supplies policy `/2`, no link can carry a scope, so every action
of an `account_scope` recipe is refused with `gateway.account-scope.unbound`.

**Non-claims.** The gateway shows that the header carried a value the grant
lists. What the provider does with the header is the provider's.

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
- every scope and partition a link carries lists the verified value of its
  argument (`gateway.policy.scope-denied`, `gateway.policy.partition-denied`;
  a missing or malformed value is `gateway.policy.argument-unavailable`);
- when the chain carries sum limits, the verified argument is at most the
  smallest (`gateway.policy.above-sum-limit`); a recipe that declares
  `bounds.sum` also requires every link to carry a sum limit with the
  recipe's argument and partition (`gateway.policy.sum-required`, also for
  an action with no bounded branch) (§6.10);
- one slot is reserved, all or none and with the claim, in the counter of
  every distinct link subject (§6.3), and one sum slot in every distinct sum
  counter (§6.10). A counter shared by several links of one chain takes the
  smallest of their counts, or sum limits, as its capacity.

A link's counter therefore counts every admitted action of its subject and of
every delegate below it. Siblings, and delegation to the parent's own key
under another method, no longer get fresh counters. Each admitted action is
within every ceiling of its chain, so the argument sum over one link's actions
in one window is at most that link's ceiling times its count; for the root
link, that bounds the whole tree. The bound holds per namespace and per store:
counters are keyed by namespace (§6.2) and live in one store, so a namespace
served from two stores, or a store that loses its records, counts separately.

Count meaning changes, so the evaluator identifier becomes `/2` (025 §6, rule
7). Its policy type becomes `auths.gateway.argument-ceiling-policy/2`, whose
bytes keep `/1`'s four members and add §6.10's optional sum, partition, and
scope. A grant naming evaluator `/1` is refused as unregistered, and one whose
policy type is `/1` as mismatched. `auths-gateway bound-extension` prints `/2`
and gains `--sum-limit`, `--partition`, and `--scope`.

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
   binary search over the occupied prefix, as `reserve_window` does. For each
   distinct sum counter (§6.10), find its lowest free slot `n` the same way
   and load slot `n − 1`'s `cumulative` (0 when `n` is 0); the sum counter is
   full when that plus the verified argument exceeds its capacity.
2. If a counter is full, insert the claim alone as `not-entered` with
   `gateway.policy.window-exhausted`, or with `gateway.policy.sum-exhausted`
   when only sum counters are full; the operation ID is consumed, as today.
   An existing claim key goes to §4.4's replay path.
3. Otherwise, insert the claim (`attempting`, with `counters`) and one slot
   record per counter and sum counter in one `insert_all`. Each sum slot's
   `cumulative` is the loaded value plus the argument.
4. If the claim key exists, take the replay path. If slot `s` of counter `c`
   exists, advance `c` to `s + 1`; for a sum counter, load that slot's
   `cumulative` too. Return to step 2 if that reaches capacity, and retry
   step 3. After 32 rounds, store nothing and return `not-entered` with
   `gateway.policy.count-unavailable`.

Slots are inserted only at an observed frontier and are not deleted inside
their window, so a counter's slots form a prefix, and a search that reaches
capacity proves it full. A sum slot's `cumulative` is fixed once inserted, and
slot `n` can be inserted only once, over the loaded slot `n − 1`, so the last
slot's `cumulative` is the window's exact sum. Work is one binary search per
counter, one load per sum counter, and at most 32 inserts. Slots are never
released (§13, readings 2 and 17), and a replay consumes nothing.

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

- **Count and sum slots.** A slot's `expires_at` is
  `window_end + window_seconds`, so it outlives its window by one full
  window. `serve` deletes expired slots on a 60-second tick, at most 1 024 per tick. A process whose clock lags by more
  than one window could admit an action its deleted counter no longer
  charges; that falls under the unauthenticated-clock non-claim (§1).
- **Claims.** Never collected, because deleting a claim reopens its logical
  operation at the provider (053 §3.1). The store grows by one bounded record
  per logical operation. A full store fails the insert
  (`gateway.attempt.unavailable`, nothing stored) and evicts nothing.

### 6.6 Formal model and decider

`formal/Auths/Product/CeilingCount.lean` changes as follows.

- `Context.count : Nat → Nat` (the actor's count per window length) becomes
  `count : CounterKey → Nat` over `CounterKey := count (subject, window) |
  sum (subject, window, partition)`, where a `sum` key holds the window's
  running sum. `Policy` gains §6.10's optional sum limit, partition, and
  scope. With `Link := (subject, Policy)`, `linkAdmits` is today's `admits`
  at the link's counter plus the scope, partition, and sum conditions, and
  `chainAdmits` requires every link, each shared key taking the smallest
  capacity.
- `reserve : List Link → Nat → (CounterKey → Nat) → Option (CounterKey → Nat)`
  takes the argument, raises every distinct `count` key of an admitted chain
  by one and every distinct `sum` key by the argument, and returns `none`
  otherwise.
- New theorems:
  - `reserve_all_or_none`: either every value is unchanged, or each distinct
    `count` key rises by exactly one, each distinct `sum` key by exactly the
    argument, and every other key is unchanged.
  - `aggregate_count_bound`: for every arrival order in one window, the
    admitted chains containing a link number at most its count.
  - `aggregate_spend_bound`: their argument sum is at most the link's ceiling
    times its count.
  - `aggregate_sum_bound`: for every arrival order in one window, the
    argument sum of the admitted chains containing a link with a sum limit,
    for one partition value, is at most that limit.
  - `delegation_never_multiplies` and `sum_delegation_never_multiplies`: the
    corollaries for a root link.
  - `scope_admits_only_listed`: an admitted chain's scope and partition
    values are in every list its links carry.
- `decider_sound`, `tightening_never_admits_more`, and
  `bounded_policy_law_lawful` are re-proved over the extended `Policy`, with
  statements otherwise unchanged.

The decider does not change: `ceiling_count_tightens` still requires the same
argument and window, and a ceiling and count no larger than the parent's. A
new leaf `argument_policy_tightens` calls it and adds §6.10's sum, partition,
and scope rules. The decider no longer carries the aggregate bound, which the
parent's counters now enforce, but it keeps each child's own bound no wider
than its parent's (025 §15), and one shared window keeps a chain's counters
on the same boundaries. Three new pure leaves in `kernel.rs` are translated
through the pinned Aeneas route, each with a refinement theorem:
`chain_counts_admit(counts: &[u64], capacities: &[u64]) -> bool` to the count
part of `chainAdmits`; `chain_sums_admit(sums: &[u64], argument: u64,
capacities: &[u64]) -> bool`, whose additions are checked and whose overflow
refuses, to its sum part; and `argument_policy_tightens` to the extended
`tightens`. The atomicity of
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
- **Sum.** For each sum counter and window, let E be the entered entries that
  charge it, a_e each entry's verified argument, and m_e its capacity for it.
  Some arrival order admits E exactly when, for every capacity value k among
  them, the a_e of the entries with m_e ≤ k sum to at most k: ordering by
  capacity is optimal, as for deadlines. At the smallest failing k, every
  entry with m_e ≤ k is `inconsistent` (`audit.sum-exceeded`).
- **Exhaustion.** An entry refused with `gateway.policy.window-exhausted` or
  `gateway.policy.sum-exhausted` is `refused` with that code. When the
  bundle shows, for each of its counters, fewer entered entries than its
  capacity, or for a sum counter a sum that leaves room for the refused
  argument, `provider_result.recount` is `not-shown-by-bundle`, because a
  bundle may be incomplete.

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
  counter, flagged;
- siblings whose combined arguments exceed the parent's sum limit, refused
  with `gateway.policy.sum-exhausted` at the first argument that does not
  fit, although each sibling's own sum has room;
- an argument equal to the remaining sum, admitted, and one unit more,
  refused;
- two partition values of one link counted separately, and a partition value
  the grant does not list, refused before the claim;
- a child that drops its parent's sum, changes its partition, widens its
  partition or scope list, or raises its sum limit, each refused as expanded;
- an exhausted ancestor sum refusing without consuming the descendant's count
  or sum slot;
- an argument above the smallest sum limit, refused before the claim with
  zero slots;
- a `bounds.sum` recipe with an unbounded action, and with a link lacking a
  sum, both refused with `gateway.policy.sum-required`;
- two PostgreSQL processes racing for the last units of one sum, admitting
  at most the limit;
- an audit bundle whose entries' arguments fit each capacity alone but not
  together, flagged with `audit.sum-exceeded`, and every reordering of a valid
  bundle passing.

`bounds-hostile.json` keeps its eight cases under evaluator `/2`; "sub-agent
narrower inside" now also consumes its parent's slot. Every refused case has
zero provider entries and zero leases.

### 6.9 Relationship to Stripe profile budgets

Under §12's decision (option A), §6.10's sum budget replaces `auths-stripe`'s
budgets (012 §6) in production, and the vertical's evaluator is a test-only
reference and a demo. The gateway budget keeps their per-currency sum
(through a partition bound to the provider record) and their holding of
capacity while an outcome is unknown. It differs in three ways, each
narrower:

- windows are fixed and epoch-aligned only (§6.4, §13 reading 11);
- capacity is never released, even on `not-entered` or proven non-effect
  (§13, reading 17), because release needs provider-specific recovery
  evidence the gateway does not qualify (§16);
- a link's sum bounds its subject and every delegate together (§6.10), where
  012's budgets are per policy.

The two limits never count each other's effects. Until epic 8 lands, a Stripe
account reachable through both paths has two unrelated limits. The runbook
and the claim ledger MUST say so, and an operator MUST NOT rely on either
limit to bound the other path.

### 6.10 Sum budgets, partitions, and scopes

Policy `auths.gateway.argument-ceiling-policy/2` is canonical CBOR:

| Key | Member | Rule |
| --- | --- | --- |
| 0–3 | argument, ceiling, window seconds, maximum count | As `/1` (025 §25 reading 5) |
| 4 | sum limit | Optional; an integer in 1..=2^53 − 1 |
| 5 | partition | Optional, only with 4: `{0: argument, 1: values}` |
| 6 | scope | Optional: `{0: argument, 1: values}` |

Each `values` is 1–16 sorted, unique strings of 1–64 bytes in `0x21..=0x7e`.
A partition or scope argument is a top-level verified MCP argument other than
member 0, read through `mcp-arguments-v1` as a string. The partition and scope
may name the same argument. Anything else is a malformed policy
(`gateway.policy.evaluator-mismatch`). The largest policy stays well below
025's 4 096-byte bound.

**Admission** (§6.1). The scope value must be in every scope's list, and the
partition value in every partition's list. The argument must be at most the
smallest sum limit the chain carries. A recipe's `bounds.sum` requires every
link to carry a sum limit whose member 0 is the recipe's `argument` and whose
partition argument is the recipe's `partition`, both present or both absent.

**Tightening.** `argument_policy_tightens(child, parent)` holds exactly when
`ceiling_count_tightens` holds and:

- if the parent has a sum limit, the child has one no larger, with the same
  partition argument (or none when the parent has none) and a value list that
  is a subset of the parent's;
- if the parent has a scope, the child has one on the same argument with a
  subset of its values.

A parent without a sum or scope accepts a child that adds one, which only
narrows. A child that fails is `gateway.policy.expanded`.

**Sum counters.**

| Item | Definition |
| --- | --- |
| Sum counter key | SHA-256 of `auths.gateway-bounded-sum/1`, NUL, then namespace, link subject identifier, evaluator identifier, and partition value (empty when unpartitioned; a listed value is never empty), each with an eight-byte big-endian length prefix, then eight-byte big-endian `window_seconds` and window index |
| Sum slot key | SHA-256 of `auths.gateway-bounded-sum-slot/1`, NUL, the sum counter key, and the eight-byte big-endian slot number |
| Sum slot record `auths.gateway-bounded-sum/1` | `counter`, `slot`, `amount`, `cumulative`, `window_seconds`, `window_index`, `window_end`, `namespace`, `operation_id`, and the claim key |

Each link that carries a sum limit contributes one sum counter for the
action's partition value. A sum counter shared by several links of one chain
takes the smallest limit as its capacity. Every action that charges a sum
counter also charges its link's count counter, so a sum counter holds at most
the link's count of slots in a window, and the binary search of §6.3 stays
bounded. Reservation is §6.3's, atomic with the claim. The window is the
policy's.

**Why delegation cannot multiply it.** A link's sum counter is keyed by its
subject, not by the actor, and every action under the link charges it. The
argument sum over a window of all actions of the link's subject and its
delegates, for one partition value, is therefore at most that link's limit,
and the root link's limit bounds the whole tree per partition value
(`aggregate_sum_bound`, §11.1). Across partition values the bound is the
limit times the number of values the root lists.

**Why a partition must be bound.** An unconstrained partition would let an
agent spread one budget over labels of its choosing. A grant therefore lists
the values it allows (§13, reading 18), and the compiler requires the
partition field to reach the provider in the write body or the account-scope
header, or to be checked against the provider record by a
`relative_ceiling.bind` (§3.2). The Stripe recipe binds `currency` to the
PaymentIntent's `/currency` (§3.1).

**Non-claims.** The sum is of verified arguments, not provider amounts
settled. Capacity is never released. A bind shows the record's partition
value at `read_at`, not at the write.

## 7. Operator plane

### 7.1 Listeners, capacity, and deadlines

`serve` (`product/runtime/auths-gateway/src/bin/auths-gateway.rs`) runs two
listeners with separate capacity. #166 implemented the two listeners with
fixed capacities of 64 and 4, the admin peer check, the application
deadlines, and the accept back-off (`listener.rs`, `app.rs`, and
`admin_peer_admitted`). This section adds `--app-capacity`, the admin row's
probe, commit, and drain bounds, and the descriptor check.

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
(§9.1): the canonical `auths.provider-connection/2` bytes that
`auths-connections` defines, keyed by SHA-256 of `auths.gateway-connection/1`,
NUL, provider, NUL, alias. Admin mutations replace it by compare-and-swap
through `auths-connections`' own transition functions, so its format and
rules stay the registry's (053 §4). Every process reloads it at §5.5 steps 4,
8, and 11, so a disable or revocation committed through any process stops new
leases and entries in every process at its next reload. The per-process
`PersistentConnectionStore` copy (`connections.cbor`) leaves the state
directory.

Credential bytes stay in each host's local credential store
(`credentials.cbor`), and nothing secret enters the shared store.

**Why the record changes to `/2`.** A stored secret is keyed by the
generation at which it was installed or rotated in. A state change (disable
or enable) advances the record's `generation` without storing a secret. So
the reference commitment, `credential_commitment(connection ID, generation,
secret)`, is bound to the credential's own generation, not to the record's
current one.

`/1` does not carry the credential's generation, so after any disable and
enable, a joining or rotating host cannot recompute the commitment.

**`auths.provider-connection/2`** adds one field, `credential_generation`:
- It is the generation of the last install or rotate, and never exceeds
  `generation`.
- Install and rotate set it equal to the new `generation`.
- State changes leave it unchanged.
- `/1` is retired, and a store holding `/1` bytes is refused as obsolete
  state.

**Leasing.** A process leases the secret its local store retains for the
record's `generation`. Under `auths-connections`' retained-entry rule, that
is the newest stored generation not above it. The lease proceeds only if that
stored generation equals `credential_generation` and its reference commitment
equals the record's. Otherwise the process refuses before the claim
(`gateway.connection.credential-generation-missing`).

| Operation | Behavior |
| --- | --- |
| `install` (first host) | Inserts the record once (`gateway.install.connection-exists` if present) and stores the secret locally |
| `install --join` (each further host, with the same recipe, trust, lock, provider, alias, deployment, and store) | Loads the record (`gateway.install.join-record-missing` if absent); applies the credential guard; computes the reference commitment the local store would record for the secret under the record's connection ID and `credential_generation`; compares it with the record's in constant time; stores the secret at `credential_generation` only on a match (`gateway.install.join-commitment-mismatch` otherwise) |
| `rotate` | Committed to the record through one process, which sets `generation` and `credential_generation` to the new generation. Each other process then accepts the same secret through its own `rotate` only when the secret's commitment, computed under `credential_generation`, equals the record's (`gateway.admin.generation-conflict` otherwise). A later disable or enable leaves both checks valid. |

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
| `disable`, `enable`, `revoke`, `rotate` | §7.2–§7.4 | `gateway.admin.disabled`, `.enabled`, `.revoked`, `.rotated` |
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
| `counters-digest` | bytes (32) | At least one count or sum counter was reserved |
| `refusal` | text, at most 128 bytes | `not-entered` |
| `http-status` | uint, 100–599 | A complete response was recorded |
| `response-digest` | bytes (32) | With `http-status` |
| `observation` | text: `match`, `mismatch`, `echo-mismatch` | `observed` |
| `evidence-digest` | bytes (32) | `observed-by-provider` |
| `pre-entry-digest` | bytes (32) | Pre-entry observations were recorded |
| `relative-basis` | uint, at most 2^53 − 1 | A relative-ceiling basis was recorded (§5.6) |
| `relative-basis-digest` | bytes (32) | With `relative-basis`: the basis response's SHA-256 |

`counters-digest` is the SHA-256 of `auths.gateway-counter-set/1`, a NUL byte,
and the sorted count and sum counter keys, whose distinct domains keep them
apart. At most 13 of an observation's 16 facts are used.
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
  "pre_entry": {"observations": 1, "verified": true}, "relative_basis": null,
  "recount": null
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
  `inconsistent`);
- for a `relative_ceiling` recipe, requires each entered entry's outcome to
  carry `relative-basis`, and `relative_ceiling_admits` to hold on the
  re-derived argument, that basis, and the recipe's basis points
  (`audit.relative-ceiling-missing`, `audit.relative-ceiling-exceeded`, both
  `inconsistent`). The basis is the gateway's assertion under observer
  trust; an auditor with provider access can re-read the record, which may
  have changed since.

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
`architecture.toml`, and in `PRODUCT_FUZZ_TARGETS` and the scheduled
campaign's `CAMPAIGN_TARGETS` (`xtask/src/fuzz.rs`), seeded from
`bindings/fixtures/gateway/`. It depends on the scheduled Fuzz job passing
first (Epic 6 step 1, merged in #168).

| Target | Property |
| --- | --- |
| `target_gateway_recipe` | `compile` never panics; an accepted digest equals the digest of the re-serialized canonical source; `review` and `recovery_capability` are total |
| `target_gateway_request` | On the fixture recipes and arbitrary arguments, `closed_request_from_arguments` never panics; accepted URLs stay in the origin with no query or fragment and the recipe's segment count; bodies stay in bound; form keys are the recipe's plus the echo; the token and the key match their derivations; an account-scope header appears exactly when declared, with the verified value, and never on a credential read |
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
  link's count or, per partition value, its sum, and leave no slot behind a
  refusal;
- `relative_ceiling_admits` agrees with `argument ≤ floor(basis ×
  basis_points / 10 000)` around every exact multiple;
- §6.7's sum condition agrees with a brute-force search over arrival orders
  for up to six entries;
- every reachable record's outcome facts round-trip through signing and
  verification.

**Kani** harnesses, exhaustive over their finite domains, cover
`stage_transition_allowed`, `recovery_capability`, the §8.1 presence rule,
`chain_counts_admit` and `chain_sums_admit` for up to four counters, and
`argument_policy_tightens` for value lists of up to three. Symbolic harnesses
over every `u64` input check `relative_ceiling_admits` against the
floor-division form for every basis point in 1–10 000, and `relative_basis`
against checked subtraction. They join the Kani closure, so
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
| Store | `auths.gateway-attempt/3`, `auths.gateway-bounded-count/2`, `auths.gateway-bounded-sum/1`, `auths.gateway-connection/1`, `auths.lifecycle.postgresql/5` |
| Policy | `auths.gateway.argument-ceiling-window-count/2`, `auths.gateway.argument-ceiling-policy/2`, `auths.gateway-counter-set/1` |
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
| `sum-slot` | §6.10 | `auths.gateway-bounded-sum/1` |
| `connection` | §7.3 | `auths.provider-connection/2` |

Every record is at most 262 144 bytes, the connection record's maximum under
AP-SPEC-040 §7.4. `MAX_GATEWAY_ATTEMPT_BYTES` in
`product/stores/auths-stores/src/gateway_attempt.rs` becomes that value.

### 9.2 Trait

`GatewayAttemptStore` keeps `load` and `replace`, and gains:

- `insert(kind, key, record, expires_at)`, with `expires_at` present exactly
  for `count-slot` and `sum-slot`;
- `insert_all(entries) -> Inserted | Exists { index }` over entries of the
  same four values, all or none;
- `sweep_expired(now, limit) -> deleted`, for `count-slot` and `sum-slot`
  only.

Every method fails closed and never reports unreadable state as absent.

### 9.3 File store

`FileGatewayAttemptStore` names files by kind (`claim-`, `slot-`, `sum-`,
`conn-`, then the hex key and `.json`). Mutations hold the existing host-wide
exclusive `flock` on `.replace.lock`, and loads hold it shared. Under the
exclusive lock, `insert_all`:

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
    record_kind TEXT NOT NULL CHECK (record_kind IN ('attempt', 'count-slot', 'sum-slot', 'connection')),
    expires_at BIGINT NULL,
    record_bytes BYTEA NOT NULL CHECK (octet_length(record_bytes) BETWEEN 1 AND 262144),
    record_sha256 BYTEA NOT NULL CHECK (octet_length(record_sha256) = 32),
    CHECK ((record_kind IN ('count-slot', 'sum-slot')) = (expires_at IS NOT NULL))
);
CREATE INDEX auths_gateway_records_expiry
    ON auths_gateway_records (expires_at) WHERE record_kind IN ('count-slot', 'sum-slot');
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

- `insert_all` all or none under two racing processes, including a claim with
  count and sum slots;
- a crash at every step of the file batch;
- sweep bounds;
- shared-connection-record visibility across two processes.

The PostgreSQL variants run in the PostgreSQL lifecycle workflow, as today.

## 10. Stable codes

Codes marked "recorded" appear as an attempt's `refusal`; codes marked
"before claim" return `not-entered` with nothing stored.

| Code | Where |
| --- | --- |
| `gateway.recipe.invalid-provider-header`, `.invalid-credential-guard`, `.invalid-idempotency`, `.response-locator-conflict`, `.invalid-pre-entry`, `.invalid-relative-ceiling`, `.invalid-account-scope`, `.invalid-bounds`, `.unbound-partition` | compile |
| `gateway.idempotency.window-exceeds-retention`, `gateway.policy.too-many-bounds`, `gateway.pre-entry.requirement-missing`, `gateway.pre-entry.observer-unavailable`, `gateway.connection.credential-generation-missing`, `gateway.trust.observer-key-in-authority-chain` | before claim |
| `gateway.policy.sum-required`, `.above-sum-limit`, `.scope-denied`, `.partition-denied`; `gateway.account-scope.unbound`, `.invalid-value` | before claim (§5.9, §6.10) |
| `gateway.policy.count-unavailable` | before claim, after 32 contended rounds |
| `gateway.policy.window-exhausted`, `gateway.policy.sum-exhausted` | recorded, atomically with the claim |
| `gateway.pre-entry.condition-false`, `gateway.pre-entry.unavailable`, `gateway.credential.mode-guard`, `gateway.attempt.entry-deadline`, `gateway.transport.not-entered` | recorded |
| `gateway.credential.account-mismatch`, `.account-unavailable`, `.capability-excess`, `.capability-unavailable` | recorded, at step 9 (§5.7, §5.8) |
| `gateway.relative-ceiling.above`, `.binding-mismatch`, `.unavailable` | recorded, at step 10 (§5.6) |
| `gateway.trust.key-aliased` | install and serve |
| `gateway.install.operator-attestation-required`, `.operator-attestation-invalid`, `.credential-guard`, `.credential-probe`, `.credential-account`, `.credential-capability`, `.connection-exists`, `.join-record-missing`, `.join-commitment-mismatch` | install |
| `gateway.serve.descriptor-limit`, `gateway.serve.accept-failed` (logged, since #166) | serve |
| `gateway.admin.peer-refused` (logged, since #166), `.status`, `.reobserved`, `.generation-conflict`, `.credential-guard`, `.credential-probe`, `.credential-account`, `.credential-capability`; `gateway.reobserve.not-observable` | admin |
| `gateway.observer.credential-guard` | observe |
| `audit.counters-mismatch`, `.bound-exceeded`, `.sum-exceeded`, `.pre-entry-missing`, `.pre-entry-invalid`, `.pre-entry-unsatisfied`, `.relative-ceiling-missing`, `.relative-ceiling-exceeded` | audit |
| `gateway.echo-verify.match`, `.mismatch`, `.absent`, `.record-invalid`, `.action-invalid`, `.pointer-invalid` | echo-verify |

Four existing codes change meaning:

| Code | Today | After this spec |
| --- | --- | --- |
| `gateway.policy.count-unavailable` | A store failure during reservation; the claim is recorded `not-entered` | 32 contended rounds, nothing stored; a store failure is `gateway.attempt.unavailable` |
| `gateway.connection.changed` | Refused before the claim | Also recorded after the claim, at steps 8 and 11 |
| `gateway.credential.unavailable` | Returned for a lease failure and for a write that failed before network entry | Recorded for a lease failure only; the other case is `gateway.transport.not-entered` |
| `gateway.policy.window-exhausted` | Recorded after a separate claim insert | Recorded in the same atomic step as the claim |

## 11. Formal obligations

The gateway's I/O (sockets, HTTP, the stores) stays covered by conformance,
fuzz, property, and Kani checks. Its decision logic is machine-checked: every
rule that decides whether a credential is leased, a write is sent, or an
outcome is recorded is a small pure Rust function. It follows AP-SPEC-061
§3.4's extraction rules, is translated through the pinned Aeneas route, and
has a refinement theorem to a Lean model in `formal/Auths/Product/`. Each
theorem is registered in `formal/assurance-manifest-v1.toml` under a new
claim identifier. Each translated leaf and its refinement theorem are
`qualified`, citing the translation and the source closure. Axioms stay
`propext`, `Quot.sound`, and `Classical.choice`. Every translation slice is
gated with `--error-on-warnings` and `-warnings-as-errors` from its first
commit.

### 11.1 Spend limit (epic 4)

§6.6's model changes and theorems, with claim text that says "fixed window",
"a link's count bounds its subject and delegates", and "a link's sum limit
bounds the sum of the bounded argument over its subject and delegates, per
listed partition value". The leaves are `chain_counts_admit`,
`chain_sums_admit`, and `argument_policy_tightens`.

### 11.2 Admission order (epic 3)

§5.5's order becomes a closed step machine. The leaf is
`next_step(state: SubmitState, event: SubmitEvent) -> SubmitDecision` in a new
`product/runtime/auths-gateway/src/order.rs`. `GatewayEngine::submit`
performs I/O only as the decision directs, so the engine has no ordering of
its own to diverge from. Model: `formal/Auths/Product/SubmitOrder.lean`.
Theorems over every event trace:

- `lease_requires_verified_claim`: a credential lease happens only after
  native verification succeeded, the claim committed with every count and
  sum slot, and the step 8 reload found the record unchanged.
- `send_requires_lease_and_deadline`: the write is sent only after a lease,
  the pre-entry re-read when declared, the step 11 reload, and the step 12
  deadline check.
- `send_requires_credential_checks`: when declared, the write is sent only
  after the step 9 account read found equal commitments and every denied
  read was refused with a declared status.
- `send_requires_relative_ceiling`: when declared, the write is sent only
  after the step 10 relative-ceiling read produced a basis, every bind was
  equal, and `relative_ceiling_admits` held on the verified argument.
- `account_scope_requires_binding`: for a recipe with `account_scope`, the
  claim happens only after step 3 found every link's scope listing the
  verified value.
- `at_most_one_send`: each claim sends at most one write, including under
  replay and re-observation.
- `pre_claim_refusal_stores_nothing` and
  `post_claim_refusal_records_not_entered`: every refusal before step 6
  leaves no record, and every refusal after it and before transport entry
  records `not-entered` with its code.

The statement of `lease_requires_verified_claim` is the gateway premise the
reference-monitor theorem (board §3) needs.

### 11.3 Recovery (epics 2 and 3)

The leaves are `recovery_capability` (§4.2) and `valid_transition` (§4.3).
Model: `formal/Auths/Product/Recovery.lean`. Theorems:

- `capability_total_deterministic`: every declaration triple maps to exactly
  one capability, and `write_is_conditional` is always `false`.
- `class_matches_declarations`: each class holds exactly under §4.2's rules.
- `unknown_resolves_only_linked`: over every transition sequence, a record in
  `unknown` leaves it only for `observed-by-provider`, only for a `linked`
  class, and only on a transition that carries a token-and-value match.
- `provider_claim_requires_evidence`: `observed-by-provider` is reachable only
  through a transition carrying match evidence from the stored plan.
- `terminal_stages_final`: `not-entered`, `observed`, and
  `observed-by-provider` have no outgoing transition.
- `transitions_preserve_identity`: every transition keeps the identity
  fields, `evaluated_at`, `counters`, and the plan.

The Kani harness of §8.5 still checks `valid_transition` exhaustively over
bounded records. Lean adds the statements over sequences.

### 11.4 Credential generations (epic 5)

The leaves are the generation arithmetic of `auths-connections`'
`transition_state` and `rotated`, and a new
`lease_generation(record_generation, credential_generation, stored: &[u64]) -> Option<u64>`
that implements the retained-entry rule together with §7.3's equality check.
Model: `formal/Auths/Product/ConnectionGenerations.lean`, over any sequence
of install, join, rotate, disable, enable, and revoke. Theorems:

- `credential_generation_le_generation`: always true.
- `state_change_preserves_credential_generation`: disable and enable change
  only `generation` and `state`.
- `lease_selects_credential_generation`: a lease succeeds exactly when the
  local store holds `credential_generation` with the record's commitment,
  and it returns that generation.
- `join_after_state_changes`: a host that joins after any sequence of state
  changes, holding the installed or rotated secret, can lease. This is the
  case §7.3's `/2` exists for.
- `revoked_never_leases`: after revocation, no sequence produces a lease.

### 11.5 Request construction (epic 2)

The leaf is `closed_request_from_arguments` in `recipe.rs`, restructured under
AP-SPEC-061 §3.4. `CompiledRecipe::compile`'s parsing stays covered by the
hostile recipe corpus and fuzzing, not by proof. Model:
`formal/Auths/Product/RequestConstruction.lean`. Theorems, for every compiled
recipe and every argument map:

- `method_and_origin_fixed`: the request uses exactly the compiled method and
  pinned origin.
- `path_from_declared_segments`: each path segment is a declared `fixed`
  segment or the percent-encoded value of a declared field reference, and no
  argument can add, remove, or reorder segments.
- `headers_within_declaration`: the header set is contained in the declared
  headers, the credential header, the derived `Idempotency-Key`, the declared
  version headers, and the declared account-scope header.
- `account_scope_header_exact`: the write and every action read carry the
  declared account-scope header with exactly the verified field's value; no
  credential read carries one; and a recipe without `account_scope` sends no
  `account-scope` header on any request.
- `credential_reads_fixed`: every denied read is a `GET` or `HEAD` whose path
  is its declared `fixed` segments, independent of every argument.
- `body_bounded`: the body is at most 16 KiB and consumes only declared
  fields.

### 11.6 Relative ceiling (epic 3)

The leaves are `relative_ceiling_admits` and `relative_basis` (§5.6). Model:
`formal/Auths/Product/RelativeCeiling.lean`. Theorems:

- `relative_ceiling_exact`: for every argument, basis, and basis point in
  1–10 000, the leaf admits exactly when `argument ≤ (basis × basis_points)
  / 10 000` in natural-number floor division.
- `relative_ceiling_never_exceeds_ratio`: an admitted argument times 10 000
  is at most the basis times the basis points.
- `relative_ceiling_monotone`: a larger basis or more basis points never
  admits less, and a zero basis admits only a zero argument.
- `relative_basis_never_negative`: the basis is the difference when the
  subtrahend is at most the value, and absent otherwise.

`send_requires_relative_ceiling` (§11.2) connects these to the order.

### 11.7 Kani and residual assumptions

- **Kani.** The harnesses of §8.5.
- **Residual assumptions,** recorded in the manifest and the claim ledger:
  - store atomicity and linearizability;
  - the unauthenticated gateway clock;
  - provider behavior, including what a basis value, an account identifier,
    a refusal status, or an account-scope header means;
  - the fidelity of the Charon/Aeneas translation (AP-SPEC-061 §1);
  - that `GatewayEngine::submit`'s I/O follows `next_step`'s decisions, which
    holds by construction and is tested by the scenario corpus but not proved
    over the async runtime.

## 12. Owner decision: the single provider-write path

**Decided 2026-09-27: option A.** The gateway becomes the single
provider-write path, and epic 8 retires the hand-built local-agent effect
profiles. The table keeps option B as the record of what was not chosen. Its
A column lists what production gives up and what it keeps. On the same day
the owner decided that production keeps the five Stripe checks as recipe
capabilities (§5.6–§5.9, §6.10); every other section stands as written.

The local agent (`product/runtime/auths-node`) serves five effect profiles,
all `unqualified` in
`product/runtime/auths-node/src/generated/profile_launch_projection.json`, so
none runs in production: `auths.stripe.refund/1`,
`auths.postgresql.bounded-update/1`, `auths.postgresql.update-preflight/1`,
`auths.opentofu.saved-plan-apply/1`, and `auths.opentofu.plan-preflight/1`.

**Why consolidation is recommended.** The public record shows defects
clustering in mechanisms each vertical re-implements and the gateway
centralizes: #145 (Stripe refund recovery), #147 (receipt clocks in the
PostgreSQL vertical), and #160 (provider clients' proxy and redirect
settings). The north star already runs on the gateway, and no
vertical is qualified, so consolidating loses no qualified claim.

| Topic | A: consolidate | B: keep both |
| --- | --- | --- |
| Production writes | HTTPS provider writes go only through the gateway; the Stripe refund becomes §3.1's recipe | Two paths and two Stripe stacks |
| Local-agent effect profiles | All five removed in one cutover (routes, the journal executor's effect path, their generated clients, and their connection administration), with no switch | Kept. Each mechanism this spec centralizes (recovery records, hardened clients, shared connection state, §7's operator plane, key-identity separation) MUST reach the local agent before any profile is qualified |
| Domain crates | Pure evaluators, fixtures, Kani harnesses, and demos stay as test-only references (plan, "Phase 1" and "Domain to shared product") | Unchanged |
| PostgreSQL and OpenTofu | Not HTTP, so no gateway equivalent. Their production paths end, and with them the PostgreSQL serializable row-version write and OpenTofu's stale-plan refusal | Unchanged |
| Stripe checks | Production keeps all five, as provider-neutral recipe capabilities that the Stripe recipe declares (§3.1): relative ceilings (§5.6, a declared ratio of a basis read after the lease); account binding at onboarding and every lease (§5.7); negative probes in place of the restricted-key guard (§5.8; neither path can read a key's scopes, and the vertical checks only the `rk_test_` prefix); Connect scope (§5.9, a grant-listed `Stripe-Account` value); amount-sum budgets (§6.10). §6.9 and §14 list where each is narrower than the vertical | Kept in the vertical |
| Architecture documents | The boundary plan's vertical-package rule and its ADR 0012 paragraph, and ADR 0012's decision and consequences, are rewritten: production writes become data-only recipes; verticals stay the source of reviewed semantics and evidence but not the production executor; and ADR 0013 states whether and how a recipe earns a qualified claim. AP-SPEC-040 is superseded for provider writes, and AP-SPEC-041–044 and AP-SPEC-038 Epic 6 move to gateway recipes | Unchanged |
| Authoring paths | Two (self-hosted adapter, gateway recipe), compared in the developer docs | Three, compared on one page by credential isolation, schema, recovery, and qualification |
| Spend limits | The gateway count and sum budgets only | Independent per path (§6.9) |

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
| 12 | Relative-ceiling rounding | (a) floor, tested as `argument × 10 000 ≤ basis × basis_points`; (b) nearest | (a): 012 §5's `floor-minor-unit`; never admits above the exact ratio |
| 13 | When the relative ceiling runs | (a) at step 10, after the lease, recorded `not-entered` and consuming the operation ID and slots; (b) before the claim | (a): the read needs a credential, and a lease before the claim would break `lease_requires_verified_claim` |
| 14 | When the account read runs | (a) at onboarding and every lease, read-backs included; (b) at submission leases only | (a) |
| 15 | When denied reads run | (a) at onboarding and every lease; (b) at onboarding and a declared interval | (a): an interval leaves time in which a widened key writes; it costs up to four reads per lease |
| 16 | Denied reads and the version response rule | (a) the rule applies; (b) only the status counts | (a): if the provider's refusals omit a required version header, the recipe cannot declare denied reads, which Epic 7 checks against the provider's documentation |
| 17 | Sum capacity after `not-entered` | (a) never released; (b) released | (a): release widens, as in reading 2 |
| 18 | Partition values | (a) listed in the grant, with the partition field bound to the provider; (b) any value | (a): (b) lets an agent multiply its budget with new labels |
| 19 | A platform write and an account-scoped write in one recipe | (a) a recipe with `account_scope` always sends the header; (b) a sentinel value that omits it | (a): a sentinel would put provider semantics in gateway code |
| 20 | The account-scope header on credential reads | (a) never; (b) on every request | (a): with the header, the account read would test the scoped account, not the credential's own |
| 21 | The relative-ceiling basis without an observer key | (a) read and recorded by the gateway, signed only inside the outcome; (b) required to be a 060 observation, as `pre_entry` is | (a), not the narrower reading: (b) refuses every production action until AP-SPEC-038 Epic 4, which the owner's decision to keep the check rules out; (a) claims nothing from the basis beyond the gateway's own refusal |
| 22 | Where account-scope values live | (a) the grant's bounded policy, narrowing under delegation; (b) a fixed recipe value | (a): the owner requires a grant-constrained field, and different grants may allow different accounts |
| 23 | Where the relative ratio lives | (a) the recipe, one ratio per approved installation; (b) each grant, as 012's policy | (a): the owner's direction; no grant issuer can widen it |
| 24 | Re-enabling a disabled connection, which §7.7 did not list but Epic 5's done gate needs | (a) an `enable` admin command; (b) a new install | (a): a reinstall would change the connection ID and void every action; `enable` stores no secret, like `disable` |
| 25 | How a process knows whether its `rotate` commits a new generation or takes one committed elsewhere | (a) a process that holds the record's current secret commits; one that does not takes the secret only on a matching commitment (`gateway.admin.generation-conflict` otherwise); (b) an explicit flag | (a): a stale process can never publish over a rotation it has not taken, and no flag can be set wrong; to rotate again it first takes the current secret |
| 26 | `install --join` against a revoked record, or one whose descriptor names another recipe | (a) refused (`gateway.install.connection-revoked`, `gateway.install.join-recipe-mismatch`); (b) stored anyway | (a): no secret is stored for a connection that can never lease |
| 27 | Operator `reobserve` on a disabled connection | (a) refused, as entries are; (b) allowed as reconciliation | (a), the narrower reading: it shares the entry path's load and authorization |
| 28 | Where several development processes on one host share the connection record | (a) `install --attempt-store <absolute dir>`, recorded in manifest `/3`; (b) never | (a): the file store is host-wide under its lock; production uses the `PostgreSQL` store and refuses the flag |
| 29 | The operator attestation file | (a) `{statement, signature_b64, evidence}` with 1–4 `{evidence_type, media_type, bytes_b64}` objects whose identifiers the gateway derives; (b) evidence identifiers supplied in the file | (a): nothing in the file chooses an identifier the kernel derives |
| 30 | An admin state change that loses a compare-and-swap to another process | (a) reload and reapply up to 8 rounds, then `gateway.admin.generation-conflict`; (b) fail at once | (a): a kill switch should not fail on an unrelated concurrent change; the bound keeps it within the admin deadline |
| 31 | The pool `serve`'s descriptor check counts | (a) the `PostgreSQL` pool's maximum connections, and zero for the file store; (b) a fixed number | (a) |

## 14. Conflicts with committed documents

Each amendment lands with the code that causes it.

| Document | Conflict | Resolution |
| --- | --- | --- |
| 053 §1 | First scope: one write plus an optional read-only observation per operation | `/2` adds, per submission, at most one pre-entry read, one relative-ceiling read, one account read, and four denied reads, and per onboarding the probe, the account read, and the denied reads; all are read-only (`GET` or `HEAD`) and gateway-performed, and each read-back lease repeats the account read and denied reads |
| 053 §3 | The first installation may run offline | A recipe with a probe, an account read, or denied reads needs egress at `install`, `install --join`, and `rotate`, and a join reads the shared store; recipes without them keep the offline first install |
| 053 §3, the socket paragraph #166 added | A fixed 64 application connections; an admin session waits at most 45 seconds for its change, which waits for submissions and read-backs already in progress | `--app-capacity` and §7.1's admin deadlines; admin mutations commit without waiting, then drain (§7.2) |
| 053 §3.2 | Path segments only from verified fields; a fixed header allowlist | `response-field` segments from the recorded response (§4.1); the provider-header registry with its `version` and `account-scope` classes (§5.1) |
| 053 §3.3 and its Epic 3 acceptance | The ordered path claim → credential → transport, and its acceptance cases | The path becomes §5.5, with the reloads, the atomic slots, and the credential checks, pre-entry read, and relative-ceiling read between credential and transport. Epic 3's acceptance gains the pre-entry, guard, account, denied-read, relative-ceiling, and shared-record cases. `unknown` still resolves only through provider evidence |
| 059 §3.2 | JSON-only echo | Form placement (§5.4); the echo stays the only added body value |
| 059 §7.1 | Re-observation only by replay, from a locator fixed at claim; a stored `attempting` record never re-observed | Also by admin `reobserve`; response locators fixed at response time; `attempting` re-observable for `linked` recipes (§4.3) |
| 060 §14 reading 4 | Outcome facts `commitment` and `stage` | §8.1 |
| 025 §25 readings 5, 7, and 10 | The count per actor, reserved after the claim, keyed to the bounded branch's actor; policy bytes of four members | Superseded by §6; policy `/2` adds §6.10's members |
| 012 §5 | Basis points and a closed denominator enum in each policy; an `arithmetic-overflow` denial | The ratio is recipe data (§13, reading 23); the denominator is a declared pointer, optionally minus one more; `u128` arithmetic cannot overflow, so the code has no gateway equivalent. 012 stays the test-only reference |
| 012 §6 | Budgets per policy over fixed or rolling windows, released on proven non-effect or reconciliation | §6.10: per link and partition value, fixed windows only, never released (§6.9) |
| 012 §7 | Connect scope `platform \| acct_…` in the exact action, with every read and the mutation in that account context | §5.9: a grant-listed field in the `Stripe-Account` header of the write and every action read; a platform write needs a recipe without `account_scope` (§13, reading 19) |
| 012 §13 | Evidence read before verification and re-read after the seal, before the credential; a "restricted" credential | The relative-ceiling basis is read once, after the lease (§13, reading 13); restriction is shown by denied reads (§5.8), which the vertical does not make |
| 012 connection onboarding and lease | The account is checked with the provider at onboarding and against the local descriptor at every lease | §5.7 asks the provider at every lease, at one read per lease |
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
| 1. Case file and fixtures | ADR 0013 and the case 0007 comparisons (§2), for all ten recipe capabilities and the sum budget; hostile recipe cases for every new construct, including basis points 0 and 10 001, a `POST` or `field`-segment denied read, a refused status of 429, five denied reads, `Stripe-Account` in `provider_headers`, an unregistered account-scope header, and an unbound partition; attempt scenarios `/3`, including `pre-entry-replaced-after-observation`, `relative-ceiling-above`, `relative-ceiling-exact-boundary`, `relative-basis-unavailable`, `relative-binding-mismatch`, `account-substituted-at-lease`, `denied-read-answered`, `account-scope-outside-grant`, `account-scope-unbound`, and `account-scope-only-on-action-requests`; §6.8's count and sum cases in `bounds-aggregate.json`; `outcome-v2.json`, `key-identity.json`, and `codes.json` | The vectors exist and fail against current code; the ADR and case file are reviewed |
| 2. Recipe `/2` | The compiler, including §3.2's rows for the credential account and denied reads, `account_scope`, `bounds`, and `relative_ceiling`, and §5.1's registry classes; `recovery_capability`, and review `/2` in both CLIs; account-scope headers in request construction; derivation emits `/2`; the fixtures, north-star recipe, and derivation corpus are regenerated | Every fixture compiles to its documented class; every hostile case fails with its code; both packaged CLIs pass the corpus; §11.3's capability theorems and §11.5, including `account_scope_header_exact` and `credential_reads_fixed`, are proved and registered, with `cargo xtask formal` green |
| 3. Store and engine | §9 (kinds, `insert_all`, sweep, the file batch, schema 5, record `/3`); the §5.5 steps marked 3, including the account read and denied reads at onboarding and every lease (§5.7, §5.8) and the relative ceiling (§5.6, `ratio.rs`); re-observation of `attempting` | Conformance passes on both stores (PostgreSQL in its workflow); the scenario corpus drives the counting provider; every hostile suite has zero unauthorized entries, and every pre-claim refusal zero leases; each relative-ceiling, account, and denied-read scenario records `not-entered` with its code, one lease, and zero writes; §11.2, §11.3's transition theorems, and §11.6 are proved and registered, with `cargo xtask formal` green |
| 4. One spend limit | Formal first (the Lean model, theorems, and the three translated leaves, with `cargo xtask formal` green); then evaluator `/2` with policy `/2` (§6.10), the account-scope binding (§5.9), the count and sum slots of §5.5 step 6, §6.5's sweep, §6.7, and every §6.4 description | `bounds-aggregate.json` passes on both stores, including both races; no count or sum slot leaks; the audit flags the capacity-3 and capacity-1 bundle and the sum bundle and passes every valid one; `account-scope-outside-grant` and `account-scope-unbound` refuse with zero leases |
| 5. Operator plane | §7, including connection record `/2` (§7.3), and the §5.5 steps marked 5 | With the application at full capacity, every admin command answers within its deadline; a disable or revoke through process A stops new entries in process B at B's next reload, on PostgreSQL; a second host joins only with the matching secret, including after a disable and enable, and a cross-process `rotate` followed by a disable and enable still leases on every host; `did:key` and `raw-key-v1` aliasing is refused at install and per proof; an invalid attestation is refused; §11.4 is proved and registered, with `cargo xtask formal` green |
| 6. Evidence and assurance | Step 1, repairing the scheduled Fuzz job (`.github/workflows/fuzz.yml`) so a scheduled campaign can pass, with a unit test on a captured libFuzzer log, merged in #168; scheduled runs pass from 2026-09-27. Then §8: outcome `/2` and its consumers (including `relative-basis`), observe `/2`, audit `/2` (including the relative-ceiling and sum checks), `echo-verify`, the SDK projections, the fuzz crate, property tests, Kani harnesses, and the code inventory | A scheduled Fuzz run is green with the gateway targets; Rust, Python, and TypeScript agree on `outcome-v2.json`; the north-star audit shows `http_status` for every entered refund, including a rejected one, and flags a bundle whose basis does not admit its argument |
| 7. North-star recipe | The Stripe recipe moves to §3.1, declaring all five Stripe checks, with an approval window of at most 86 340 seconds; its grants carry policy `/2` with a sum limit partitioned by currency and a scope listing the test connected account; the counting double returns refunds with metadata, serves PaymentIntents, the account, and 403 refusals, requires `Stripe-Version`, honors `Stripe-Account`, and honors the key; `journey.py` checks `observed-by-provider`, the guard refusing a non-test key, and one hostile case per check: a refund above the ratio of `/amount_received`, a currency that does not match the PaymentIntent, the double reporting another account at the lease, the double answering a denied read with 200, a `connect_account` outside the grant, and a refund that exceeds the currency's remaining sum; the README non-claims and the claim ledger are updated; the test-mode command stays the developer's own step (board §0 step 4) | `stripe-refund-journey` is green from the packed wheel, and each hostile case records its code with zero writes; the ledger entry uses §1's claim and non-claim wording |
| 8. Consolidation | §12 A's removals and rewrites in one pull request | The profiles and routes are gone; the specs, ADRs, and plan are amended, and `AGENTS.md`'s summary of the boundary plan is checked against the rewrite; the board is updated; CI is green |

## 16. Non-goals

| Non-goal | Reason |
| --- | --- |
| A conditional provider write | Profile-owned, and settled |
| Automatic retry or re-entry after `unknown`, even within a declared retention | Safe retry is provider semantics (053 §7; plan, "What must not be shared early") |
| Recording an operator's resolution of `unknown` | An out-of-band finding is an assertion the gateway cannot check, and recording it beside provider evidence in the signed outcome would blur the two. Outside `linked`, `unknown` is the honest terminal answer (053 §3.3) |
| Fencing or detecting a lost or restored store | Reinstalling under a new namespace voids every earlier action (§4.5); the count reset is a stated non-claim |
| Releasing sum capacity on proven non-effect or reconciliation | Release needs provider-specific recovery evidence the gateway does not qualify; §6.10's budget is never released |
| Provider permission introspection | HTTP has no provider-neutral form; §5.8's denied reads show observed refusals only |
| Arithmetic beyond §5.6's one subtraction and one ratio | 060 conditions stay comparison-only (060 §2); a wider expression language is a new mechanism needing its own ADR |
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
may say refunds made through the gateway carry a provider link. Until Epic 3
is green, no document may say the gateway enforces a relative ceiling or
checks the account or denied reads at every lease. Until Epic 4 is green, no
document may say a sum budget bounds a link's delegates or that an
account-scope header carries only a grant-listed value. Until Epic 7's ledger
entry exists, no document may say production keeps the vertical's five Stripe
checks.
