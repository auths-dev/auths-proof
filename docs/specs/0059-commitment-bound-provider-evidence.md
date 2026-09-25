# AP-SPEC-059: Commitment-bound provider evidence

- **Status:** Steps 1–4 implemented in `product/runtime/auths-gateway` and
  the gateway clients. Step 5 (live Airtable) is open.
- **Depends on:** [AP-SPEC-053](0053-declarative-credential-isolated-gateway.md)
  (gateway, recipe compiler, attempt store, and outcome states, merged in
  PR #125), [AP-SPEC-057](0057-evidence-program-for-the-exact-action-boundary.md)
- **Enables:** [AP-SPEC-060](0060-evidence-conditioned-authority.md), which
  consumes the outcomes defined here as signed observations
- **Scope:** the gateway writes a token derived from the verified action
  commitment into one recipe-declared provider field. Provider-held
  evidence that carries the token binds that provider record to that exact
  authorized action. This adds one outcome stage, `observed-by-provider`.
- **Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** specify
  implementation requirements

## 1. Decision and claim

The gateway can report that it sent a request (`response-recorded`) and that
a later read found matching state (`observed`). It cannot report that the
state it found was **caused by this authorized action**. AP-SPEC-053 says so
directly: "match is not causation." When the write times out (`unknown`),
nothing can move the operation forward except a human.

This spec makes the provider carry the link. The gateway derives an **echo
token** from the verified action commitment and writes it, alongside the
authorized change, into a provider field the recipe declares for it. Any
later evidence of that provider record that contains the token (a read-back,
and later a provider event) is evidence that the record was written by a
request that carried this exact authorized action's token.

**Claim.** When the gateway reports `observed-by-provider`, the provider
returned, over the pinned TLS origin and under the gateway-held credential,
a record whose echo field equals the token for this namespace, logical
operation, and action commitment. The link to the authorization is as strong
as the premise that **no other party with write access to that provider field
wrote the same token**.

**Not a claim.**

- The token is not a signature. Anyone who knows the namespace, operation ID,
  and commitment can compute it, and the application knows all three. An
  application that keeps another provider credential can forge the link.
  This is the same premise AP-SPEC-053 already makes about alternate
  credentials. It is not new trust.
- The read-back over TLS cannot be shown to others. What is new is that the
  account owner or an auditor can re-read the provider record with their own
  access and find the token, **without trusting the gateway's store**. That
  is the sense in which the evidence is held by a third party.
- Not finding the token never proves the write did not happen.
- Provider business meaning stays unqualified, as in 053.

## 2. Correction to the board wording

The board's backlog paragraph says to "derive the provider idempotency key
from the action commitment." That conflicts with AP-SPEC-053 §3.2, which
derives the optional `Idempotency-Key` from the namespace and logical
operation ID so that **a fresh challenge for the same logical operation
cannot reopen it at a provider that honors the key, within that provider's
retention window**. A key derived from the commitment
changes with every challenge and loses that protection whenever gateway
state is lost.

Decision: the idempotency key stays as 053 §3.2.1 defines it. A recipe opts
in with `write.idempotency_key`, and the gateway derives the key from the
namespace and logical operation ID only. It helps only when the gateway's
claim was lost, and only with a provider that honors it, within that
provider's retention window. The commitment is carried in a **separate echo
field**. For providers that
return the idempotency key in authenticated events (Stripe events carry
`request.idempotency_key`; this is not checked against the current API),
that is an additional binding to the logical operation, not a replacement
for the echo.

## 3. Contract

### 3.1 Echo token

```text
echo = "auths-e1-" || lowercase-hex( SHA-256(
         "auths.gateway-echo/1\0" || namespace || "\0" ||
         operation_id || "\0" || action_commitment ) )
```

The token is 73 ASCII bytes. It is computed by the gateway from the
**verified** commitment in the attempt record. The application never supplies
it, and no submit-time input can change it.

It is derived with a hash rather than taken from the raw commitment for two
reasons: domain separation, and so the namespace, which the commitment does
not otherwise include, is bound.

### 3.2 Recipe declaration

The recipe source (`auths.gateway-recipe-source/1`, 053 §3.2.1) gains one
optional block. It changes the compiled digest, so it needs a new operator
approval:

```json
"echo": {
  "write": "/fields/auths_echo",
  "observe": "/fields/auths_echo"
}
```

- `write` is a JSON pointer to a **fixed key** in the write body template. Its
  value source is the new typed source `echo`. Only the compiler can place
  that source, and only at this pointer.
- `observe` is a JSON pointer into the bounded observation response.
- `echo` requires an `observation` in the recipe. Without one, compile fails
  with `recipe.echo-without-observation`.
- The echo key MUST NOT also be a profile argument, a fixed literal, or a
  path or query segment. Violations fail compile with
  `recipe.echo-conflict`.
- The operator preview MUST show the echo field and state that the token will
  be stored in the provider record and is visible to anyone who can read it.

The recipe language is otherwise unchanged. The echo is the only value the
gateway adds to a request body.

### 3.3 States

```text
               +--> not-entered
claimed -------+--> response-recorded --+--> observed (matched: bool)
               |                        +--> observed-by-provider
               +--> unknown ------------+--> observed-by-provider
                                        +--> unknown (unchanged)
```

- `observed-by-provider` is recorded only when the observation response's
  `observe` pointer holds exactly this attempt's token. It is terminal for
  the attempt.
- A read that finds a **different** token records `observed` with
  `matched: false` and the fact `echo-mismatch`. Another writer changed the
  field, or this write never applied. The gateway does not guess which.
- A read that finds no token leaves `unknown` as `unknown`.
- `unknown` → `observed-by-provider` requires an observation path computable
  from verified fields alone, such as the record ID of an update. A create
  whose record ID is only in the lost response cannot be resolved until the
  recipe language has typed query segments (board §3, "053 extensions").
  That is out of scope here.
- `GatewaySubmitResult` gains `ObservedByProvider { status, evidence }`.
  Python and TypeScript clients gain the same variant. There is no
  `confirmed`, as decided on 2026-09-21.

### 3.4 Evidence record

The attempt store keeps a secret-free record for every
`observed-by-provider`:

| Field | Content |
| --- | --- |
| `channel` | `read-back` in this version |
| `locator` | the observation path, which was built from verified fields |
| `echo` | the token |
| `evidence_digest` | SHA-256 of the exact observation response bytes |
| `evidence` | those bytes, at most 64 KiB, after the recipe's existing response bound |
| `observed_at` | gateway wall-clock time; not authenticated |

The response bytes are kept so the operator can show exactly what the
provider returned. They MUST NOT be logged, and they inherit the provider
data's sensitivity. A recipe whose observation response could contain
secrets MUST NOT declare `echo`, and the preview says so.

### 3.5 Later channels (not in this version)

| Channel | Authenticated to | Needs |
| --- | --- | --- |
| Shared-secret webhooks (Stripe `Stripe-Signature`, GitHub `X-Hub-Signature-256`, Standard Webhooks) | Holders of the webhook secret, including the operator. It resists a hostile app, not a hostile operator. | Inbound HTTPS ingress to the gateway, a webhook secret in the credential store, and a closed, reviewed set of authenticators (no plugins). This is a new credential and deployment surface, so it is an owner decision (board rule 9). |
| Asymmetric provider signatures (such as Standard Webhooks `v1a`) | Anyone with the provider's public key | A provider that uses them for the needed events |

Each channel is a separate, reviewed vertical when it is added. This spec
only fixes the rule they must share: evidence is admitted only if it carries
the exact token from §3.1.

## 4. Where it lives

All changes are in `product/runtime/auths-gateway` and the gateway bindings.
Core is unchanged. The echo source is a closed recipe-compiler feature, not a
provider catalog. Provider meaning stays with the operation, as in 053 §3.

## 5. Epic and acceptance

1. **Fixtures first** (2 days). Hostile recipes: echo at a profile-argument
   key, echo in the path, echo without observation, duplicate echo, echo at a
   non-fixed key. Store transition vectors, including restart during
   `unknown`. Done: vectors fail against the current compiler and store.
2. **Compiler and preview** (3 days). Done: the Airtable recipe compiles with
   `echo`; every hostile case fails with its stable code; the preview shows
   the field.
3. **Engine and store** (4 days). Done: a hosted test with the counting
   provider covers the cases below.
   - A normal write reaches `observed-by-provider`.
   - An injected timeout after delivery goes from `unknown` to
     `observed-by-provider` on the next observation.
   - A provider-side overwrite records `echo-mismatch`.
   - A replay or fresh challenge for the same logical operation still makes
     no second provider entry.
4. **Bindings** (2 days). Done: the Python and TypeScript clients expose the
   new variant, and the public-API inventories are updated in the same
   commit.
5. **Live** (1 day, board rule 9: at most 5 runs, disposable Airtable
   resources, no new credentials). The Airtable update recipe runs through
   the isolated gateway. Done: the result is `observed-by-provider`, and an
   operator using their own Airtable access finds the token in the record.
   The run is recorded in the claim ledger with its limits from §1.

**Acceptance:** steps 1–5 on one exact revision with green hosted CI, plus a
claim-ledger entry that uses §1's claim and non-claim wording without change.
Todoist create stays `response-recorded` or `observed` until typed query
segments exist. That limit is written in the ledger, not hidden.

## 6. Non-goals

- Signing outcomes. The gateway signing what it observed is AP-SPEC-060's
  observer role.
- Deriving the idempotency key from the commitment (§2).
- Negative evidence, or any stage meaning "did not happen."
- Webhook ingress or new provider credentials in this version (§3.5).
- Changing the Stripe vertical (`auths-stripe`). It already derives its
  refund idempotency key from a preimage that includes the nonce and
  evidence digest (`product/integrations/auths-stripe/src/types.rs:902`).
  Whether it adopts an echo field is decided in that vertical.
- Standalone receipts, which board §5 refuses.

## 7. Readings this spec had to choose

| Sentence | Readings | Pick |
| --- | --- | --- |
| Board: "derive the provider idempotency key from the action commitment" | (a) replace 053's key; (b) keep 053's key and add a commitment carrier | (b), §2 |
| Board: "provider-signed webhooks/receipts … third-party evidence" | (a) publicly verifiable signatures; (b) provider-held evidence re-checkable by the account owner | (b) now; (a) only where a provider signs asymmetrically (§3.5). Stripe and GitHub webhooks use shared secrets, so they are not (a). |
| Board: "turns `unknown` into `observed-by-provider`" | (a) always; (b) when the record can be located from verified fields | (b), §3.3 |


### 7.1 Readings fixed during implementation

| Question | Reading |
| --- | --- |
| What `echo.write` points at | A key in the rendered JSON body (`/fields/auths_echo`). The key must not already exist, and it must sit inside a fixed object of the template. The compiler inserts it. An author-written `echo` value anywhere fails with `gateway.recipe.echo-conflict`. |
| Codes | `gateway.recipe.echo-without-observation` and `gateway.recipe.echo-conflict`, under the existing `gateway.recipe.` prefix |
| Token input | The action commitment is hashed as its raw 32 bytes |
| When a read-back is `observed-by-provider` | The observed token equals this attempt's token **and** the observed value equals the verified value. The token without the value records `observed` with `matched: false`. |
| A different token after `unknown` | The attempt stays `unknown`, because there is no `unknown → observed` edge. After `response-recorded`, it records `observed` with `matched: false` and the fact `echo-mismatch`. |
| What counts as an absent token | A missing member or JSON `null`. Any other value that is not the token is a mismatch. |
| What "next observation" means | A replay submission for the same namespace and operation. It triggers one read-only observation when the recipe declares echo with an unchanged digest, the locator and expected value equal those recorded at claim time, and the stored stage is `unknown` or `response-recorded`. It never writes. The token comes from the stored commitment. |
| Crashed attempts | A record left in `attempting` is never re-observed, because it cannot be told apart from one in flight. |
| What the application sees | `observed-by-provider` with status, channel, token, evidence digest, and time. `echo-mismatch`, the locator, and the response bytes stay in the store. |
| Stored record | Schema `auths.gateway-attempt/2`. Records in the earlier schema are rejected rather than read. |
| Concurrent re-observations | Two racing re-observations of one file-store record may each record valid evidence, and the last write wins. This fits the single-host scope. |

## 8. Verification and release boundary

Hosted CI on the exact revision is the gate. This spec runs no checks. Until
step 5 is recorded, no document may describe gateway outcomes as bound to
provider records.
