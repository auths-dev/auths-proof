# ADR 0014: Qualify the Stripe refund recipe against a disposable Connect account

**Status:** Proposed. No family is a candidate or qualified. Acceptance requires
the executable family corpus, independent oracle and protected evidence below.

**Date:** 6 October 2026

## Scope and identity

The proposed family is `stripe-refund-v1`, starting from
[`examples/stripe-refund-approval/recipe.json`](../../examples/stripe-refund-approval/recipe.json)
and its profile lock. Qualification binds the compiled recipe, profile lock,
reviewed provider contract, candidate executable and semantic closure, Linux
x86_64 target, PostgreSQL schema and `aws-secrets-manager-v1` custody. A source
file or provider name alone identifies none of these claims.

The contract is Stripe API `2025-03-31.basil` in `provider-test-mode`. A test-mode
Connect account must differ from the platform account. Only disposable test
payments may be refunded; no customer data or real-money claim is in scope.
The gateway continues to interpret recipe data. Provider semantics and the
qualification oracle remain in the release harness, outside the runtime build.

## Oracle and provider assumptions

The test-only oracle must independently derive the POST URL, ordered form body,
version and account-scope headers, payment-intent basis read, refund locator and
fresh observation from the reviewed action and evidence. It must compare both
accepted and refused cases with the candidate, including request/evidence
commitments. It may reuse canonical encoding and cryptographic primitives;
calling the gateway's evaluator to produce the expected result is not an oracle.
The old Stripe vertical's bounded-refund evaluator is a reference for arithmetic,
not proof that the current recipe shares every budget or recovery meaning.

| Assumption | Required protected observation |
| --- | --- |
| The credential addresses test mode | The `rk_test_` prefix and `/v1/balance` `livemode=false` guard both hold. |
| Credential identity stays bound | The unscoped `/v1/account` result agrees with the installed platform commitment on every lease. |
| Restricted reads are refused | Unscoped customers and payouts reads return the recipe's declared 403 statuses. |
| The selected account is distinct | Record sanitized platform and connected identifiers; action reads, write and refund read-back carry the exact verified `Stripe-Account`. Credential reads do not. |
| The ceiling uses the selected payment | Fresh amount and currency evidence passes at 50%, and refuses at boundary plus one or with a changed currency. |
| The exact request is entered once | Provider and credential witnesses count replay, fresh-challenge replay, race, restart and crash cases separately from the corpus's expected counters. |
| A recorded refund is observed | Fresh GET of the returned refund identifier matches amount and echo under the selected account. |
| The idempotency declaration held in this run | Inspect a deliberate duplicate request inside the declared 86,400-second window; do not infer indefinite retention. |

Stripe documents refund amounts in minor units and a remaining-refundable
constraint ([refund API](https://docs.stripe.com/api/refunds/create)); the recipe's
50% basis is not an atomic reservation of that provider balance. Stripe documents
server-side connected-account selection by header
([Connect authentication](https://docs.stripe.com/connect/authentication)). That
does not establish that the platform token is restricted to one connected account.

## Corpus, recovery and publication gates

The maintained offline seeds are the recipe/profile lock, gateway
`attempt-scenarios-v3.json`, `bounds-aggregate.json`, `outcome-v2.json` and
`hostile-recipes-v2.json`. They must be expanded into the family-owned
`auths.qualification-corpus/1` with executable coverage of every mandatory wall
scenario; they are not the missing protected family corpus.

The live corpus must additionally exercise every declared capability, provider
secret rotation, production doctor, two-host restart, redaction of actual support
bundles and installed Python/TypeScript clients with no token or source import.
The current recipe declares no lost-response recovery capability. Response loss
must remain `unknown`; delayed read-back may resolve only when the gateway has
retained the recipe's required response locator. `recovery` is not applicable
because this recipe cannot locate an unrecorded refund response. Observer
rotation is not applicable unless the qualified installation declares one.

Before a candidate run, resolve the production qualification bootstrap described
in [`qualification/README.md`](../../qualification/README.md): no optional policy,
test-feature executable or fabricated intermediate attestation can stand in for
the exact shipped target. Resource bindings and expected digests must also be
fixed by a reviewed corpus expansion before execution, rather than copied from
the candidate's answers.

Use a maximum 30-day attestation and rerun before renewal or any tuple change.
Revoke on evidence/custody compromise, unauthorized entry, broken account binding,
changed provider behavior or a materially false published assumption. Publish
only sanitized disposable identifiers, bounded evidence, signed artifacts and
explicit exclusions. Provider availability, settlement, indefinite idempotency,
global exactly-once behavior and prevention of writes by other actors remain
provider-owned. No live evidence is claimed by this decision record.
