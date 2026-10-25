# ADR 0020: Materialize a provider credential after task admission

**Status:** Partially implemented for AP-SPEC-071. The gateway library now has
a connection-specific, operator-installed materializer port invoked after
task read/write reservation. It checks the returned subject, pinned effective
authority digest and lease deadline; a configured source reference cannot
fall back to the ordinary bearer path. The live Jules runs still installed a
checked, short-lived access token before task activation. No Google custody
adapter or installed CLI configuration uses the new port yet, so those runs do
not qualify as post-admission renewal or durable OAuth custody.

**Date:** 25 October 2026

## Context

A human task pins a connection ID, account subject, connection generation and
reviewed recipe. The current gateway credential store commits to the exact
secret bytes at a credential generation. Its `lease_secret` returns those same
bytes. A Google access token expires during a task, while the underlying
employee refresh grant can remain valid. Replacing the connection's secret by
the normal rotation path changes its generation and correctly invalidates the
task. Mutating the committed bytes under the old generation would violate the
store contract. Neither option supplies post-claim renewal for an already
approved task.

This is a general distinction: the stable, operator-approved **source of
provider authority** may be an OAuth refresh grant, workload identity, or
another protected source, while the short-lived **request credential** is
materialized for one provider operation. The source must remain bound to the
same provider account and effective privileges throughout the task.

## Decision

Add a custody-owned `CredentialMaterializer` port at the execution boundary.
The connection record names a stable, protected source reference and its
generation, not a bearer supplied by the agent or task application. A
materializer is installed by the operator for that exact reference; it is not
selected by a recipe or action. The existing exact-byte credential store stays
valid for static secrets. A connection opts into the materializer explicitly;
there is no fallback from a failed materialization to a stale installed bearer.

The gateway calls the port **only after** native task admission and durable
operation reservation, and before provider entry. The call carries a closed
custody context: task and operation IDs, connection ID and generation,
credential-source generation, provider account subject, installed recipe
digest, request verb/class, and a short deadline. The materializer verifies
that context against the pinned source and returns a zeroizing, deadline-bound
request-credential lease directly to gateway transport. The agent and
application never receive the secret. Task or recipe data cannot name a
materializer endpoint, source path, scope, audience, or token body.

The materializer must check that the source generation has not changed and
that the newly materialized credential has the **same subject and no wider
effective authority** than the connection approved at task signing. A changed
subject, client, audience, scope, source generation or provider account is a
connection change: the old task fails closed and needs new approval. Ordinary
refresh that preserves those bindings does not advance the connection
generation. Source revocation and materializer failure deny the operation;
there is no silent reconsent or provider request using an expired token.

The lease has a bounded lifetime no later than the provider's expiry, the
task expiry or a short custody TTL. The gateway reloads the connection and
rechecks task revocation and lease validity immediately before entry. One
materialized bearer may be reused only within that bounded lease and the same
admitted operation; a different operation needs its own admission and lease.
Materialization itself is not evidence of provider entry. The existing
conservative read/write budgets and unknown-outcome rules still apply once an
operation is reserved or provider entry becomes possible. Credentials and
refresh material are absent from command arguments, agent channels, task
cards, receipts, diagnostics and public logs.

## Jules development adapter

The protected demo_co grant remains in its owner-only local file. An Auths
custody adapter may read it through a protected local interface after the
gateway's task admission. For every lease it must validate the pinned grant
file and producer generation, Desktop OAuth client ID, Google token endpoint,
the exact `openid`, `userinfo.email` and `drive.file` scope set, and live
Google UserInfo `sub`, verified email and hosted domain for Jules. A refresh
uses that same Desktop client and stays in memory. If Google reports a changed
granted-scope set, the adapter refuses the lease. The adapter returns only the
short-lived access token to gateway custody. It does not execute the Google
read/write or change task authority.

The current `google_write_credential.py` already performs most grant and
subject checks before installation. It is a development reference for the
materializer, not the materializer itself. The installed implementation must
prove that a task is durably admitted before asking this adapter for a token,
and that a grant-file swap, mismatched source generation or widened scope is
refused before the provider request.

## Qualification and evidence

The port and every adapter need an operator-pinned descriptor and a distinct
qualification case. Synthetic tests must cover: no invocation before native
admission; wrong task/operation/connection/generation/recipe/subject; source
swap; expired token; refresh and UserInfo failure; wider scopes; bearer
redaction; revocation between lease and entry; concurrent last-budget claim;
and restart. A test should force the installed bearer to expire, refresh from
the unchanged Jules grant after a new admitted action, and observe one real
provider read or write without changing the signed connection generation.
The independent provider probe remains the evidence of effect; a token lease
or gateway HTTP status alone is insufficient.

The same port must support an independently implemented second-provider
adapter or a static-secret implementation under the same gateway call shape.
Google-specific OAuth checks remain in its vertical/custody adapter. The
recipe interpreter remains data-only and has no Google branch.

## Rejected approaches

1. Rotate the installed bearer while retaining the old task: the signed task
   pins a generation that rotation invalidates.
2. Replace secret bytes under an unchanged commitment: this breaks the
   credential-store's exact-secret invariant.
3. Let the agent or task CLI supply a freshly refreshed bearer: that bypasses
   custody and subject binding.
4. Let the broker execute the provider request: that bypasses the gateway's
   task claim, reviewed recipe and receipt path.
5. Refresh only once at installation and claim that a 30-minute task is
   renewal-safe: expiry, revocation and delayed execution remain unhandled.
