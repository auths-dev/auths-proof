# Stripe refunds behind approval by any two of three managers and a per-agent limit

Your AI agent may refund a Stripe payment only when any two of your three
managers approve that exact refund, whichever two answer, and only up to its
own limit: at most
50.00 per refund, 60.00 per currency per UTC day, and two refunds per UTC
day. The Stripe key lives only in the Auths gateway, which also checks the
key and the payment with Stripe before each refund. An auditor checks every
refund afterwards, offline.

**10 steps. The unattended run of all of them (step 10) took 8.1 s on an
Apple-silicon laptop once the wheel and gateway were built.** Building the
gateway the first time takes a few minutes.

| Who | Holds | Can do |
| --- | --- | --- |
| Root (you, the operator) | root key | issue the agent's grant, with its limits |
| Managers A, B, C | one key each, on their own machines | review and approve (or decline) one exact refund with `auths approve`; approve only, with no authority to act |
| Agent | its key and grant | request approvals, collect them, sign its exact refund, submit; never sees the Stripe key or a manager's key |
| Gateway | the Stripe key | submit a refund only after verifying approvals and limits and checking the key and the payment with Stripe |
| Auditor | two pinned values | verify every refund from a file, with no network |

**Or start from a generated project.** `auths init stripe-refund-approval
--gateway "$(command -v auths-gateway)"` writes this deployment into a new
directory: one command per step below, each role's key in its own directory,
and `bin/selftest`, which runs the hostile refunds, the audit, the tampered
bundles, and a key scan against the double. It is a development deployment:
one OS user, a file attempt store, and a software observer key, with
development custody for every role, so it cannot establish credential
isolation. This README stays the explained, step-by-step path.

## Steps

Run from this directory. You need Python 3.9+, Rust (for the gateway), and a
checkout of this repository.

**1. Install the SDK and the gateway.**

```sh
pip install maturin
maturin build --profile python-extension --manifest-path ../../bindings/python/Cargo.toml --out dist
pip install dist/auths-*.whl
cargo install --locked --path ../../product/runtime/auths-gateway --features loopback-provider
```

`--features loopback-provider` lets the gateway talk to the local Stripe
double in steps 4 and 5. Leave it out when you use real Stripe (see below).

**2. Pick a private working directory.** The gateway requires absolute,
owner-only paths.

```sh
export WORK=$(mkdir -p -m 700 /tmp/auths-refunds && cd /tmp/auths-refunds && pwd -P)
```

The gateway's Unix sockets live under this directory: the app socket you
name, and its admin socket at `<state-dir>/admin.sock`. A Unix socket path
holds at most 103 bytes on macOS and 107 on Linux (`sun_path`, less its
terminating NUL), so keep the directory short; the gateway refuses a longer
path with `gateway.serve.app-socket-too-long` or
`gateway.serve.admin-socket-too-long`, giving the length and the limit.
`pwd -P` is there because the gateway also refuses a state directory reached
through a symbolic link, and `/tmp` is one on macOS.

**3. Create the root, three managers, the agent, and the trust.**

```sh
python refunds.py setup --state "$WORK/state"
```

This writes development keys for `root`, `manager-a`, `manager-b`,
`manager-c`, and `agent`, one `auths approve` signer file per manager
under `state/signers/` (development custody over that manager's key), and:

- a trusted context for the gateway: refunds need **approvals from any two
  of the three managers**. The root is the only trust anchor, and it may
  delegate once, to the agent; one authorized branch from one actor under
  one root is the whole composition. Managers A, B, and C are approver
  anchors (`raw-key-v1`, the trust's validity, expiry-only status): the
  verifier accepts their approvals and nothing else from them, and they hold
  no authority of their own. The approval requirement is any 2 of
  {A, B, C}; the agent's own approval never counts. Each approval is a native
  approval statement bound to the exact refund, the gateway's audience and
  challenge, the approval window, and the requirement, collected from each
  manager as a remote approval (`propose_mcp_approval`, `approval_requests`,
  `collect_approvals`); the agent signs the refund itself
  (`sign_approval_action`);
- the agent's grant from the root, carrying a bounded-policy commitment:
  `amount` at most 5000 (cents), at most 2 refunds and at most 6000 (cents)
  per currency (EUR or USD) per fixed, epoch-aligned 86400 s window, which is
  a UTC day, and only in the connected account `acct_1AuthsConnected`. The
  count and the sum bound the agent and anyone it delegates to together.
  `--ceiling`, `--max-count`, `--sum-limit`, `--currencies`,
  `--connect-account`, and `--window-seconds` change it.

It prints `recipe_digest` and `trusted_context_sha256`. Keep both.
`recipe.json` is the gateway recipe for `POST /v1/refunds`, in recipe
source `/2`. `auths-gateway review --recipe recipe.json --profile-lock
profile.lock.json` shows everything it declares:

- `Stripe-Version`, pinned and sent on every request, and required back on
  every response;
- a credential guard: the key must start with `rk_test_`, `GET /v1/balance`
  must report `livemode: false`, `GET /v1/account` must name the account
  you install with, and `GET /v1/customers` and `GET /v1/payouts` must be
  refused with 403. The gateway checks the account and the two refusals
  again every time it takes the key from its store;
- `Stripe-Account`, set from the refund's `connect_account`, which the grant
  must list;
- a relative ceiling: after taking the key, the gateway reads the
  PaymentIntent and refuses a refund above half of its `amount_received`,
  or in a currency other than the PaymentIntent's;
- the sum limit per `currency` that the grant must carry;
- an `Idempotency-Key` it derives from the namespace and operation ID, with
  a declared 86 400-second retention the gateway cannot verify. Because of
  that retention, each refund's approval window is 86 340 seconds: the
  gateway refuses, before any claim, an action whose window plus its
  60-second entry deadline exceeds the declared retention;
- a read-back: the gateway writes an echo token derived from the approved
  refund into `metadata[auths_echo]` and reads the refund back.

`profile.toml` generated `generated.py` and `profile.lock.json` with
`auths generate`.

**4. Start Stripe (the local double).**

```sh
export STRIPE_KEY=rk_test_mock_local     # any rk_test_ token for the local double
python mock_stripe.py --ledger "$WORK/ledger.jsonl" \
  --token-sha256 $(printf '%s' "$STRIPE_KEY" | shasum -a 256 | cut -d' ' -f1) &
# it prints its port, for example 54321
```

**5. Install the gateway with the Stripe key on stdin, and start it.**

```sh
mkdir -m 700 "$WORK/gateway"
printf '%s\n' "$STRIPE_KEY" | auths-gateway install --state-dir "$WORK/gateway" \
  --recipe recipe.json --profile-lock profile.lock.json \
  --trusted-context "$WORK/state/trust/gateway.context.cbor" \
  --approve-digest <recipe_digest from step 3> \
  --provider stripe --alias refunds --account-label acct_1AuthsPlatform0 --credential-stdin \
  --loopback-provider 54321
unset STRIPE_KEY
auths-gateway observer-init --state-dir "$WORK/gateway"
auths-gateway serve --state-dir "$WORK/gateway" --app-socket "$WORK/app.sock" \
  --loopback-provider 54321 &
```

If your state directory has to be long, `serve --admin-socket PATH` moves
the admin socket into another owner-only directory (mode 0700, owned by you,
not reached through a symbolic link); pass the same `--admin-socket` to
`disable`, `revoke`, `rotate`, and `doctor`.

`install` makes the guard's four reads before it stores the key, and stores
nothing if one fails: a key without `rk_test_` is refused
(`gateway.install.credential-guard`) before any read. `observer-init` prints
`observer_anchor.principal`: the key the gateway signs its outcomes with.
Give it and `trusted_context_sha256` to your auditor.

**6. The agent asks for a refund; managers A and B approve; manager C never answers; the gateway submits.**

The agent writes one approval request to each of the three managers. Each
request is a file of text (`auths-ar2-…`) you can send any way you like, for
example pasted into chat; it is not secret, and it carries no text of its
own.

```sh
python refunds.py request --state "$WORK/state" --operation-id refund-1 \
  --payment-intent pi_mock_journey --amount 1500 --out "$WORK/refund-1"
```

The refund is in USD (`--currency`) in the connected account the grant lists
(`--connect-account`). Any two managers answer, each on their own machine:

```sh
auths approve "$WORK/refund-1/manager-a.request" \
  --signer "$WORK/state/signers/manager-a.json" --out "$WORK/refund-1/manager-a.response"
auths approve "$WORK/refund-1/manager-b.request" \
  --signer "$WORK/state/signers/manager-b.json" --out "$WORK/refund-1/manager-b.response"
```

`auths approve` checks the request natively, prints the review that
the SDK derives from the exact refund the manager approves (the arguments,
the requesting agent, the approvers and how many must approve, and the
approval window), and asks
`Approve this action? [y/N]`. Only `y` signs; without a terminal it signs only
with `--yes`. `--decline` signs a refusal instead. The signer files that step 3
wrote are development custody: a seed file on disk, and the command says so.
In production each manager points `--signer` at their own custody adapter.

Manager C never answers, and need not: whoever answers first counts. The
agent collects whatever responses exist, signs its exact refund, and submits:

```sh
python refunds.py submit --state "$WORK/state" --socket "$WORK/app.sock" \
  --operation-id refund-1 --responses "$WORK/refund-1"
```

`submit` sends a refund to the gateway once two managers approved it, and
decides nothing itself: only the gateway enforces the approval threshold,
the ceiling, the per-window count and sum, and at most one run per operation
ID. It prints the gateway's result with `"decided_by": "gateway"`, here
`{"outcome": "observed-by-provider", "status": 200, "decided_by": "gateway",
"bundle": "appended", ...}`: the gateway checked the key and the
PaymentIntent (60.00 received, so at most 30.00 refundable here), sent the
refund, and found its echo token in the refund it read back. The ledger has
one write. The record lists the managers who approved (`"approved"`), those
who have not answered (`"pending"`, here manager C), and any who declined
(`"declined"`). One decline beside two approvals does not stop
the refund. When too many managers declined for two approvals to remain
possible, or fewer than two approved so far, no proof exists and nothing is
sent: `submit` prints `"outcome": "not-submitted"` with
`"decided_by": "approver"` (`"reason": "approvers-declined"`) or `"client"`
(`"reason": "approvals-incomplete"`, with who is still `waiting`), never a
gateway code.

**7. Watch the refusals.** These happen before any credential lease:

| Attempt | Decided by | Result | Stripe calls |
| --- | --- | --- | --- |
| The agent lowers the threshold (`request --required 1`); only manager A approves | gateway | `denied` `approval-threshold-not-met` | 0 |
| The agent lowers the threshold to 1; managers A and B both approve it | gateway: each approval is bound to the requirement it was asked for, so none counts toward the installed one | `denied` `approval-threshold-not-met` | 0 |
| Manager A, also given an agent grant (`refunds.py grant --agent manager-a`), submits a refund that managers A and B approve | gateway: A is in the proof's authority chain, so its approval never counts and only B's does. The SDK refuses to author this proposal at all; the journey builds the bundle by hand, as a hostile client would. The denial comes before any claim, so it uses no count slot | `denied` `approval-threshold-not-met` | 0 |
| 90.00, above the 50.00 ceiling | gateway | `not-entered` `gateway.policy.above-ceiling` | 0 |
| `--connect-account acct_1AuthsOtherAcct`, which the grant does not list | gateway | `not-entered` `gateway.policy.scope-denied` | 0 |
| 50.00 when 45.00 of the day's 60.00 USD is left | gateway | `not-entered` `gateway.policy.sum-exhausted` | 0 |
| A third refund on the same UTC day | gateway | `not-entered` `gateway.policy.window-exhausted` | 0 |
| `refund-1` requested again, with fresh approvals | gateway | `not-entered` `gateway.attempt.replay` | 0 |
| `refund-1`'s proof sent for another refund | gateway | `denied` `action-body-mismatch` | 0 |
| The first lowered-threshold refund requested again at the installed threshold, after the window is full | gateway | `not-entered` `gateway.policy.window-exhausted`: a verification denial claims nothing, so this is not a replay | 0 |
| Managers B and C run `auths approve … --decline` | managers B and C | `not-submitted` (`approvers-declined`): manager A's approval alone cannot make a quorum, so nothing is sent | 0 |
| Manager A's response collected twice, beside manager B's | the agent's collector | `not-submitted` (`approvals-incomplete`): a second response from one manager refuses that manager (`approval.duplicate-response`), leaving one approval | 0 |
| A request edited to show another amount | manager A's `auths approve` | refuses `approval.action-mismatch` and signs nothing | 0 |

`request` accepts an operation ID it requested before: it keeps the earlier
request as `pending/<id>.json.N` and says on stderr that the gateway's
attempt store decides whether the ID may run again. `request --required N`
names another threshold than the installed one and says so on stderr; the
gateway, which holds the installed requirement, refuses what it produces. The
agent's collection checks that every response signs its own request's
approval statement byte for byte; the gateway's verifier checks every
signature and the threshold of its installed trust.

Refund 4 (40.00) is approved by managers A and C while manager B declines: a
different pair from refund 1, and one decline beside two approvals still
submits. It names a PaymentIntent whose charge is already fully refunded. It is authorized and within half of that
PaymentIntent's 100.00, so the gateway enters it and records
`{"outcome": "response-recorded", "status": 400}`: one Stripe write, no
refund. It still uses the agent's second refund of the day, which is why the
third refund above is refused.

These are also decided by the gateway, by the recipe's checks after it takes
the key from its store, and before any write. Each such refusal still uses a count
slot, which is never released, so step 10 makes them as a second agent with
its own grant (`python refunds.py grant --agent agent-checks --max-count 4`):

| Attempt | Result | Stripe writes |
| --- | --- | --- |
| 30.01, above half of the PaymentIntent's 60.00 | `not-entered` `gateway.relative-ceiling.above` | 0 |
| `--currency eur` against the USD PaymentIntent | `not-entered` `gateway.relative-ceiling.binding-mismatch` | 0 |
| Stripe (the double) reports another account for the key | `not-entered` `gateway.credential.account-mismatch` | 0 |
| Stripe (the double) answers `GET /v1/customers` with 200 | `not-entered` `gateway.credential.capability-excess` | 0 |

**8. Export the audit bundle.**

```sh
python refunds.py export --state "$WORK/state" --out audit-bundle.json
```

It holds one entry per operation ID: the first submission, or a later one
that the gateway recorded in place of a first one it did not. Resubmissions
of an operation ID are not in the bundle; the gateway's attempt store is the
complete record. Each entry carries the proof and the action, and also the
gateway-signed outcome when the gateway recorded that submission. The
gateway records nothing, and so signs no outcome, for a submission it
refuses before it claims the operation: a proof that does not verify, a
refund above the ceiling or in an account the grant does not list, or any
submission while the connection is disabled, revoked, or cannot be
prepared, or while the attempt store or the clock is unavailable. Three of
step 7's refusals are such entries: the lowered threshold that two managers
approved, above the ceiling, and the unlisted account. The first
lowered-threshold refund's entry is the signed one of its later retry. The bundle also holds every approval
response the agent collected (declines included), and the installed recipe
and trusted context.

**9. Audit offline.** With the gateway stopped and the network off:

```sh
auths-gateway audit --bundle audit-bundle.json \
  --trusted-context-sha256 <from step 3> --observer <from step 5> \
  --allow-unverified-refusals
```

For every refund it re-verifies, with the gateway's own verifier:

- the proof chain from the agent to the root, and each approving manager's
  signature;
- the approval threshold of the pinned trusted context (the report lists,
  per entry, the managers whose approvals counted; the agent, which signed
  the refund, is never among them);
- the ceiling, and the per-window count and per-currency sum recounted
  across the bundle without relying on the order of the entries;
- the connected account: every bounded grant the refund rests on lists the
  account it names, as the recipe's account scope requires;
- the gateway-signed outcome: signed by the pinned observer, for this exact
  action, with its recorded stage, the time the gateway evaluated it, the
  counters it reserved, which must match the ones the audit derives, and
  the PaymentIntent amount it read, which must admit the refund;
- the provider's result, reported beside the verdict as `provider_result`:
  the HTTP status and response digest the gateway recorded. Refund 1 is
  `observed-by-provider` with 200; refund 4 is `verified` (authorized and
  entered) with `http_status` 400 beside it.

The report also lists each recorded approval response, so it shows who
approved and who declined. Responses never change a verdict: only the verified
proof counts an approval, and a decline carries no authority.

Each entry is `verified` (`audit.verified`), `refused` with the gateway's
stable code, `unverified`, or `inconsistent` with an `audit.*` finding.
`verified` and `refused` rest on the outcome the gateway signed. An entry
without one is `unverified`: the audit still re-verifies its proof, and
`admitted` says whether the proof passed, but nothing in the bundle shows
what the gateway did with it.

The command exits non-zero when it refuses the bundle as a whole, as for
replaced trust (`audit.trust-pin-mismatch`); when any entry is inconsistent
(`audit.inconsistent`), as for a flipped proof byte
(`audit.entered-without-authority`), a swapped action
(`audit.outcome-commitment-mismatch`), or a replayed outcome
(`audit.outcome-invalid`); and when any entry is unverified
(`audit.unverified`). `--allow-unverified-refusals` lets an unverified entry
pass when the audit itself refuses its proof, as for the three refusals of
step 7 that the gateway made before recording anything. An unverified entry
whose proof verifies still fails: a refund whose outcome was left out of the
export, or a valid refund the gateway refused while its connection was
disabled. The option has a cost: a refund whose outcome was removed and whose
proof was then altered also passes, as `unverified`, just as a refund removed
from the bundle would.

**10. Or run all of it unattended.**

```sh
python journey.py --gateway "$(command -v auths-gateway)"
```

This runs steps 3–9 with every manager answering through `auths approve`:
refund 1 approved by two managers while the third never answers (its
status stays `pending` and the refund is authorized), refund 4
approved by another pair beside a decline, two declined managers, a manager
approving its own refund, a response collected twice, a tampered request, a key without `rk_test_` refused at
install, every refusal of step 7 before and after the credential lease, the
audit with and without `--allow-unverified-refusals`, five tampering cases,
and one case that shows the limit of that option. Every submission goes
through `gateway_witness.py`, a relay on the application socket that runs as
its own process and records each exchange. The journey fails if a hostile
request is refused anywhere but at the gateway: each must print
`"decided_by": "gateway"` with the expected result, and the witness must
have seen exactly one submission to the gateway for it, answered with that
same result. A negative control refused by `request --precheck` must fail
that check. It checks every result, including exactly two Stripe writes
(refund 1, and the rejected refund 4), no write for any refusal and no
Stripe call at all for the refusals before the lease, the `Idempotency-Key`
each write carried, `Stripe-Version` on every request, `Stripe-Account` on
every request about the refund and on none that tests the key, refund 1's
read-back, and the audit's `http_status` of 200 and 400.
It prints timings. It then restores the gateway's store from a backup taken
before the first refund, which keeps the shared connection record but no
claim, and resubmits refund 1's approved proof. With the claim gone the
gateway sends it again, with the same key, and the double answers with the
first refund: three writes, one refund. CI runs it from the packed wheel
(`.github/workflows/sdk-recipes.yml`, job `stripe-refund-journey`).

### Optional: a client-side pre-check

`python refunds.py request --precheck` refuses, before it writes any request,
a refund whose `--required` is below the gateway's threshold
(`approvals_required` in `setup.json`) or whose amount is above the recorded
ceiling. It prints
`{"outcome": "not-submitted", "decided_by": "client", "reason": "precheck", ...}`
and exits 0. It is a client-side pre-check, not an enforcement boundary: it
only spares managers a request the gateway would refuse, and the gateway
enforces every one of these rules whether or not it runs. It is off unless
you pass the flag, and the journey's hostile cases run without it.

## From npm

The same journey runs from the npm package, `@auths-dev/sdk`, against the
same recipe, gateway, and Stripe double. `typescript/refunds.ts` and
`typescript/journey.ts` are the TypeScript `refunds.py` and `journey.py`, and
`generated.ts` is the command contract the package's `auths generate`
wrote from the same `profile.toml`. You need Node 20.6+ and Rust. From
`typescript/`:

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack --version 0.15.0 --locked
npm --prefix ../../../bindings/typescript ci
npm --prefix ../../../bindings/typescript run build:wasm
npm --prefix ../../../bindings/typescript run build
npm pack ../../../bindings/typescript && mv auths-dev-sdk-*.tgz auths-dev-sdk.tgz
npm install && npm run build
cargo install --locked --path ../../../product/runtime/auths-gateway --features loopback-provider
node build/journey.js --gateway "$(command -v auths-gateway)"
```

The last command took 7.0 s on an Apple-silicon laptop once the package and
gateway were built. Each `python refunds.py …` step above is
`node build/refunds.js …` with the same flags (`--precheck` included) and
prints the same JSON records, each manager runs `npx auths approve …` with
the same flags, and `journey.js` takes the same test-mode options as
`journey.py`. It makes the same checks, through the same
`gateway_witness.py` process, except the state-loss resubmission. The package installs from the tarball you packed,
so this directory keeps no lockfile. CI runs it from the packed tarball as
job `stripe-refund-journey-npm`.

## Real Stripe, test mode

The same journey runs against Stripe's test mode with your own keys.
Automated runs here never call Stripe; run this yourself. You need a
test-mode platform account with one connected account that can accept card
payments, your test secret key (`sk_test_…`, used below only to create two
PaymentIntents), and a restricted test key (`rk_test_…`) for the gateway
that may read the balance, the account, and PaymentIntents and create
refunds on connected accounts, and may not read customers or payouts.
Stripe answers a request the key lacks permission for with 403; confirm in
your Dashboard that the restricted key's refusals carry `Stripe-Version`,
since otherwise `install` refuses the key
(`gateway.install.credential-capability`).

The run makes exactly one refund (15.00) against the first PaymentIntent,
one 40.00 refund request that Stripe rejects because the second
PaymentIntent is already refunded, and the reads the recipe declares. The
double-only cases (another account reported, a denied read answered) and the
state-loss resubmission run only against the double.

```sh
export STRIPE_TEST_SECRET_KEY=sk_test_...        # your own test-mode secret key
export STRIPE_TEST_RESTRICTED_KEY=rk_test_...    # your restricted test key, for the gateway
export CONNECT=acct_...                          # your connected account
stripe_post() {  # path, then form fields, in the connected account
  printf 'user = "%s:"\n' "$STRIPE_TEST_SECRET_KEY" | curl -s -K - -H "Stripe-Account: $CONNECT" \
    "https://api.stripe.com/v1/$1" "${@:2}" | python -c 'import json, sys; print(json.load(sys.stdin)["id"])'
}
payment() {
  stripe_post payment_intents -d amount="$1" -d currency=usd -d payment_method=pm_card_visa \
    -d confirm=true -d 'automatic_payment_methods[enabled]=true' \
    -d 'automatic_payment_methods[allow_redirects]=never'
}
PI=$(payment 6000)
REFUNDED=$(payment 10000) && stripe_post refunds -d payment_intent="$REFUNDED" > /dev/null
PLATFORM=$(printf 'user = "%s:"\n' "$STRIPE_TEST_RESTRICTED_KEY" | curl -s -K - \
  https://api.stripe.com/v1/account | python -c 'import json, sys; print(json.load(sys.stdin)["id"])')
cargo install --locked --path ../../product/runtime/auths-gateway --root "$WORK/stripe"
python journey.py --gateway "$WORK/stripe/bin/auths-gateway" --stripe-test-mode \
  --payment-intent "$PI" --rejected-payment-intent "$REFUNDED" \
  --platform-account "$PLATFORM" --connect-account "$CONNECT"
```

The default gateway build pins `https://api.stripe.com` to a public address
and has no loopback option. The restricted key reaches only the gateway's
install step, on stdin; the secret key reaches only `curl`.

## What this does not claim

- Development keys stand in for custody. In production the root and each
  manager sign through their own custody adapters.
- A production gateway cannot yet sign outcomes. Its observer key must be
  held in KMS or an HSM, and the shipped gateway has no such client yet
  ([#190](https://github.com/auths-dev/auths-proof/issues/190)). This journey
  uses a development observer key.
- The recipe is not qualified. Under ADR 0013, a recipe earns a qualified
  provider claim only through its own later ADR, with differential and
  live-provider evidence.
- Any two of the three managers suffice, whoever answers; the approver set
  and the threshold are the operator's, fixed in the installed trust, never
  the request's. A decline carries no authority: it stops a refund only when
  too few managers remain to approve it.
- A request is not confidential: anyone who receives it sees the refund. The
  requester it names is not authenticated by the request; the agent's own
  signature on the refund is. The guarantee that a manager signs what they saw holds only for
  a surface that shows what the SDK returned, as `auths approve` does.
- Managers approve; they cannot act. The trust anchors only the root, so
  only the agent, under its grant from the root, can submit a refund, and no
  number of approvals stands in for the agent's signature and grant.
- The audit checks the entries in the bundle. It cannot show that none were
  left out; the gateway's attempt store is the complete record.
- The bundle keeps one entry per operation ID. A resubmission of an
  operation ID is not in it, and an entry without a signed outcome is
  replaced by a later submission of the same ID that the gateway recorded:
  the audit then reports that later refusal, as `refused`, not the first.
  The three refusals step 9 accepts as `unverified` are the ones no later
  submission replaced; the first lowered-threshold refund is audited through
  its retry.
- An `unverified` entry is evidence neither way: without the gateway's signed
  outcome, the bundle does not show whether the gateway entered the provider.
  `--allow-unverified-refusals` accepts such an entry only when the audit
  itself refuses its proof, so it also accepts a refund whose outcome was
  removed and whose proof was then altered, as it would a refund removed from
  the bundle. A production gateway signs no outcomes yet (above), so its
  bundles fail the audit with or without the option.
- The per-window count and sum are recounted at the time the gateway
  evaluated each submission, which its signed outcome carries, so an outcome
  requested in a later window still counts in its submission's window.
- Windows are fixed UTC days, not rolling: up to four refunds, and up to
  120.00 per currency, can land within 24 hours across midnight UTC.
- The sum is of approved refund amounts, not amounts Stripe settled. A slot
  or sum capacity is never released, even for a refund that was refused
  after the credential lease or that Stripe rejected.
- The gateway reads the PaymentIntent after taking the key and before the
  write; the write is not conditional on it, and the amount received or the
  currency may change in between. The ratio and what `amount_received`
  means are the recipe author's. Stripe still applies its own limit on the
  refundable amount, as refund 4 shows.
- The account read shows which account Stripe reported for the key when the
  gateway took it, not at the write, and not that the identifier names one
  legal entity.
- The denied reads show only that `GET /v1/customers` and `GET /v1/payouts`
  were refused when made. They do not show that the key lacks any other
  permission, that a refusal had a permission reason, or that the key's
  permissions did not change before the write.
- `Stripe-Account` carries only a value the grant lists; what Stripe does
  with it is Stripe's. The `rk_test_` prefix and `livemode: false` are
  Stripe's conventions, declared in the recipe; the gateway compares bytes
  and one JSON value.
- The gateway reads refund 1 back and finds its echo token in the refund's
  metadata. That shows the record is consistent with the approved refund,
  not who wrote it: anyone who can write that metadata can write the token.
  The audit shows what the gateway recorded, under observer trust, not what
  Stripe settled. `verified` means authorized and entered, never accepted.
- The gateway's attempt store stops a second submission of the same
  operation ID: at most one Stripe write per operation ID on a single host,
  and an `unknown` outcome needs reconciliation. The `Idempotency-Key`
  helps only if that store is lost and the refund is submitted again, and
  then only while Stripe still keeps the key. `journey.py` shows this
  against the double, not against Stripe.
- The double is not Stripe.
