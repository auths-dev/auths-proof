# Stripe refunds behind 2-of-3 manager approval and a per-agent limit

Your AI agent may refund a Stripe payment only when two of your three
managers approve that exact refund, and only up to its own limit: at most
50.00 per refund and two refunds per UTC day. The Stripe key lives only in the
Auths gateway. An auditor checks every refund afterwards, offline.

**10 steps. The unattended run of all of them (step 10) took 4.2 s on an
Apple-silicon laptop once the wheel and gateway were built.** Building the
gateway the first time takes a few minutes.

| Who | Holds | Can do |
| --- | --- | --- |
| Root (you, the operator) | root key | issue the agent's grant, with its limit |
| Managers A, B, C | one key each, on their own machines | review and approve one exact refund with `auths approve` |
| Agent | its key and grant | request approvals, collect them, submit; never sees the Stripe key or a manager's key |
| Gateway | the Stripe key | submit a refund only after verifying approvals and limit |
| Auditor | two pinned values | verify every refund from a file, with no network |

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
double in step 5. Leave it out when you use real Stripe (see below).

**2. Pick a private working directory.** The gateway requires absolute,
owner-only paths.

```sh
export WORK=$(mkdir -p -m 700 /tmp/auths-refunds && cd /tmp/auths-refunds && pwd -P)
```

**3. Create the root, three managers, the agent, and the trust.**

```sh
python refunds.py setup --state "$WORK/state"
```

This writes development keys for `root`, `manager-a`, `manager-b`,
`manager-c`, and `agent`, one `auths approve` signer file per manager
under `state/signers/` (development custody over that manager's key), and:

- a trusted context for the gateway: refunds need **three authorized
  approvals from three distinct roots**. The agent's authority descends from
  the root, so it counts once; the other two must be managers. The approvals
  are the core `k_of_n` plan the approval-quorum SDK builds, collected from
  each approver as a remote approval (`propose_mcp_approval`,
  `approval_requests`, `collect_approvals`);
- the agent's grant from the root, carrying a bounded-policy commitment:
  `amount` at most 5000 (cents) and at most 2 refunds per fixed,
  epoch-aligned 86400 s window, which is a UTC day. The count bounds the
  agent and anyone it delegates to together. `--ceiling`, `--max-count`,
  and `--window-seconds` change it.

It prints `recipe_digest` and `trusted_context_sha256`. Keep both.
`recipe.json` is the gateway recipe for `POST /v1/refunds`, in recipe
source `/2`. It declares `write.idempotency` of kind `derived-header`, so
the gateway sends each refund with an `Idempotency-Key` it derives from the
namespace and operation ID (`auths-gateway review` shows
`"sends_idempotency_key": true` and the declared 86 400-second retention,
which the gateway cannot verify). Because of that retention, each refund's
approval window is 86 340 seconds: the gateway refuses, before any claim,
an action whose window plus its 60-second entry deadline exceeds the
declared retention.
`profile.toml` generated `generated.py` and `profile.lock.json` with
`auths generate`.

**4. Install the gateway with the Stripe key on stdin.**

```sh
mkdir -m 700 "$WORK/gateway"
export STRIPE_KEY=sk_test_mock_local     # any token for the local double
printf '%s\n' "$STRIPE_KEY" | auths-gateway install --state-dir "$WORK/gateway" \
  --recipe recipe.json --profile-lock profile.lock.json \
  --trusted-context "$WORK/state/trust/gateway.context.cbor" \
  --approve-digest <recipe_digest from step 3> \
  --provider stripe --alias refunds --account-label my-stripe-account --credential-stdin
auths-gateway observer-init --state-dir "$WORK/gateway"
```

`observer-init` prints `observer_anchor.principal`: the key the gateway signs
its outcomes with. Give it and `trusted_context_sha256` to your auditor.

**5. Start Stripe (the local double) and the gateway.**

```sh
python mock_stripe.py --ledger "$WORK/ledger.jsonl" \
  --token-sha256 $(printf '%s' "$STRIPE_KEY" | shasum -a 256 | cut -d' ' -f1) &
# it prints its port, for example 54321
unset STRIPE_KEY
auths-gateway serve --state-dir "$WORK/gateway" --app-socket "$WORK/app.sock" \
  --loopback-provider 54321 &
```

**6. The agent asks for a refund; managers A and B approve; the gateway submits.**

The agent writes one approval request per manager. Each request is a file of
text (`auths-ar1-…`) you can send any way you like, for example pasted into
chat; it is not secret, and it carries no text of its own.

```sh
python refunds.py request --state "$WORK/state" --operation-id refund-1 \
  --payment-intent pi_123 --amount 1500 --approvers manager-a,manager-b --out "$WORK/refund-1"
```

Each manager answers on their own machine:

```sh
auths approve "$WORK/refund-1/manager-a.request" \
  --signer "$WORK/state/signers/manager-a.json" --out "$WORK/refund-1/manager-a.response"
auths approve "$WORK/refund-1/manager-b.request" \
  --signer "$WORK/state/signers/manager-b.json" --out "$WORK/refund-1/manager-b.response"
```

`auths approve` checks the request natively, prints the review that
the SDK derives from the exact refund the manager signs (the arguments, the
requester, the other approvers, and the approval window), and asks
`Approve this action? [y/N]`. Only `y` signs; without a terminal it signs only
with `--yes`. `--decline` signs a refusal instead. The signer files that step 3
wrote are development custody: a seed file on disk, and the command says so.
In production each manager points `--signer` at their own custody adapter.

The agent approved its own request in the first command. It now collects the
responses and submits:

```sh
python refunds.py submit --state "$WORK/state" --socket "$WORK/app.sock" \
  --operation-id refund-1 --responses "$WORK/refund-1"
```

The result is `{"outcome": "response-recorded", "status": 200}`, and the
ledger has one entry.

**7. Watch the refusals, before any credential lease.**

| Attempt | Result | Stripe calls |
| --- | --- | --- |
| Manager B runs `auths approve … --decline` | `submit` reports `declined` and submits nothing | 0 |
| A request edited to show another amount | `auths approve` refuses `approval.action-mismatch` and signs nothing | 0 |
| 90.00, above the 50.00 ceiling | `not-entered` `gateway.policy.above-ceiling` | 0 |
| Only manager A approves | `denied` `composition-requirement-not-met` | 0 |
| A third refund on the same UTC day | `not-entered` `gateway.policy.window-exhausted` | 0 |

The agent's collection checks that every response signs its own request's
envelope byte for byte; the gateway's verifier checks every signature and the
threshold of its installed trust.

Refund 4 (40.00, approved by managers B and C) names a PaymentIntent Stripe
does not hold. It is authorized, so the gateway enters it and records
`{"outcome": "response-recorded", "status": 400}`: one Stripe call, no refund.
It still uses the agent's second refund of the day, which is why the third
refund above is refused.

**8. Export the audit bundle.**

```sh
python refunds.py export --state "$WORK/state" --out audit-bundle.json
```

It holds every submitted proof and action, the gateway-signed outcome of
each, every approval response the agent collected (declines included), and
the installed recipe and trusted context.

**9. Audit offline.** With the gateway stopped and the network off:

```sh
auths-gateway audit --bundle audit-bundle.json \
  --trusted-context-sha256 <from step 3> --observer <from step 4>
```

For every refund it re-verifies, with the gateway's own verifier:

- the proof chain from the agent to the root, and each manager's signature;
- the approval threshold of the pinned trusted context (the report lists the
  approving principals);
- the ceiling, and the per-window count recounted across the bundle
  without relying on the order of the entries;
- the gateway-signed outcome: signed by the pinned observer, for this exact
  action, with its recorded stage, the time the gateway evaluated it, and the
  counters it reserved, which must match the ones the audit derives;
- the provider's result, reported beside the verdict as `provider_result`:
  the HTTP status and response digest the gateway recorded. Refund 4 is
  `verified` (authorized and entered) with `http_status` 400 beside it.

The report also lists each recorded approval response, so it shows who
approved and who declined. Responses never change a verdict: only the verified
proof counts an approval, and a decline carries no authority.

Each entry is `verified` (`audit.verified`), `refused` with the gateway's
stable code, or `inconsistent` with an `audit.*` finding. The command exits
non-zero when any entry is inconsistent or the bundle's trusted context is
not the pinned one: a flipped proof byte (`audit.entered-without-authority`),
a swapped action (`audit.outcome-commitment-mismatch`), a replayed outcome
(`audit.outcome-invalid`), or replaced trust (`audit.trust-pin-mismatch`).

**10. Or run all of it unattended.**

```sh
python journey.py --gateway "$(command -v auths-gateway)"
```

This runs steps 3–9 with every manager answering through
`auths approve`, a declined manager, a tampered request, the three
refusals, and the four tampering cases,
checks every result, including exactly two Stripe calls (refund 1, and the
rejected refund 4) and the `Idempotency-Key` each one carried, and the
audit's `http_status` of 200 and 400 for them, and prints timings. It then
restores the gateway's store from a backup taken before the first refund,
which keeps the shared connection record but no claim, and resubmits refund
1's approved proof. With the claim gone the gateway sends it again, with the
same key, and the double answers with the first refund: three calls, one
refund. CI runs it from the packed wheel
(`.github/workflows/sdk-recipes.yml`, job `stripe-refund-journey`).

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

The last command took 6.0 s on an Apple-silicon laptop once the package and
gateway were built. Each `python refunds.py …` step above is
`node build/refunds.js …` with the same flags, each manager runs
`npx auths approve …` with the same flags, and `journey.js` takes the same
`--stripe-test-mode` and `--payment-intent` options as `journey.py`. The
package installs from the tarball you packed, so this directory keeps no
lockfile. CI runs it from the packed tarball as job
`stripe-refund-journey-npm`.

## Real Stripe, test mode

The same journey runs against Stripe's test mode with your own test key.
Automated runs here never call Stripe; run this yourself. It makes exactly
one refund (15.00) against your PaymentIntent, one 40.00 refund request that
Stripe rejects because it names a PaymentIntent your account does not hold,
and refuses live keys. The state-loss resubmission runs only against the double.

```sh
export STRIPE_TEST_SECRET_KEY=sk_test_...        # your own test-mode key
PI=$(printf 'user = "%s:"\n' "$STRIPE_TEST_SECRET_KEY" | curl -s -K - \
  https://api.stripe.com/v1/payment_intents \
  -d amount=6000 -d currency=usd -d payment_method=pm_card_visa -d confirm=true \
  -d 'automatic_payment_methods[enabled]=true' \
  -d 'automatic_payment_methods[allow_redirects]=never' \
  | python -c 'import json, sys; print(json.load(sys.stdin)["id"])')
cargo install --locked --path ../../product/runtime/auths-gateway --root "$WORK/stripe"
python journey.py --gateway "$WORK/stripe/bin/auths-gateway" --stripe-test-mode --payment-intent "$PI"
```

The default gateway build pins `https://api.stripe.com` to a public address
and has no loopback option. The key reaches only the gateway's install step,
on stdin.

## What this does not claim

- Development keys stand in for custody. In production the root and each
  manager sign through their own custody adapters.
- Every listed approver must sign: to replace a manager who declines, start a
  new request (see `docs/product/APPROVAL_QUORUM.md`).
- A request is not confidential: anyone who receives it sees the refund. The
  requester it names is not authenticated by the request; the agent's own
  approval is. The guarantee that a manager signs what they saw holds only for
  a surface that shows what the SDK returned, as `auths approve` does.
- Three managers acting together, without the agent, also meet the
  threshold. That is the managers' own authority, and no agent limit
  applies to it.
- The audit checks the entries in the bundle. It cannot show that none were
  left out; the gateway's attempt store is the complete record.
- The per-window count is recounted at the time the gateway evaluated each
  submission, which its signed outcome carries, so an outcome requested in a
  later window still counts in its submission's window.
- Windows are fixed UTC days, not rolling: up to four refunds can land
  within 24 hours across midnight UTC.
- Stripe returns the refund object to the gateway, which records its status
  and a digest, and the audit shows both beside the verdict. The response
  body is not in the bundle, and the gateway does not read the refund back,
  so the audit shows what the gateway recorded, under observer trust, not
  what Stripe settled. `verified` means authorized and entered, never
  accepted.
- The gateway's attempt store stops a second submission of the same
  operation ID: at most one Stripe call per operation ID on a single host,
  and an `unknown` outcome needs reconciliation. The `Idempotency-Key`
  helps only if that store is lost and the refund is submitted again, and
  then only while Stripe still keeps the key. `journey.py` shows this
  against the double, not against Stripe.
