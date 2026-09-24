# Stripe refunds behind 2-of-3 manager approval and a per-agent limit

Your AI agent may refund a Stripe payment only when two of your three
managers approve that exact refund, and only up to its own limit: at most
50.00 per refund and two refunds a day. The Stripe key lives only in the
Auths gateway. An auditor checks every refund afterwards, offline.

**10 steps. The unattended run of all of them (step 10) took 2.1 s on an
Apple-silicon laptop once the wheel and gateway were built.** Building the
gateway the first time takes a few minutes.

| Who | Holds | Can do |
| --- | --- | --- |
| Root (you, the operator) | root key | issue the agent's grant, with its limit |
| Managers A, B, C | one key each | approve one exact refund |
| Agent | its key and grant | propose refunds; never sees the Stripe key |
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
`manager-c`, and `agent`, and:

- a trusted context for the gateway: refunds need **three authorized
  approvals from three distinct roots**. The agent's authority descends from
  the root, so it counts once; the other two must be managers. The approvals
  are the core `k_of_n` plan the approval-quorum SDK builds
  (`author_mcp_quorum_proof`);
- the agent's grant from the root, carrying a bounded-policy commitment:
  `amount` at most 5000 (cents) and at most 2 refunds per 86400 s.
  `--ceiling`, `--max-count`, and `--window-seconds` change it.

It prints `recipe_digest` and `trusted_context_sha256`. Keep both.
`recipe.json` is the gateway recipe for `POST /v1/refunds`, and
`profile.toml` generated `generated.py` and `profile.lock.json` with
`auths-profile generate`.

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

```sh
python refunds.py refund --state "$WORK/state" --socket "$WORK/app.sock" \
  --operation-id refund-1 --payment-intent pi_123 --amount 1500 --approvers manager-a,manager-b
```

Each approver sees the exact refund and signs it. The result is
`{"outcome": "response-recorded", "status": 200}`, and the ledger has one
entry.

**7. Watch the gateway refuse, before any credential lease.**

```sh
python refunds.py refund --state "$WORK/state" --socket "$WORK/app.sock" \
  --operation-id refund-2 --payment-intent pi_123 --amount 9000 --approvers manager-a,manager-b
```

| Attempt | Gateway result | Stripe calls |
| --- | --- | --- |
| 90.00, above the 50.00 ceiling | `not-entered` `gateway.policy.above-ceiling` | 0 |
| Only manager A approves | `denied` `composition-requirement-not-met` | 0 |
| A third refund on the same day | `not-entered` `gateway.policy.window-exhausted` | 0 |

The SDK refuses a one-approval refund locally. `journey.py` shows the gateway
refusing it anyway when an agent skips that check (`--local-trust`).

**8. Export the audit bundle.**

```sh
python refunds.py export --state "$WORK/state" --out audit-bundle.json
```

It holds every submitted proof and action, the gateway-signed outcome of
each, and the installed recipe and trusted context.

**9. Audit offline.** With the gateway stopped and the network off:

```sh
auths-gateway audit --bundle audit-bundle.json \
  --trusted-context-sha256 <from step 3> --observer <from step 4>
```

For every refund it re-verifies, with the gateway's own verifier:

- the proof chain from the agent to the root, and each manager's signature;
- the approval threshold of the pinned trusted context (the report lists the
  approving principals);
- the ceiling, and the per-window count recomputed across the bundle;
- the gateway-signed outcome: signed by the pinned observer, for this exact
  action, with its recorded stage.

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

This runs steps 3–9, the three refusals, and the four tampering cases,
checks every result, including exactly two Stripe calls, and prints timings.
CI runs it from the packed wheel (`.github/workflows/sdk-recipes.yml`,
job `stripe-refund-journey`).

## Real Stripe, test mode

The same journey runs against Stripe's test mode with your own test key.
Automated runs here never call Stripe; run this yourself. It makes exactly
two refunds (15.00 and 40.00) against one PaymentIntent, and refuses live
keys.

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
- Three managers acting together, without the agent, also meet the
  threshold. That is the managers' own authority, and no agent limit
  applies to it.
- The audit checks the entries in the bundle. It cannot show that none were
  left out; the gateway's attempt store is the complete record.
- The per-window count is recomputed at the time the gateway signed each
  outcome, so the app requests that outcome right after submitting. An
  outcome signed in a later window than its submission is counted there.
- Stripe returns the refund object to the gateway, which records its status
  and a digest. The response body is not in the bundle, and the gateway does
  not read the refund back, so the audit shows what the gateway recorded,
  not what Stripe settled.
