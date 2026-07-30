# 0023 release evidence · 2026-07-30

Status remains `specified`: the closed profile, canonical fixtures, runnable
demo, and provider experiment are implemented. Authoritative CI on the exact
revision, a public deployment, and genuine visual-browser execution remain
release-environment gates.

Implemented boundaries:

- `StripeExactSubscriptionCancelV1`, cancellation evaluator/configuration,
  verified command, cancellation-only credential and gateway;
- profile-owned `SubscriptionCancelReceipt` decision, transition, and
  observation family;
- durable release-intent state with exact workflow replay, one active
  cancellation per Subscription, monotonic liability release accounting, and
  restart-safe unknown outcomes;
- distinct period-end and immediate transitions; immediate always sends
  `invoice_now=false` and `prorate=false`;
- reconciliation retrieves the exact Subscription and never resubmits an
  unknown effect blindly.

Local evidence:

- fifteen cancellation-related library tests passed, including transition,
  replay, concurrency, restart, liability, and existing merchant-cancel
  regression tests;
- seven canonical-fixture/evaluator tests passed for period-end eligibility,
  pending update/items, renewal races, already scheduled/terminal, stale
  evidence, receipt isolation, and secret-free canonical manifests;
- two native demo tests passed for both modes, pre-credential denials, unknown
  liability retention, and replay without a second provider call;
- three browser-source tests passed for adjacent controls/results, designed
  receipt semantics, and absence of credentials or unsafe invoice/proration
  controls.
- the localhost HTTP gate passed health, readiness, scenario, period-end,
  immediate, pre-credential denial, unknown-outcome, replay, and designed
  receipt routes.
- five Kani harnesses proved terminality, mandatory claim ordering,
  unknown-outcome release restrictions, period-end liability conservation,
  and immediate pre-terminal liability retention;
- strict clippy, workspace MSRV 1.91, profile inventory, architecture,
  compliance, and specification synchronization gates passed;
- the Aeneas toolchain lock, Lean build, and formal audit passed (72 compiled
  statements); translation regeneration stopped only because the exact pinned
  Charon binary is unavailable.

Stripe test-mode provider evidence (redacted):

- the account initially had zero Subscriptions and exposed ready test clocks;
- a repository-labeled test-clock Subscription was scheduled with
  `cancel_at_period_end=true`, the clock advanced beyond the exact period end,
  and Stripe returned terminal `canceled` state with `ended_at`;
- a separate repository-labeled test-clock Subscription was canceled
  immediately with `invoice_now=false` and `prorate=false`, and Stripe returned
  terminal `canceled` state with `ended_at`;
- two Invoice objects remained separately observable; cancellation was not
  represented as a refund;
- temporary customer and test-clock objects were deleted and the product was
  archived after the experiment.

The installed browser process cannot launch in this host's macOS sandbox
(`MachPortRendezvousServer: Permission denied`). Native router and DOM/
JavaScript contract tests passed. The Fly/Vercel manifests are present, but no
public deployment or cloud-secret upload was authorized.

The local Docker daemon stopped answering its socket during this gate,
including a read-only `docker ps` ping. The locked Dockerfile is present, but
the 0023 image build/runtime check therefore remains an environment blocker.

The supplied `sk_test_…` value was read only from the ignored sibling
environment. It was never printed unmasked, copied into source, persisted in
receipts, or exposed to frontend code.
