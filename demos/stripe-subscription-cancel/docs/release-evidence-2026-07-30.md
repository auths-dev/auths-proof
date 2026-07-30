# 0023 release evidence · 2026-07-30

Status is `implemented`. The closed profile, canonical fixtures, runnable
demo, provider experiment, Docker-local gate, public deployment, genuine
visual-browser execution, and authoritative CI are complete on this revision.

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

Public deployment evidence:

- Fly API and same-origin frontend:
  `https://auths-stripe-subscription-cancel.fly.dev`
- Vercel frontend:
  `https://auths-stripe-subscription-cancel.vercel.app`
- Fly image manifest:
  `sha256:68dfd9f77375c134463f6756d55587fe0043f55ae1a7cf4d7a4cbc1a35bfff3d`
- Vercel deployment:
  `dpl_E937mMwDAWmC5mYtDkmY5PsGk9md`
- Fly region and durable storage: `cdg`, encrypted 1 GB volume with scheduled
  snapshots.
- The Fly health and readiness routes reported `production`, `ready`, and the
  exact `stripe-subscription-cancel` credential scope.
- The Vercel API rewrite reached the Fly scenario route. A public period-end
  request released 2,400 minor units, retained 1,200, and used one credential
  and provider call. Replaying the same workflow returned zero credential
  requests and zero provider calls.

The in-app browser completed the public period-end, immediate,
pending-invoice-items denial, replay, and outcome-unknown scenarios. It also
rendered the inline canonical receipt and the dedicated receipt page. The
observed results preserved `invoice_now=false`, `prorate=false`, denial before
credentials, full liability retention for unknown outcomes, and zero provider
calls on replay. After the design-system revision, desktop and mobile browser
inspection and screenshot capture succeeded against the local and public
surfaces.

Docker-local evidence:

- Compose configuration validated and the release image built successfully as
  `sha256:97c4d2c44977e3a0c61da3357a186cd46fb662857c119a7c708b1d886c24f3d2`.
- The running container passed health, readiness, scenario, period-end,
  immediate, pending-items denial, renewal-race denial, outcome-unknown,
  replay, designed-receipt, and design-token checks.
- Period-end released 2,400 and retained 1,200 minor units. Immediate released
  all 3,600 units while preserving `invoice_now=false` and `prorate=false`.
- Both denials stopped before credentials and provider calls, unknown retained
  all 3,600 units, and replay made zero credential requests and zero provider
  calls.
- The in-app browser executed the Docker-backed period-end and replay flows
  and rendered the canonical receipt. The container was stopped after the
  gate; its image, container, and named audit volume were preserved.

The redesigned frontend uses the repository's Auths blue, warm white, and
near-black design language. The shared UX contract is recorded in
`demos/STRIPE_DEMO_DESIGN_LANGUAGE.md`; all twelve Stripe demo web smoke and
syntax suites passed after the family-wide review.

The authoritative `cargo xtask ci` gate passed outside the filesystem sandbox
so its localhost exchange-transport conformance sockets could bind. It covered
workspace build/test/clippy, MSRV 1.91, architecture, 55-package compliance,
Stripe profile inventory, 506 golden vectors, Rust/Go/TypeScript corpus parity,
formal/Kani assurance, bindings, packages, fuzz smoke tests, and the live demo
bundle.

The supplied `sk_test_…` value was read only from the ignored sibling
environment. It was never printed unmasked, copied into source, persisted in
receipts, or exposed to frontend code.
