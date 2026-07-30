# 0018 release evidence · 2026-07-30

Status remains `specified`: the closed profile, fixture contract, runnable demo,
and local release gates are complete. The supplied Stripe test account has no
connected accounts, and no public Fly/Vercel deployment or genuinely restricted
Connect credential was authorized for this revision.

Local evidence:

- ten focused transfer tests cover inclusive and one-minor-unit-exceeded
  boundaries, basis-point floor arithmetic, destination/source/group/currency
  mutations, stale and unavailable evidence, aggregate exhaustion,
  configuration precedence, concurrent last-capacity reservation, fresh
  critical snapshot isolation, unknown
  capacity retention, durable restart, replay, release, and duplicate budget-ID
  rejection;
- two canonical-fixture tests validate evaluator output and every manifest
  digest;
- two native demo tests cover pre-credential denial, one-effect replay, and
  unknown-outcome capacity retention;
- two browser-source smoke tests verify adjacent exact-command and conservation
  presentation and the absence of credential-shaped values;
- strict clippy passed for both the integration and demo;
- the Stripe profile inventory gate passed;
- the locked release Docker image built successfully and its `/healthz`,
  `/api/v1/scenario`, and pre-credential denial endpoints passed in the running
  non-root container.

Stripe test-mode capability checks (redacted):

- `GET /v1/accounts?limit=3` returned HTTP 200 and zero connected accounts;
- `GET /v1/charges?limit=3` returned HTTP 200 and three paid, captured,
  successful test Charges;
- without a permitted connected destination, no genuine test Transfer could be
  constructed, so no Stripe mutation was attempted.

The installed browser process could not launch in this host's macOS sandbox
(`MachPortRendezvousServer: Permission denied`). Native router tests and the
DOM/JavaScript contract suite passed; a genuine visual browser run remains a
release-environment gate.

The supplied standard `sk_test_…` value was read only from the ignored sibling
demo environment for the two read-only capability requests. It was never
printed, copied into this demo, uploaded, persisted in receipts, or exposed to
frontend code.
