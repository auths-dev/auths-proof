# 0019 release evidence · 2026-07-30

Status remains `specified`: the closed profile, fixture contract, runnable demo,
and local gates are implemented. The supplied Stripe test account has no
positive available test balance, and its standard test key is not permitted to
list external destinations. No public deployment or payout-restricted
credential was authorized.

Local evidence:

- ten focused payout tests cover exact and one-unit-exceeded limits, retained
  minimum balance, destination substitution/disablement, exact distinct scoped
  approvals, stale and insufficient balance, configuration precedence,
  concurrent last capacity, pending/unknown/failed capacity, persistent
  restart/replay, and release only after returned-funds observation;
- two canonical-fixture tests validate evaluator output and every manifest
  digest;
- two native demo tests cover approval denial before credentials, pending
  capacity, unknown capacity, and replay without a second provider call;
- two browser-source tests verify adjacent policy/action/approval/receipt copy
  and absence of credential or bank-coordinate shapes;
- strict clippy and the Stripe profile inventory gate passed;
- the locked release image built and its health, scenario, and pre-credential
  denial endpoints passed in the running non-root container.

Stripe test-mode prerequisite checks (redacted):

- account and balance retrieval both returned HTTP 200;
- there was no positive available test balance;
- external-destination listing returned HTTP 403 `more_permissions_required`;
- therefore no safe exact destination/balance pair existed and no Stripe Payout
  mutation was attempted.

The installed browser process cannot launch in this host's macOS sandbox
(`MachPortRendezvousServer: Permission denied`). Native router and
DOM/JavaScript contract tests passed; genuine visual browser execution remains
a release-environment gate.

The supplied `sk_test_…` value was read only from the ignored sibling
environment. It was never printed unmasked, copied, uploaded, persisted in
receipts, or exposed to frontend code.
