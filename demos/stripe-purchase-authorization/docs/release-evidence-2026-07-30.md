# 0017 release evidence · 2026-07-30

Status remains `specified`: the complete profile is implemented and exercised
locally, but the supplied Stripe test account is not enabled for Issuing and
no public Fly/Vercel deployment or genuinely restricted reconciliation key was
authorized for this revision.

Local evidence:

- nine focused integration tests cover inclusive and exceeded limits,
  merchant/category/country deny precedence, missing and expired intent,
  malformed and stale webhook evidence, deadline decline, aggregate
  exhaustion, concurrent last-unit reservation, event replay, unknown outcome,
  durable restart, capture/release observation, and reconciliation;
- two canonical-fixture tests validate evaluator output and every manifest
  digest;
- two native demo tests exercise proof-authorized success, deadline denial,
  replay, unknown response, invalid receipt IDs, verified Stripe HMAC, the
  direct-response `Stripe-Version` header, and unmatched-event decline;
- browser-source smoke tests verify the adjacent policy/event/decision/receipt
  presentation and absence of credential-shaped values;
- the successful hot path records zero credential requests and zero provider
  calls;
- the persistent JSON store retains unknown capacity across restart;
- the webhook route rejects missing, stale, malformed, or invalid signatures;
- canonical fixtures contain no PAN, CVC, credential, or full provider
  payload.
- the locked release Docker image built successfully and its `/healthz` and
  `/api/v1/scenario` routes passed from the running non-root container.

Stripe test-mode capability check (redacted):

- `GET /v1/issuing/cards?limit=3` authenticated successfully enough to return a
  Stripe `invalid_request_error`;
- Stripe reported that the account is not set up to use Issuing;
- consequently no genuine Issuing card or
  `/v1/test_helpers/issuing/authorizations` request could be created.

The installed browser process could not launch in this host's macOS sandbox
(`MachPortRendezvousServer: Permission denied`). The native router/DOM contract
and JavaScript smoke suites passed; a genuine visual browser run remains a
release-environment gate.

The supplied standard `sk_test_…` value was read only from the ignored sibling
demo environment. It was never printed, copied into this demo, uploaded,
persisted in receipts, or exposed to frontend code.
