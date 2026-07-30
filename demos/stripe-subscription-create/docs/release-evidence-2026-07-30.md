# 0021 release evidence · 2026-07-30

Status remains `specified`: the exact profile is implemented and exercised
locally against Stripe test mode, but no public Fly/Vercel deployment or
genuinely restricted subscription-create key has been supplied on this
revision.

Real test-mode observations (redacted):

- SetupIntent mandate dependency: `seti_1TynyWPbjgb2M2TeTPbShVg4`;
- Subscription: `sub_1TynyoPbjgb2M2TeIEQ41526`;
- first Invoice: `in_1TynyoPbjgb2M2TebbPbt6La`, paid 500 USD minor units;
- one credential request and one create call;
- durable replay: zero credential requests and zero provider calls;
- configuration denial: zero credential requests and zero provider calls;
- ambiguous Subscription: `sub_1TynzjPbjgb2M2TeevBc9r3T`;
- ambiguous receipt stored no provider projection;
- reconciliation source: `reconcile-workflow-search`, with no second create;
- a final exact-source browser run exercised denial, success, replay, and the
  human-readable receipt in installed Chrome;
- its Subscription `sub_1TyoIbPbjgb2M2TewMwCTGvW` began with paid Invoice
  `in_1TyoIbPbjgb2M2TeRkfPVfqi`;
- the repository-owned test clock advanced through the provider-derived weekly
  renewal anchor and invoice-finalization window;
- renewal Invoice `in_1TyoJ1Pbjgb2M2TeOPHDCgZg` was paid for 500 USD minor
  units, reducing durable remaining cycles from 2 to 1 and remaining term
  liability from 1,000 to 500 USD minor units.

The demo used the developer-provided standard `sk_test_…` key locally. That is
not evidence of provider-side least privilege. No secret value appears in
tracked artifacts.
