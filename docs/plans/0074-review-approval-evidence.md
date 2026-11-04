# Native review meaning and exact approval evidence

The `review_approval_tests::native_review_changes_require_fresh_authority_and_approval`
constructor uses the maintained Airtable and Stripe refund example recipes,
ordinary native MCP proofs and exact Ed25519 approvals. Five cases independently
change a displayed label, consequences, destination, financial units or the
80-byte unit boundary. Every case proves the original native action pins its
original recipe and refuses the changed recipe; a newly authorized action still
cannot reuse the old exact approval. Original and freshly approved controls pass.

The complete native literal is retained beside its native signing request in
`bindings/fixtures/gateway/review-approval-boundary.json`. The constructor compares
the complete parsed literal to the native private review without truncation and
refuses an unsupported summary renderer. Markup in a label remains literal data.
Thirteen financial-review source negatives cover missing/null/empty/whitespace/
over-limit/control/bidi units, omitted fields, unsupported review version,
missing/oversized/excess consequences and case-insensitive label collisions.

Trust, keys, connection/account and clock are explicit synthetic fixtures. This
is signed native compilation/review/approval evidence, not provider execution,
financial interpretation, durable-store behavior or human attention. A changed
unit declaration does not establish that a provider honors that unit; qualified
domain meaning still requires the independently reviewed recipe contract.

The installed owner channel's separate authentication, review/signing correlation
and complete literal-display tests remain required. The native constructor and
the installed generic renderer provide complementary evidence; this artifact
does not manufacture an installed frontend result. Exact-head hosted execution
remains pending after artifact construction.
