# Pass 2026-09-23: findings

- **Commit:** `57f08045` on `main`. All evidence below is at this commit.
- **Source:** an external review with 22 items. Five verification agents
  checked it, and the kernel items were also read directly. The area prompts
  in `../../prompts/` were written from this review.
- **Result:** 9 confirmed, 8 partly confirmed, 3 documented limits, 2 rejected.
  Verification found 10 more issues.

Severity is the reviewer's rating → ours, on the scale in
`../../prompts/00-how-to-use.md`. The reviewer rated only items 1–16.

## The review's 22 items

| # | Finding as reported | Verdict | Severity | Where it went | Evidence |
| --- | --- | --- | --- | --- | --- |
| 1 | A kernel security weakness. Details are in the private advisory. | confirmed | P0 → medium (CVSS 3.1 6.5) | Private advisory GHSA-j863-hjcq-vwj3 | withheld |
| 2 | The staged verifier API accepts a different `TrustedContext` at each stage, skipping the plan pin and the manifest and configuration checks | partly confirmed: real, but nothing outside the crate calls the stages | P0 → P2 | Cleanup PR | `core/crates/auths-verifier/src/lib.rs:1275`, `:1402-1411`, `:1557` |
| 3 | K-of-N counts leaves, not independent signers | documented limit; the proposed "count keys" fix is wrong for keyless principals | P0 → P3 for what remains | Settled; the quorum path is covered by draft PR #142 | `core/spec/v1/protocol.md:126-131`; `core/crates/auths-model/src/lib.rs:2748-2757` |
| 4 | The Stripe path writes no action-derived echo | partly confirmed: the facts hold, but Stripe is outside AP-SPEC-059's scope | P0 → none | Settled | `docs/specs/0059-commitment-bound-provider-evidence.md:216-219` |
| 5 | Stripe refund recovery reads only 100 refunds and matches on editable metadata | partly confirmed: production fails closed; the demo fails open | P1 → P2 production, P1 demo | #145 | `product/integrations/auths-stripe/src/local_agent.rs:1386-1402`; `demos/stripe-refund/src/app.rs:525` |
| 6 | PostgreSQL `committed_at` comes from the caller, not the database | confirmed | P1 → P2 | #147 | `product/integrations/auths-postgresql/src/local_provider.rs:363` |
| 7 | The PostgreSQL ledger isn't cryptographically bound to the rows it changed | partly confirmed: the transaction binds them, but a receipt field and AP-SPEC-044 claim more | P1 → P2 | #147 | `product/integrations/auths-postgresql/src/local_provider.rs:358-361`, `:1419`; `product/integrations/auths-postgresql/src/receipts.rs:170` |
| 8 | Gateway writes don't check that the record is unchanged since approval | documented limit | P1 → P3 | Settled | `docs/specs/0060-evidence-conditioned-authority.md:47-49` |
| 9 | The journal blocks async threads with whole-file rewrites and fsync, and is single-host | confirmed for the journal; single-host is documented | P2 → P2 | Separate small PR; multi-host is board queue item 9 | `product/runtime/auths-node/src/journal_executor.rs:1942`; `product/stores/auths-stores/src/operation.rs:1445` |
| 10 | The PostgreSQL lifecycle store takes a global lock and reloads every record | documented limit | P2 → P3 | Settled | `docs/specs/0038/epic_2.md:44-46` |
| 11 | Provider secrets are stored in plaintext and wiped inconsistently | confirmed, and wider than reported | P2 → P2 | #148 | `product/runtime/auths-connections/src/credential.rs:51`, `:454`, `:558-559` |
| 12 | The budget ledger isn't safe across processes and never refunds | confirmed; nothing uses it | P2 → P3 | Cleanup PR (delete) | `product/stores/auths-stores/src/lib.rs:257` |
| 13 | The gateway sends no idempotency key | confirmed; the board and AP-SPEC-059 assume it exists | P2 → P2 | #146 | `docs/specs/0053-declarative-credential-isolated-gateway.md:217-219`; `docs/specs/0059-commitment-bound-provider-evidence.md:63` |
| 14 | A codec failure falls back to the digest of empty bytes | confirmed, but unreachable: encoding into a `Vec` can't fail | P3 → P3 | Cleanup PR | `core/crates/auths-verifier/src/lib.rs:1005-1006` |
| 15 | Author-side and verifier-side extension rules differ | rejected | P3 → none | Settled | `core/crates/auths-authority/src/lib.rs:159-167`; `core/crates/auths-author/src/lib.rs:537-558` |
| 16 | About 150 panic sites in `auths-node` | confirmed; none reachable from external input | P3 → P3 | Cleanup PR | `product/runtime/auths-node/src/bin/auths.rs:1305-1352` |
| 17 | The README is stale | partly confirmed: it already leads with Python, but that snippet uses an unqualified route | — → P3 | Epic 4 | `README.md:14-23`, `:36` |
| 18 | `stripe-profiles.toml` is stale | partly confirmed: the statuses are deliberate, but `exact-refund` is missing | — → P3 | Cleanup PR; settled | `xtask/src/stripe.rs:98`; `compliance.toml:606` |
| 19 | The Stripe coverage story needs a measured figure | partly confirmed: the facts hold, but no "every Stripe action" claim exists | — → none | Settled | none |
| 20 | Airtable and Todoist exist only as fixtures | partly confirmed: the live runs are recorded, but a public doc links real provider records | — → P3 | Cleanup PR; settled | `docs/product/SELF_HOSTED_ACCEPTANCE_REVIEW.md:33` |
| 21 | The echo token's limits are undocumented | rejected: already documented | — → none | Settled | `docs/specs/0059-commitment-bound-provider-evidence.md:41-45` |
| 22 | The root-level `public_api_*.md` files are working notes | confirmed; CI ownership rules and AP-SPEC-040 reference them | — → P3 | Cleanup PR | `.github/ci/phase-ownership.toml:352-362` |

## Found during verification

| Finding | Severity | Where it went | Evidence |
| --- | --- | --- | --- |
| The Stripe refund demo frees reserved budget when the refund is past the first 100 | P1 | #145 | `demos/stripe-refund/src/stripe.rs:356`; `demos/stripe-refund/src/app.rs:525` |
| The board (§4, 2026-09-22 and 2026-09-23) and AP-SPEC-059 treat the AP-SPEC-053 idempotency key as built; it never was | P2 | #146 | `docs/specs/0059-commitment-bound-provider-evidence.md:63` |
| PostgreSQL `after_state_matches` can never be false | P2 | #147 | `product/integrations/auths-postgresql/src/local_provider.rs:1419`; `product/integrations/auths-postgresql/src/receipts.rs:170` |
| AP-SPEC-044 claims independence from the executor that the code doesn't give | P2 | #147 | `docs/specs/0044-live-provider-qualification-and-recovery-evidence.md:2092-2093` |
| Secrets are compared with `==`, not in constant time | P2 | #148 | `product/runtime/auths-connections/src/credential.rs:454`, `:558-559` |
| `CompositionRequirement::exact` sets both distinct-signer minimums to 1: right for its 15 single-signer callers, a trap for a multi-signer plan | P3 | Parked | `core/crates/auths-model/src/lib.rs:2748-2757` |
| A public doc links real Airtable and Todoist records, against the claim ledger's own rule | P3 | Cleanup PR | `docs/product/SELF_HOSTED_ACCEPTANCE_REVIEW.md:33`; `docs/product/SELF_HOSTED_CLAIM_LEDGER.md:84` |
| `exact-refund` is missing from `stripe-profiles.toml`, and its checker hardcodes specs 13–23 | P3 | Cleanup PR | `xtask/src/stripe.rs:98`; `compliance.toml:606` |
| The budget and challenge ledgers don't fsync the directory after replacing their file | P3 | Cleanup PR, deleted with item 12 | `product/stores/auths-stores/src/lib.rs:538` |
| `docs/specs/0038/epic_2.md` still describes a `Mutex` and `NoTls`; the code uses a TLS pool | P3 | Cleanup PR | `docs/specs/0038/epic_2.md:37-40` |
