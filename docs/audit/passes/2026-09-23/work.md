# Pass 2026-09-23: work

How the findings in `findings.md` were split. GitHub tracks the status of each
linked item.

## 1. Private advisory

- **GHSA-j863-hjcq-vwj3** (draft, medium): item 1.
- **Owner decision:** how status applies to principals other than the trust
  anchor, including what a missing status statement means for a delegate.
- **Size:** about half a day once decided. The spec, the Rust, Go and
  TypeScript verifiers, and the fixtures change together.

## 2. Issues

| Issue | Findings | Owner decision |
| --- | --- | --- |
| #145 Stripe refund recovery | item 5; the demo releasing budget | Whether the demo releases a reservation after a complete scan finds nothing |
| #146 Gateway idempotency key | item 13; the documents that assume it | Build the key, or correct the documents |
| #147 PostgreSQL receipts | items 6 and 7; the AP-SPEC-044 claim | None now. Enforcing executor trust inside the database belongs to AP-SPEC-038 §9 |
| #148 Provider secrets | item 11; the `==` comparisons | Encryption at rest, under AP-SPEC-038 §9 |

## 3. Existing epics

- **Approval quorum, draft PR #142:** what remained of item 3. The PR already
  denies its `duplicate-signer` hostile case and sets `minimum_distinct_actors`
  to k. Nothing to add.
- **Epic 4, publish the evidence:** item 17, the README rewrite. Lead with a
  qualified path and label the Stripe snippet as testkit-only.
- **AP-SPEC-038 §9, production trust (board queue item 9):** the multi-host
  parts of items 9 and 10. Already covered.

## 4. Small PRs

**Cleanup PR:** one PR of mechanical fixes.
- Item 2: make the staged verifier functions private to the crate.
- Item 3: fix the doc comments that say "satisfied" where the code returns
  every authorized leaf.
- Item 12: delete the unused budget and challenge ledgers and their
  `compliance.toml` entry.
- Item 14: remove the silent default in `verify_portable_sealed`.
- Item 16: add one `encode_infallible` helper with an `INVARIANT:` comment.
- Item 18: add `exact-refund` to `stripe-profiles.toml` and widen the checker.
- Item 20: remove the provider record links from
  `docs/product/SELF_HOSTED_ACCEPTANCE_REVIEW.md`.
- Item 22: move `public_api_*.md` under `docs/`, updating
  `.github/ci/phase-ownership.toml` and AP-SPEC-040's reference.
- `docs/specs/0038/epic_2.md`: correct the stale `Mutex` and `NoTls`
  description.

**Separate small PR:** item 9, running journal mutations with
`spawn_blocking`. It adds cancellation points, so it needs its own test.

## 5. Settled

Items 3 (the plan-level claim and the "count keys" fix), 4, 8, 10, 15, 19 and
21, and parts of 18 and 20. See `../../settled.md`.

## Parked

Real but small, and not scheduled:
- One key can count as two principals under `did:key` and raw key (item 3).
- `CompositionRequirement::exact` sets both distinct-signer minimums to 1.
  That's right for its single-signer callers, but a trap for a multi-signer plan.
- The recipe review and the submit result don't say that the write is
  unconditional (item 8).
- No document says that any Stripe API-key holder can edit refund metadata
  (item 4).
