# AP074 hosted evidence: 9913d4c7

Observed terminal state: 29 October 2026, 15:07 UTC.
[PR #213](https://github.com/auths-dev/auths-proof/pull/213) source revision:
`9913d4c702451c19de2b601cd634e397db20f951`.

All 96 check records finished: **88 success, eight conditional skips, zero
failures**. All fourteen workflows finished: thirteen success, one conditional
skip. This revision is CI-qualified. This is evidence for this published source
only, not for subsequent disclosure tests or complete AP074 acceptance.

## Workflow results

| Workflow | Run | Result |
| --- | --- | --- |
| CI | [40889129833](https://github.com/auths-dev/auths-proof/actions/runs/40889129833) | Success, including CI-qualified |
| PostgreSQL lifecycle | [40889129739](https://github.com/auths-dev/auths-proof/actions/runs/40889129739) | Success; all 18 explicit native cases executed |
| Python SDK | [40889129804](https://github.com/auths-dev/auths-proof/actions/runs/40889129804) | Success; wheel producers, installed consumers and gateway harnesses |
| TypeScript SDK | [40889129810](https://github.com/auths-dev/auths-proof/actions/runs/40889129810) | Success; packed Node/Chromium and gateway harnesses |
| SDK outcome recipes | [40889129755](https://github.com/auths-dev/auths-proof/actions/runs/40889129755) | Success; installed examples, scaffold and recipes |
| Gateway operator package | [40889129870](https://github.com/auths-dev/auths-proof/actions/runs/40889129870) | Success; source-free extraction/simulation |
| Recipe qualification | [40889129736](https://github.com/auths-dev/auths-proof/actions/runs/40889129736) | Success for simulation/candidate/offline paths; conditional live/release jobs skipped |
| Gateway isolation | [40889129561](https://github.com/auths-dev/auths-proof/actions/runs/40889129561) | Success with distinct UIDs |
| Airtable Docker demo | [40889129895](https://github.com/auths-dev/auths-proof/actions/runs/40889129895) | 36 cases passed; production qualification false |
| Stripe Docker demo | [40889130083](https://github.com/auths-dev/auths-proof/actions/runs/40889130083) | 23 cases passed; production qualification false |
| Google installed images | [40889129830](https://github.com/auths-dev/auths-proof/actions/runs/40889129830) | Success for independent application-owned reference |
| Git signing protocol | [40889129499](https://github.com/auths-dev/auths-proof/actions/runs/40889129499) | Success |
| Git signing branch protection | [40889129611](https://github.com/auths-dev/auths-proof/actions/runs/40889129611) | Success |
| Gateway custody live | [40889129882](https://github.com/auths-dev/auths-proof/actions/runs/40889129882) | Conditional skip; no qualification evidence |

The eight skipped jobs concern the production credential-store journey, Stripe
test-mode journey, custody store contract, independent first qualification
signer, independent finite commissioning reviewer, retained production operator,
complete cleaned-release signing and gateway release verification. No skipped
job is counted as a pass or live-provider/human-review evidence.

## Formal and implementation results

- [Authoritative implementation](https://github.com/auths-dev/auths-proof/actions/runs/40889129833/job/123506132526)
  and its rollup passed. Its repeated configurations report 3,008 passed,
  zero failed and 97 ignored across 609 result suites; these are not unique-test
  counts. Feature-gated native cases executed separately below.
- [Compliance](https://github.com/auths-dev/auths-proof/actions/runs/40889129833/job/123506132619),
  dependency/secrets checks and all three live-reference implementations
  (OpenTofu, PostgreSQL and records API) and their rollups passed.
- [Kani](https://github.com/auths-dev/auths-proof/actions/runs/40889129833/job/123506132424)
  passed with 49 actual successful verification results.
- [Authoritative Lean](https://github.com/auths-dev/auths-proof/actions/runs/40889129833/job/123512213089)
  completed a clean 3,270-job build, 329 compiled statements and transitive-axiom
  audit, four reviewed external links with zero compiled external axioms, four
  Rust refinement tests and the 49-harness inventory. Fast Lean is separate
  feedback and is not substituted for this result.
- [Final formal evidence](https://github.com/auths-dev/auths-proof/actions/runs/40889129833/job/123528105291)
  passed with translation, clean Lean and Kani (artifact `12907997775`). The
  formal-translation rollup and
  [CI-qualified](https://github.com/auths-dev/auths-proof/actions/runs/40889129833/job/123533062348)
  also passed.

### Translation provenance

[Pinned translation](https://github.com/auths-dev/auths-proof/actions/runs/40889129833/job/123506132456)
passed by validated same-PR reuse, not a fresh translation. Artifact
`12905565623` records current head `9913d4c7`, run `40889129833`, attempt 1,
`execution=reused-pr-run`, reproduction count 2, and reuse from run
`40867724155`, attempt 1, source head
`ab36e4b76420a37912d00b2c5b1fac1ad6c556c5`.

The source closure is
`a002dc42725b1e3e5234f8ba11eea3f8ba8141e2e64f052d950182d4f93a2825`.
The translation phase closure is
`a5a98c9c76bde8f03021fd572008961e2c425d11a8eb9ba2080b270b4a65c519`.
The toolchain closure is
`baff1cabbf9c83ffca0f4bdb1b8dda685a5ac59638e95d6d12e57f5d5bda9633`.
The evidence closure is
`cbc4400d316703bd0a0af4136f65c580047835a03144353343d051214233269f`.

## Native durable execution and producer identity

[PostgreSQL job](https://github.com/auths-dev/auths-proof/actions/runs/40889129739/job/123500802885)
ran all eighteen explicit cases with one pass and zero ignored each: CLI content
capacity; file/PostgreSQL process capacity, acquisition crash, mutation crash,
dependency ordering and fixed-window budgets; file I/O failures; PostgreSQL
partial-batch rollback and COMMIT reply loss; file/PostgreSQL mutation and
information retained replay. Mutation crash cases took 1.98 seconds on file and
10.16 seconds on PostgreSQL. Thirty existing gateway PostgreSQL cases, lifecycle
and operator-plane tests also passed.

Physical/WAL restore retained before-target and excluded after-target state.
`replay_continuity_claim=false` remains explicit: a restored database does not
establish its own freshness.

The actual Linux wheel/PostgreSQL producer checkout was PR merge commit
`16eb79e57fde2b82fca5550c8e2b4c5596a79046`, with verified tree
`b8913649cbe69cbe2b4aac8339f5c9fedf708a77`, identical to the published source
tree. Preserve that producer identity; it is not literally the source commit.
Demo producers separately checked out the source head.

Both installed Docker demos passed the original substituted-challenge assertion
unchanged. Neither claims production qualification. Google remains the
independent AP070 reference and receives no managed-native guarantee here.

## Limits

No CI repair or rerun was needed for this revision. Its final formal run finished
before the next publication. Later commits require fresh exact-head hosted
checks. The [implementation ledger](0074-implementation-status.md) remains
authoritative for the open AP074 acceptance gates; this report closes no
unexecuted human UI, differential, concurrency, retention or performance claim.
