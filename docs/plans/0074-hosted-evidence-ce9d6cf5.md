# AP074 final hosted evidence — ce9d6cf5

Observed terminal state: **2026-10-29 16:13 UTC**. [PR213](https://github.com/auths-dev/auths-proof/pull/213).

Published source head: **`ce9d6cf551af226d1a13d28f2de027ae5b81cbab`**. Main CI is qualified, but the complete PR matrix is **not all green**: two macOS Python consumers never acquired hosted runners, including their one authorized recovery attempt.

All 96 latest check records are terminal: **86 success, 2 cancelled, 8 conditional skips**. All 14 workflows are terminal: **12 success, 1 failure (Python infrastructure), 1 conditional skip (custody live)**. No source/test defect was identified. Isolated checkout `/private/tmp/auths-ap074-ci-c80902ab` is clean at the published head; no source edits, local gates, commits or pushes this round. Parent's unpublished A13/A14, A15 and owner UI work is outside this evidence. Main/AP073/AP070 source untouched.

## Complete workflow matrix

| Workflow | Run | Result |
|---|---|---|
| Main CI | [40899439849](https://github.com/auths-dev/auths-proof/actions/runs/40899439849) | Success, including final formal evidence and CI-qualified |
| PostgreSQL lifecycle | [40899439948](https://github.com/auths-dev/auths-proof/actions/runs/40899439948) | Success; all 20 selected native cases actually ran |
| Python SDK | [40899439869](https://github.com/auths-dev/auths-proof/actions/runs/40899439869) | Attempt 2 failed solely on two runner-acquisition cancellations; 24 other jobs successful |
| TypeScript SDK | [40899439801](https://github.com/auths-dev/auths-proof/actions/runs/40899439801) | Success; packed Node/Chromium and both native harnesses |
| SDK outcome recipes | [40899439802](https://github.com/auths-dev/auths-proof/actions/runs/40899439802) | Success; installed Python/TS examples, scaffold and recipes |
| Gateway operator package | [40899439793](https://github.com/auths-dev/auths-proof/actions/runs/40899439793) | Success; source-free extraction and simulation |
| Recipe qualification | [40899439949](https://github.com/auths-dev/auths-proof/actions/runs/40899439949) | Simulation/candidate/offline success; conditional live/release reviewer jobs skipped |
| Gateway isolation | [40899439954](https://github.com/auths-dev/auths-proof/actions/runs/40899439954) | Distinct-UID success |
| Airtable Docker demo | [40899439876](https://github.com/auths-dev/auths-proof/actions/runs/40899439876) | 36 cases passed; production_qualification=false |
| Stripe Docker demo | [40899439762](https://github.com/auths-dev/auths-proof/actions/runs/40899439762) | 23 cases passed; production_qualification=false |
| Google installed images | [40899440046](https://github.com/auths-dev/auths-proof/actions/runs/40899440046) | Independent application-owned reference passed; no AP070 managed-native claim |
| Git signing protocol | [40899439950](https://github.com/auths-dev/auths-proof/actions/runs/40899439950) | Success |
| Git signing branch protection | [40899439930](https://github.com/auths-dev/auths-proof/actions/runs/40899439930) | Success |
| Gateway custody live | [40899439846](https://github.com/auths-dev/auths-proof/actions/runs/40899439846) | Conditional skipped; no evidence |

The eight skipped jobs are production credential-store journey, Stripe test-mode journey, custody store-contract, independent first qualification signer, independent finite commissioning reviewer, retained production operator, complete cleaned-release signing and gateway release verification. None counted as passed. All required main CI implementations and formal phases passed; none were preflight-skipped.

## Sole remaining root: macOS hosted-runner capacity

Python attempt 1 finished with 24 successful jobs and exactly two cancelled consumers:

- [CPython 3.10 macOS, job123543596333](https://github.com/auths-dev/auths-proof/actions/runs/40899439869/job/123543596333).
- [CPython 3.11 macOS, job123543596002](https://github.com/auths-dev/auths-proof/actions/runs/40899439869/job/123543596002).

Both had no runner and no steps. GitHub's failure annotation says: **“The job was not acquired by Runner of type hosted even after multiple attempts”**, accompanied by macOS ARM capacity notices. This is not a test or source failure.

After the complete Python matrix settled, the parent explicitly authorized one grouped recovery attempt. The connector returned 403 without mutating anything; the authorized `gh` fallback issued exactly one `POST /repos/auths-dev/auths-proof/actions/runs/40899439869/rerun-failed-jobs`. Attempt 2 started at 15:47:45 UTC on the same source head. Only the unsuccessful consumers were queued for execution:

- [CPython 3.10 macOS retry, job123557778142](https://github.com/auths-dev/auths-proof/actions/runs/40899439869/job/123557778142).
- [CPython 3.11 macOS retry, job123557777897](https://github.com/auths-dev/auths-proof/actions/runs/40899439869/job/123557777897).

Both retries were cancelled again before execution with the same runner-acquisition/capacity annotations. Attempt 2 finished at 16:02:46 UTC. **No second retry was issued.** Healthy jobs and the separate main/formal workflow were not rerun or cancelled. GitHub copied successful job records to new attempt handles while retaining original execution timestamps: for example the macOS wheel's copied job123557836972 still completed at 15:24:12 UTC, before retry submission. Original successful producer artifacts therefore remain attempt-1 evidence.

Full original and retry job records/annotations: `/tmp/ap074-ci-ce9d-python-retry.json`. No platform, assertion, deadline or approval requirement was removed. The unresolved coverage is specifically the installed CPython 3.10/3.11 macOS consumers on this source head. Other 16 Python consumers, all three wheel producers, typing/API, source tests and both gateway harnesses passed.

## Main CI and formal qualification

- [Preflight123540248975](https://github.com/auths-dev/auths-proof/actions/runs/40899439849/job/123540248975): passed.
- [Authoritative123543879706](https://github.com/auths-dev/auths-proof/actions/runs/40899439849/job/123543879706) and [rollup123558564984](https://github.com/auths-dev/auths-proof/actions/runs/40899439849/job/123558564984): passed. Log has 609 result suites totaling 3,010 passed, zero failed and 98 ignored across repeated configurations, not 3,010 unique tests. Feature-gated native cases executed separately below.
- [Compliance123543880074](https://github.com/auths-dev/auths-proof/actions/runs/40899439849/job/123543880074), security, dependencies and all three live-reference implementations (OpenTofu/PostgreSQL/records API) plus rollups: passed.
- [Kani123543879775](https://github.com/auths-dev/auths-proof/actions/runs/40899439849/job/123543879775) and [rollup123558055121](https://github.com/auths-dev/auths-proof/actions/runs/40899439849/job/123558055121): passed, with **49 actual successful verifications**.
- [Authoritative Lean123552204257](https://github.com/auths-dev/auths-proof/actions/runs/40899439849/job/123552204257): clean rebuild and audit passed for **329 compiled statements**, reviewed transitive axioms, **four reviewed external links and zero compiled external axioms**, and all four Rust refinement tests. Fast Lean123540249162 also passed; it remains feedback rather than qualification.
- [Formal evidence123567518646](https://github.com/auths-dev/auths-proof/actions/runs/40899439849/job/123567518646): **PASS at 16:11:45 UTC**, explicitly `translation + clean Lean + Kani`; artifact12912697748.
- [Formal-translation rollup123572141294](https://github.com/auths-dev/auths-proof/actions/runs/40899439849/job/123572141294): passed.
- [CI-qualified123572202035](https://github.com/auths-dev/auths-proof/actions/runs/40899439849/job/123572202035): passed.

### Translation reuse provenance

[Translation123543879863](https://github.com/auths-dev/auths-proof/actions/runs/40899439849/job/123543879863) passed by validated same-PR reuse, not fresh translation execution. Phase artifact12909767960 records current head ce9d, run40899439849, attempt1; execution=`reused-pr-run`; reproduction_count=2; reused_from head9913d4c7/run40889129833/attempt1. The durable previous-head report records its underlying fresh ab36/run40867724155/attempt1 two-reproduction provenance. Preserve this chain rather than claiming two new builds.

- Source closure: `a002dc42725b1e3e5234f8ba11eea3f8ba8141e2e64f052d950182d4f93a2825`.
- Translation phase: `a5a98c9c76bde8f03021fd572008961e2c425d11a8eb9ba2080b270b4a65c519`.
- Toolchain closure: `baff1cabbf9c83ffca0f4bdb1b8dda685a5ac59638e95d6d12e57f5d5bda9633`.
- Evidence closure: `cbc4400d316703bd0a0af4136f65c580047835a03144353343d051214233269f`.

Saved phase artifact: `/tmp/ap074-ci-ce9d-formal-translation-phase.zip`.

## Actual native PostgreSQL execution

[PG job123537375377](https://github.com/auths-dev/auths-proof/actions/runs/40899439948/job/123537375377) executed all **20 explicit native selectors**, each one passed and zero ignored: CLI content capacity; file/PG process capacity; file/PG acquisition crash; file/PG mutation crash; **file/PG disclosure crash**; file/PG dependency ordering; file/PG window budgets; file I/O faults; PG partial-batch rollback; PG COMMIT reply loss; file/PG mutation retained replay; file/PG information retained replay.

New disclosure generators passed in 11.15 seconds (file) and 40.86 seconds (TLS PostgreSQL). Existing 30 PG gateway tests passed in 13.74 seconds; lifecycle in 16.89 seconds; operator plane in 0.71 seconds. Physical/WAL restore retained before-target state and excluded after-target state; `replay_continuity_claim=false` remains explicit.

Full log and timestamped execution lines: `/tmp/ap074-ci-ce9d-pg-job.json`.

## Producer identity and evidence files

Linux wheel and PG checked out PR merge **`cc77cdbea1132f2b1e0e48f2a2f96aa8e8d8dfb5`**, not literal source head ce9d. Both have verified Git tree **`11274eea06e9d50ccaf61475bc877e2bda19da89`**. Preserve the actual producer identity and the source-tree equivalence. Demo producers explicitly use PR head.

Final complete check/workflow matrix, producer identity, native execution and retry evidence: `/tmp/ap074-ci-ce9d-evidence.json`. This report: `/tmp/ap074-ci-ce9d-report.md`.

Main/formal work finished and will not be cancelled by the next coherent publication. No source fix or child commit is pending. Remaining runner capacity, conditional live qualification and other AP074 acceptance gaps are not waived. No claim is made for unpublished parent changes. AP070 remains independent; AP073 untouched.
