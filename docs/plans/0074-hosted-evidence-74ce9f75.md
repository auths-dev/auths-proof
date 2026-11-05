# AP074 hosted evidence — 74ce9f75

This report records execution for published source
`74ce9f753faa6bf3f1cb065bc369f655e6c0b236` on draft PR #213. It does not
establish completion of AP074 or qualify later source changes. The remaining
source defect is the stale gateway semantic closure; its repair belongs to
the subsequent epoch and metadata batch.

## Producer identity

The PostgreSQL, Python source-contract and external-consumer jobs checked out
PR merge `df0cc98e6eae440db67038c4f552b74e1d64b90f`, merging the published
head into `e2d10a74fa0be5e6bfe2b9f698632c835cd7b11b`. Both the merge and
published source have Git tree
`bdc10c7f90813049c0b973327f51e5adf3f4f622`, verified by fetching the merge
and comparing the trees. Workflow source labels do not replace this actual
producer identity.

## Failure and repaired prior failures

[Authoritative implementation job 123749843777](https://github.com/auths-dev/auths-proof/actions/runs/40958689238/job/123749843777)
failed `semantic_closure::tests::semantic_closure_is_current`. The gateway
slice finished with 269 passed, 1 failed and 43 ignored tests. The
[authoritative rollup](https://github.com/auths-dev/auths-proof/actions/runs/40958689238/job/123754086228)
failed for that same cause.

A read-only comparison found stale manifest hashes for
`effect_native_tests.rs`, `engine.rs`, `native_information_replay_tests.rs`,
`scenario_tests.rs` and `store.rs`; the manifest also omitted
`native_differential_tests.rs`, `native_retention_tests.rs` and
`store_retention_tests.rs`. No entries had been removed. The native generator
must regenerate the gateway manifest and compiled digest from the subsequent
combined source, followed by a rebuilt non-update check. The unchanged formal
source closure below is a distinct identity and does not satisfy this gate.

Both earlier CI roots were verified repaired on this head:

- [Repository preflight 123746949082](https://github.com/auths-dev/auths-proof/actions/runs/40958689238/job/123746949082)
  passed strict workspace lint, including the native differential generator.
- [PostgreSQL job 123745460518](https://github.com/auths-dev/auths-proof/actions/runs/40958689260/job/123745460518)
  executed the repaired spawned reference worker, actual SIGKILL and unchanged
  conservation assertions as part of the successful information comparison.

## Native, differential and restore evidence

The PostgreSQL workflow ran all 24 explicit native selectors exactly once.
Each selector's actual output was followed by `1 passed; 0 failed; 0 ignored`.
This comprises the CLI process-capacity case and 23 exact file/PostgreSQL
library cases, including both nested retention fixtures. The uploaded log
was downloaded and checked against the selectors in this revision's workflow.

After installing this checkout's native Python SDK, the same job executed
**22 independent information pairs across both adapters**. The report records
source commit `df0cc98e6eae440db67038c4f552b74e1d64b90f`, run `40958689260`,
attempt `1`. Its scope remains post-authorization application state: it does
not establish AP070 managed authorization, recipient-ACK equivalence or live
Google behavior.

[Python source-contract job 123745459370](https://github.com/auths-dev/auths-proof/actions/runs/40958688998/job/123745459370)
executed the exact native mutation generator and the independent comparator:
**28 requests, 26 responses and 2 families**. This retains the documented
boundary between native compilation/classification and independent domain
references; it is not provider execution qualification.

[Reference simulation job 123745461358](https://github.com/auths-dev/auths-proof/actions/runs/40958688981/job/123745461358)
passed **104 source-only tests**, including mutation-contract negatives and
information-log parser controls. Synthetic malformed logs prove rejection
behavior; they are not native execution evidence.

Both differential artifacts were downloaded and their ZIP SHA-256 values
verified against GitHub:

| Artifact | ID | ZIP SHA-256 |
| --- | --- | --- |
| Information report and native log, run 40958689260 attempt 1 | 12934958430 | `c7af0195a0a6645e2cc6fa58f6b0ada451b46692c98649edfac35d4b551b08c0` |
| Mutation report and native corpus, run 40958688998 attempt 1 | 12933979778 | `3437045757e96a2f1020cb729935e280a2ad8758c125646608f9f766ec1143e0` |

The PostgreSQL job then passed the physical-backup/WAL point-in-time restore
exercise: the pre-target value was retained and the post-target value was
excluded. Its report explicitly records `replay_continuity_claim: false`;
restore success does not establish replay continuity.

## Formal evidence

[Translation job 123749843927](https://github.com/auths-dev/auths-proof/actions/runs/40958689238/job/123749843927)
passed validated reuse from successful source `d9618a56`, run `40942189152`,
attempt `1`. Current phase artifact `12935932042` was downloaded and verified
with ZIP SHA-256
`0a7c6b905104cd086c5aa247322d28f8764a73c09ca22ddc032636aa685bc76d`.
It records `execution: reused-pr-run`, `reproduction_count: 2` and these
identities:

| Identity | SHA-256 |
| --- | --- |
| Formal source closure | `a002dc42725b1e3e5234f8ba11eea3f8ba8141e2e64f052d950182d4f93a2825` |
| Planned translation closure | `a5a98c9c76bde8f03021fd572008961e2c425d11a8eb9ba2080b270b4a65c519` |
| Toolchain closure | `baff1cabbf9c83ffca0f4bdb1b8dda685a5ac59638e95d6d12e57f5d5bda9633` |
| Evidence closure | `cbc4400d316703bd0a0af4136f65c580047835a03144353343d051214233269f` |

[Authoritative Lean job 123756976236](https://github.com/auths-dev/auths-proof/actions/runs/40958689238/job/123756976236)
passed its clean rebuild: 329 compiled claims and reviewed transitive axioms,
4 reviewed external links with 0 compiled external axioms, and 4 Rust
refinement tests. [Kani job 123749843917](https://github.com/auths-dev/auths-proof/actions/runs/40958689238/job/123749843917)
recorded 49 successful verifications. The separate formal-fast feedback job
also passed; it is not qualification evidence.

[Final formal evidence job 123766644169](https://github.com/auths-dev/auths-proof/actions/runs/40958689238/job/123766644169)
passed exact-revision aggregation of translation, clean Lean and Kani.
[Formal-translation rollup 123769550016](https://github.com/auths-dev/auths-proof/actions/runs/40958689238/job/123769550016)
also passed. Final evidence artifact `12938720181` was downloaded and verified
with ZIP SHA-256
`9611da85b53cfdac51ee1c90a2c9667157845962daf82189865dc3abfaf9cd0f`.

## Terminal result

All **96 checks** are terminal: **85 passed, 3 failed and 8 conditionally
skipped**. The three failures are the authoritative implementation, its
rollup and [CI qualified 123769584918](https://github.com/auths-dev/auths-proof/actions/runs/40958689238/job/123769584918).
The final qualified gate records `AUTHORITATIVE: failure`; its formal,
compliance, dependency, secret and required live-reference inputs succeeded.
These three failures share the single stale gateway-closure root above.

The **14 workflows** ended with **12 passed, 1 failed (CI) and 1 conditional
skip (custody live)**. Python's complete supported interpreter/platform
matrix and installed native harnesses passed, as did packed TypeScript and
both installed demos. No platform was removed or retried.

## Workflow inventory

| Workflow | Run | Result |
| --- | --- | --- |
| CI | [40958689238](https://github.com/auths-dev/auths-proof/actions/runs/40958689238) | Failed: stale gateway closure |
| PostgreSQL lifecycle | [40958689260](https://github.com/auths-dev/auths-proof/actions/runs/40958689260) | Passed |
| Python SDK | [40958688998](https://github.com/auths-dev/auths-proof/actions/runs/40958688998) | Passed |
| TypeScript SDK | [40958689256](https://github.com/auths-dev/auths-proof/actions/runs/40958689256) | Passed |
| SDK recipes | [40958689237](https://github.com/auths-dev/auths-proof/actions/runs/40958689237) | Passed |
| Recipe qualification | [40958688981](https://github.com/auths-dev/auths-proof/actions/runs/40958688981) | Passed non-live stages; live qualification stages skipped |
| Operator package | [40958689233](https://github.com/auths-dev/auths-proof/actions/runs/40958689233) | Passed |
| Isolation | [40958689244](https://github.com/auths-dev/auths-proof/actions/runs/40958689244) | Passed |
| Airtable installed demo | [40958689243](https://github.com/auths-dev/auths-proof/actions/runs/40958689243) | Passed |
| Stripe installed demo | [40958689266](https://github.com/auths-dev/auths-proof/actions/runs/40958689266) | Passed |
| Independent Google images | [40958689239](https://github.com/auths-dev/auths-proof/actions/runs/40958689239) | Passed application-owned reference |
| Git signing protocol | [40958688983](https://github.com/auths-dev/auths-proof/actions/runs/40958688983) | Passed |
| Branch-protection action | [40958689248](https://github.com/auths-dev/auths-proof/actions/runs/40958689248) | Passed |
| Custody live | [40958689252](https://github.com/auths-dev/auths-proof/actions/runs/40958689252) | Conditional skip |

No workflows were rerun or cancelled during this investigation. No provider
calls, unattended operator consent, AP070/AP073 source changes, merge or
deployment were performed. Conditional skips are not passed live evidence.
The final source head still requires its own applicable CI and acceptance
checks after the gateway closure and epoch changes.
