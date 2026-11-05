# AP074 exact-head CI investigation — 76d008a0

Published source: `76d008a020e5b8e6c89e70bcb86ebc34e2c0e29d`, PR213. Repair: `037cb97f5bf2df186f3038ce75e5494d39230e34`, clean isolated checkout, not pushed. Main worktree, AP073 and AP070 source untouched.

## Producer identity

Observed PG and Python source-contract checkouts use PR merge `2507f1387b16fdc6e9da9c51b83130aaa1f32df0`. Its tree `fb2283aa7e1db3550a18ca3cc5cb49a1c532e5fa` equals the published source tree (fetched and diff verified). Source-head labels do not replace this actual producer identity.

## Root matrix

| Root | Hosted evidence | Repair and evidence |
| --- | --- | --- |
| Strict clippy rejects missing semicolon in test-only mutation generator | [preflight123733500686](https://github.com/auths-dev/auths-proof/actions/runs/40954513373/job/123733500686), native_differential_tests.rs:384, semicolon_if_nothing_returned | Add semicolon, no lint allowance. `cargo clippy --locked -p auths-gateway --lib --tests --all-features -- -D warnings` passes27.40s. Local log `/tmp/ap074-ci-76d0-gateway-clippy.log`. |
| Independent information crash reference loses spawned child before readiness | [PG123730998172](https://github.com/auths-dev/auths-proof/actions/runs/40954513640/job/123730998172), child spawn then parent EOFError | Retain parent ownership of Event while spawn child reconstructs its semaphore and until child exits. Exact full runner fails before change and passes22pairs after. Real SIGKILL, abandoned claim, unknown attempt, no reentry/release and conservation assertions unchanged. |
| Downstream required implementations skipped after preflight failure | [authoritative rollup123736259829](https://github.com/auths-dev/auths-proof/actions/runs/40954513373/job/123736259829), REQUIRED=true/RUN_RESULT=skipped | Fail-closed dependency rollups, not additional independent source defects. No authoritative formal/Kani/translation/compliance/security acceptance claimed. |

## Executed evidence

- PG job actually passed all24 explicit native selectors, including both retention fixtures, before installing the SDK and failing the new information runner. The native log is artifact12933406462, downloaded to `/tmp/ap074-ci-76d0-pg-native.zip` and extracted `/tmp/ap074-ci-76d0-native.log`. Subsequent physical/WAL restore stages were skipped after failure; these are unexecuted on this head.
- [Python source job123730999956](https://github.com/auths-dev/auths-proof/actions/runs/40954513619/job/123730999956) passed the exact native mutation generator and independent comparator:28requests,26responses,2families. Report artifact12934145521 ZIP SHA256 `a5e66619c969bc7d0067e22bff90996bbdf8fd21e9e80025813a927e832605ee`; downloaded and verified. Report `/tmp/ap074-ci-76d0-mutation-report.json`.
- [Reference job123730998799](https://github.com/auths-dev/auths-proof/actions/runs/40954513618/job/123730998799) ran104 source-only unit tests successfully, including information parser controls and mutation comparator negatives. Those synthetic parser fixtures establish rejection controls, not native execution.
- Current-head macOS wheel artifact12933058235 ZIP SHA256 `17c3659e6dbacc1459427daddbf703a3e301c5bed36250dc17b4615ba06d9456` was verified and installed without dependencies/network into `/tmp/ap074-ci-76d0-python`. Exact failed runner replay:

```text
/tmp/ap074-ci-76d0-python/bin/python qualification/reference/ap074_information_differential.py --native-log /tmp/ap074-ci-76d0-native.log --output /tmp/ap074-ci-76d0-information-repro-current-sdk.json
```

Result:22pairs,2adapters. This is local repaired reference execution against actual hosted native evidence; it is not a passed hosted information comparator or fresh execution of24native cases. The unchanged AP070 reference emitted Python3.13 SQLite ResourceWarnings during focused tests; no AP070 code changed.

## Terminal matrix

All96checks terminal:65success,12failure,19skipped. Fourteen workflow records:11success,2failure(CI and PG),1conditional skip(custody-live). Independent Python/platform matrix, TypeScript, SDK recipes, installed demos, isolation, operator package and reference simulations pass. [Formal-fast123733500692](https://github.com/auths-dev/auths-proof/actions/runs/40954513373/job/123733500692) passed and explicitly records executed-no-qualification. [Formal-translation rollup123739605415](https://github.com/auths-dev/auths-proof/actions/runs/40954513373/job/123739605415) records REQUIRED=true/RUN_RESULT=skipped; [CI-qualified123739647628](https://github.com/auths-dev/auths-proof/actions/runs/40954513373/job/123739647628) failed closed. These are dependencies of the identified preflight failure, not additional source roots. Authoritative formal/translation/Kani and final qualified evidence did not execute successfully on this revision. No jobs rerun or cancelled. No live provider calls, unattended consent, new PR, merge or deploy.

The two-file repair is one coherent batch. Parent owns combined source closure, independent mutation report source hashes and semantic freeze regeneration. Full AP074 acceptance remains incomplete.
