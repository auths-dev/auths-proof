# AP074 native cost evidence

AP074 §11 requires measurements as well as finite work bounds. The native test
cohort in `native_recovery_actor_tests::cost_tests` executes eight separately
authorized operations per path on each maintained adapter. Its four paths are
Airtable mutation with a lost response, independently authorized linked recovery,
bounded content acquisition, and separately approved authenticated disclosure
with a real recipient ACK. It uses actual local HTTP and Unix transport and
checks external call counts, received bytes and recorded native outcomes.

The PostgreSQL lifecycle workflow runs both exact selectors after the existing
adapter histories and uploads `ap074-native-cost-<run>-<attempt>`. It preserves
the original 48-selector differential log. The artifact contains
`native-cost-file.json` and `native-cost-postgres.json`, each with the exact PR
source revision, checkout revision and native semantic source closure. This is
an additional evidence producer; existing fault, differential and formal gates
remain required.

Each sample records:

- Native verification time against the engine's actual installed trust context.
- Native installed compilation time, including its own verification and durable
  configuration reads; it is not a subtraction-based compiler estimate.
- Exact approval verification time, followed by ordinary runtime execution that
  independently repeats its required admission and final-entry validation.
- Every pass-through adapter call's elapsed time, input/output byte counts and
  successful/error result. Each real fenced callback also records decision time,
  number of snapshot records and aggregate snapshot bytes. Instrumentation
  forwards the original callback, bytes, result and durability acknowledgement;
  it does not choose authority, re-run a decision or add a retry.
- Proof, action, context, binding, review and approval byte sizes. Actual binding,
  review, approval and fenced snapshot bounds are asserted against native
  constants. Only sizes and timings are exported; private bytes stay private.
- Linux process RSS and cumulative high-water RSS when available. These include
  the test runtime, native engine and local provider task. They are not allocator
  accounting or an independent peak allocation for each path.
- Native inventory enumeration **and record decoding** over increasing real
  retained histories: 3–17 mutation/recovery attempts and 2–16 acquisition/release
  attempts, with the production 4,096-entry inventory limit.

Adapter elapsed time includes lock/pool waiting, reads, callback, persistence and
unlock. It is a measured conservative upper bound on the lock-held interval,
not an isolated lock-hold measurement. The callback time measures native work
while the real adapter holds its writer fence. No network/provider or custody
operation runs inside that callback. Filesystem blocking and database server
scheduling remain operating-system/deployment assumptions.

The source bounds remain: 262,144 bytes per opaque record, 64 records per batch
or fence, two-second lock wait and fence deadlines, at most eight crash-batch
recovery rounds, 16,384 scanned file directory entries and 4,096 retained
inventory keys. A file recovery batch is bounded by
`MAX_GATEWAY_RECORD_BYTES * 2 * MAX_GATEWAY_BATCH_ENTRIES` encoded bytes.
These bound particular owned buffers/work units; they do not claim a total
process heap cap. Native proof/action/context bounds and each recipe's response
and content ceilings remain separately enforced.

Eight small test-profile samples characterize these representative paths, not
production p95 latency, maximum-population scan cost or worst-case heap usage.
The raw distribution must remain available; no latency optimization may weaken
native dependency verification, fresh fence validation or durability. The CI agent verified source `5acd62b0` measurements and retained artifact hashes;
the measured table below is earlier-revision evidence. The final changed head
remains unverified and complete P4 closure is still pending.


## Native cost measurements

Producer [PostgreSQL41903640108/job126832350307](https://github.com/auths-dev/auths-proof/actions/runs/41903640108/job/126832350307), attempt1. Downloaded artifact13358744149 ZIP SHA256 `c2f22d2ed1be9a81a6b9491fe06f88e551acb58c271970288c3fd99318e52825` verified. Raw files below preserve source5acd, merge4906 and gateway closurec461 identities above. Eight small test-profile fixtures per path per adapter; no production SLO or worst-case claim.

All duration cells are **minimum / median / maximum milliseconds**, calculated directly from retained integer nanoseconds. Compilation includes native verification. Fenced callback and adapter per-call ranges pool the real execution callbacks/calls across eight samples; adapter totals sum elapsed calls within each execution sample. Adapter duration includes wait/load/decision/persistence/unlock; it is not isolated lock-hold time. Callback duration includes native validation and encoding, with no provider/custody I/O.

| Backend/path | Verification | Compilation | Exact approval | Execution | Fenced callback, per call | Adapter, per call | Adapter total/sample |
|---|---:|---:|---:|---:|---:|---:|---:|
| file/mutation | 0.682 / 0.759 / 0.790 | 2.389 / 2.461 / 2.524 | 0.186 / 0.187 / 0.204 | 30.973 / 35.151 / 52.722 | 3.701 / 4.471 / 5.377 | 0.012 / 0.022 / 24.431 | 11.935 / 14.936 / 31.409 |
| file/recovery | 0.691 / 0.722 / 0.800 | 6.650 / 6.764 / 6.888 | 0.175 / 0.177 / 0.193 | 62.791 / 63.183 / 82.912 | 7.612 / 10.348 / 18.844 | 0.011 / 0.027 / 19.982 | 33.828 / 34.604 / 44.607 |
| file/acquisition | 0.746 / 0.757 / 0.772 | 3.602 / 3.664 / 3.779 | 0.182 / 0.189 / 0.199 | 47.814 / 54.784 / 65.110 | 5.845 / 7.281 / 9.007 | 0.012 / 0.022 / 15.214 | 18.172 / 18.794 / 25.689 |
| file/disclosure | 0.716 / 0.753 / 0.782 | 3.216 / 3.323 / 3.369 | 0.187 / 0.189 / 0.200 | 68.578 / 70.135 / 102.108 | 10.345 / 14.997 / 20.797 | 0.011 / 0.025 / 36.314 | 33.468 / 34.663 / 58.944 |
| postgres/mutation | 0.733 / 0.767 / 0.941 | 3.255 / 3.374 / 5.180 | 0.186 / 0.194 / 0.214 | 38.226 / 38.814 / 40.923 | 3.705 / 4.496 / 5.337 | 0.363 / 0.449 / 7.956 | 18.008 / 18.683 / 20.254 |
| postgres/recovery | 0.694 / 0.714 / 0.902 | 8.021 / 8.125 / 10.153 | 0.174 / 0.181 / 0.202 | 76.172 / 78.377 / 88.508 | 7.647 / 10.447 / 12.775 | 0.363 / 0.484 / 18.087 | 47.319 / 48.335 / 59.375 |
| postgres/acquisition | 0.731 / 0.769 / 1.950 | 4.489 / 4.547 / 5.954 | 0.182 / 0.185 / 0.206 | 52.586 / 68.293 / 83.657 | 5.900 / 7.351 / 8.877 | 0.325 / 0.454 / 11.710 | 25.783 / 31.355 / 36.357 |
| postgres/disclosure | 0.709 / 0.748 / 0.775 | 4.151 / 4.177 / 4.728 | 0.191 / 0.192 / 0.211 | 77.029 / 78.328 / 85.115 | 10.530 / 14.824 / 21.274 | 0.376 / 0.476 / 24.747 | 41.644 / 42.753 / 45.029 |

Snapshot bytes/records are maximum observed boundary values across compilation and execution, not allocator totals. RSS is Linux whole-process memory, including runtime/provider; high-water is cumulative for the test cohort, not an independent peak per path.

| Backend/path | Execution adapter calls / callbacks | Max snapshot bytes | Max snapshot records | RSS KiB min/median/max | Cohort high-water KiB |
|---|---:|---:|---:|---:|---:|
| file/mutation | 88 / 16 | 4529 | 3 | 32984 / 33720.0 / 34048 | 34048 |
| file/recovery | 104 / 24 | 12022 | 18 | 33324 / 33778.0 / 34084 | 34084 |
| file/acquisition | 136 / 16 | 7332 | 4 | 34416 / 34970.0 / 35272 | 35272 |
| file/disclosure | 96 / 16 | 16693 | 5 | 34708 / 35024.0 / 35336 | 35336 |
| postgres/mutation | 88 / 16 | 4529 | 3 | 37860 / 38720.0 / 39036 | 39036 |
| postgres/recovery | 104 / 24 | 12022 | 18 | 38308 / 38786.0 / 39080 | 39080 |
| postgres/acquisition | 136 / 16 | 7332 | 4 | 41240 / 41652.0 / 41952 | 41952 |
| postgres/disclosure | 96 / 16 | 16694 | 5 | 41460 / 41696.0 / 42016 | 42016 |

| Raw artifact member | SHA256 of archived member |
|---|---|
| native-cost-file.json | `22f49ae6d0071091a0dbf09923440ab875bb64b4ae29a88550e3654c60083df0` |
| native-cost-postgres.json | `777c78520adcc125a83a770e1f332015ed7ad2130ecb250e28aec34e96400842` |
