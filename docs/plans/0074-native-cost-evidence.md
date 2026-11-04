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
native dependency verification, fresh fence validation or durability. Exact-head
hosted execution and its actual measured values are still pending. These source
changes alone close no acceptance row and do not establish complete P4 closure.
