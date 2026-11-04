# AP074 generated concurrent durable histories

`native_recovery_actor_tests::generated_history_tests` adds generated concurrent
mutation histories to the existing all-protocol predicate proofs, sequential
property tests and native crash/capacity/dependency matrices. The oracle is an
independent set of previously entered logical operations. It does not invoke the
shipping reducer to decide its expected number of new external entries.

Four deterministic seeds generate different first-admission orders over four
native-approved effects plus subsequent mixed replay schedules. Each history
has eight concurrent rounds: duplicate first admission, two distinct first
admissions, mixed new/replayed admission, and five generated replay pairs.
Two real OS workers independently reopen the maintained store, load the installed
engine, synchronize on a bounded TCP start barrier, then submit the original
native proof/action/exact approval. Actual writer-fence order is chosen by the OS.

For every round the test compares the model's expected new entries with both
the real local HTTP capture delta and actual native transport witnesses. It
checks native journal stage and byte-for-byte retention of every earlier record.
The source baseline is unchanged throughout. A final concurrent negative uses
fresh native resource authority for another operation with an earlier exact
approval. Both workers must refuse before credential lease, reservation or transport;
the new operation must remain absent and all earlier records remain unchanged.

Each backend therefore produces four histories, 32 positive concurrent rounds,
four negative concurrent rounds, 72 generated worker processes, 16 new effect
entries and four baseline writes. The fresh process for every event also checks
that reopening cannot regenerate a permit from retained Unknown history.

The PostgreSQL workflow explicitly executes the file and TLS PostgreSQL selectors
and uploads `ap074-generated-histories-<run>-<attempt>`. The two JSON artifacts
include exact source/checkout revisions, gateway source closure, generated plans,
actual native results and observed HTTP/native counters. They retain real
scheduling outcomes rather than pretending concurrent observations have one
canonical byte representation. They expose no private proof, review, approval,
record body, response body or credential.

This producer covers generated concurrent single-grant/replay histories. It
does not independently prove every protocol transition, conservation of bounded
count/sum capacity, crash durability, hostile-process containment or provider
qualification. Those remain the responsibility of the existing source-linked
kernel/refinement and file/PostgreSQL fault, capacity, entry, disclosure and
independent-recovery evidence. No production decision, journal or retry owner is
added. Hosted execution is pending; this source does not close A20 on its own.

Installed trust, signer keys, provider credentials and clock are explicit synthetic
fixtures. Ordinary native verification and exact signatures still execute; the
cohort does not claim human presence or an authenticated production clock.
