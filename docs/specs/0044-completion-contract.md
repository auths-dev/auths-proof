# AP-SPEC-0044 completion contract

Status: implementation contract for the remaining live-provider qualification work.

This document is subordinate to
`0044-live-provider-qualification-and-recovery-evidence.md`. It closes only the
remaining execution gaps. It does not relax, replace, or reinterpret any trust,
privacy, ordering, crash, provider-observation, or cleanup requirement in that
specification.

## 1. Definition of done

AP-SPEC-0044 is complete only when all of the following are true:

- the protected workflow starts the sole append sequencer and every role-fixed
  signer and reader before candidate provisioning;
- each reviewed operation phase is entered through the protected phase
  controller, invokes one installed generated-client operation, and cannot be
  released until every required source has received a durable append ACK;
- Stripe, PostgreSQL, and OpenTofu use their real production provider paths and
  independent protected observer paths; no fixture or candidate-authored
  provider truth can satisfy qualification;
- the exact source and ledger trust registries contain their reviewed public
  keys and process identities, and every signer verifies its supplied seed
  against the checked key after receiving its first authenticated record and
  before releasing a signature;
- collection, installed-package verification, protected observation, cleanup,
  assembly, sealing, and fresh attestation verification succeed for the full
  reviewed roster; and
- a provider-free denied phase reaches `stage-common-phases`, while every
  missing, malformed, wrongly owned, or dead protected dependency refuses
  before provider provisioning or SDK invocation.

Private seeds, provider credentials, fixed protected UIDs/GID, and provider
accounts are deployment inputs. Repository code verifies and consumes them but
must never synthesize, log, retain, upload, or silently replace them.

## 2. UX

The operator supplies the already-defined protected environment, checked
attester revision, fixed UID/GID policy, source/ledger seeds, and domain
credentials, then dispatches one domain workflow. There is no interactive
fallback and no partial-success mode.

```text
+-------------------- profile qualification ---------------------+
| 1. verify immutable release + protected tools + trust inputs   |
| 2. initialize one authenticated ledger per provider row        |
| 3. start protected row services                                |
| 4. for each scenario/phase: READY -> SDK CALL -> DURABLE DONE  |
| 5. stage -> index -> assemble -> seal                          |
| 6. installed verify -> independent observe/cleanup -> attest   |
+----------------------------------------------------------------+
         any mismatch: stop, clean exact row, publish no pass
```

Operator-visible failures name the phase and protected role, but never include
secret bytes, raw provider identifiers, credentials, opaque profile state, or
provider response bodies. Mutation transport and recovery reconciliation use
distinct signed event kinds so a read-only recovery query cannot inflate the
single-mutation counter algebra. Every proxy request also commits to the exact
CredentialBroker lease identity without retaining a secret digest or raw
credential.

## 3. Architecture

```text
checked trust + one-secret role processes
                    |
                    v
          +---------------------+
          | sole append session |
          +----------+----------+
                    ^
                    | durable marker ACK
     +--------------+---------------------------------------------+
     |              |             |             |         |       |
 Supervisor    ClientProxy   JournalReader  Credential  Profile/  Provider
 source        reader/signer reader/source  Broker      Receipt   Proxy/
     ^              ^             ^             ^       readers   Observer
     |              |             |             |         ^       ^
     +--------------+----- protected phase controller ----+-------+
                                  |
                             READY / COMPLETE
                                  |
                        installed generated SDK
                                  |
                        qualification candidate agent
                                  |
                           ProviderProxy
                                  |
                             real provider
                                  |
                     independent ProviderObserver
```

### 3.1 Ownership

- The workflow owns row service lifetime and always-cleanup handling.
- The no-secret controller owns candidate process, state directory, cgroup,
  phase ordering, and the release gates.
- Each source seed is visible to exactly one role-fixed signer process.
- ClientProxy is the only SDK transport observer.
- CredentialBroker is the only mutation-credential owner.
- JournalReader and ProfileStateReader derive durable facts from pinned files.
- ReceiptVerifier derives receipt facts from the pinned journal and checked
  receipt anchors.
- ProviderObserver independently reads the provider after the candidate has
  been frozen or reaped and before `ScenarioCompleted` is appended.
- ProviderProxy owns the exercised provider transport and durably records the
  exact write/response boundary before releasing it to the candidate. Its
  reader and signer are distinct fixed identities.
- The in-row ProviderObserver owns only the runtime-read credential, appends
  its signed observation before `ScenarioCompleted`, and is distinct from the
  post-seal observer job that independently repeats and compares the read.

### 3.2 Service lifetime

Every service uses the immutable ledger deadline. A row supervisor may restart
an unseeded reader or a one-seed signer after ambiguous transport loss, but an
exact retained intent must resume read-only. A deterministic trust, canonical,
identity, ownership, or protocol failure is fatal. Row cleanup terminates and
reaps the controller process group, exact retained cgroups, readers, signers,
and sequencer, then removes only identity-checked socket/cgroup directories.

## 4. APIs

No shipping public API is added.

### 4.1 Common collection adapter

`QualificationCollectionAdapter::invoke_phase` remains the sole domain seam.
It receives the reviewed scenario, phase index, role, and profile; it invokes
exactly one installed generated-client method and returns one bounded untrusted
`QualificationCollectedOperation`. That object contains only the reviewed role
and semantic profile. Attempts, receipt claims, lifecycle state, counters, and
provider truth are derived only from authenticated ClientProxy, JournalReader,
ReceiptVerifier, ProfileStateReader, ProviderProxy, and ProviderObserver events.
PostgreSQL and OpenTofu may retain their successful preflight capability only
in the adapter's private environment until the immediately paired effect phase;
it is never serialized into the candidate collection.

The common harness owns phase ordering. An adapter cannot receive a callback,
batch phases, author signed evidence, select a socket, change a profile, or
advance after a controller/source failure.

The installed generated profile distribution is an exact verified release
artifact beside the root SDK distribution. One common offline runner installs
and imports both checked artifacts, invokes one generated method over the
controller-owned sockets, and exposes only a bounded canonical public
input/output protocol to the collection adapter. Domain adapters must not
duplicate package installation, interpreter selection, or subprocess logic.

Provider setup and onboarding execute in a distinct protected setup zone. They
produce one versioned, capability-free run handoff that binds the reviewed
provider row and cleanup identity. The no-secret collection process consumes
that handoff; it never receives setup, mutation, runtime-read, observer, or
cleanup credentials.

### 4.2 Protected row runtime

The existing environment contract is mandatory and exact:

- `AUTHS_QUALIFICATION_PHASE_CONTROLLER`
- `AUTHS_QUALIFICATION_AGENT`
- `AUTHS_QUALIFICATION_AGENT_CONFIG`
- `AUTHS_QUALIFICATION_AGENT_LAUNCHER`
- `AUTHS_QUALIFICATION_LEDGER_PLAN`
- `AUTHS_QUALIFICATION_LAUNCHER_LEDGER_PLAN`
- `AUTHS_QUALIFICATION_SOURCE_TRUST`
- `AUTHS_QUALIFICATION_RECEIPT_TRUST`
- `AUTHS_QUALIFICATION_CONNECTION_STORE_TEMPLATE`
- `AUTHS_QUALIFICATION_PHASE_RUNTIME_ROOT`
- `AUTHS_QUALIFICATION_CGROUP_ROOT`
- `AUTHS_QUALIFICATION_PRINCIPAL`

Domain-specific provider credentials remain in their existing protected job
zones. They are not forwarded to the controller, candidate collector, source
signers, evidence archive, or installed-verification job.

Before collection, the root-only `prepare-row-runtime` command creates one
new row root and delegated cgroup root. It derives every signer and reader UID
from checked source trust, creates role-specific socket directories, and
publishes exact owner-only copies of the ledger plan, source trust, and (only
where required) receipt anchors for each role. One CredentialBroker initializer
receives the descriptor and mutation credential only on stdin, validates them
with the production provider adapter, and creates a broker-owned public
connection store plus a distinct secret store. The candidate receives only an
exact public connection-store snapshot through the setuid launcher.

The decision-receipt, execution-receipt, and recovery seeds are materialized
by three separate root-only invocations. Each receives exactly one seed on
stdin, compares its derived public key with the public agent configuration or
immutable ledger plan, and creates or exact-verifies only the fixed
`qualification-{decision,execution,recovery}.key` member in every scenario
state directory. These agent-owned, mode `0600`, regular single-link files are
removed by exact row cleanup. The qualification agent opens them by fixed name
through the launcher-pinned state-directory fd and uses the common
receipt/recovery signer constructor; it never accepts a caller seed path or
generates a fallback recovery identity. Before accessing agent state, the
setuid launcher authenticates the real caller UID and its parent controller
PID, start time, and executable against the root-owned launcher ledger policy,
then repeats that check immediately before agent execution.

### 4.3 Source processes

The existing source commands and canonical record types are reused. Workflow
orchestration may relaunch one-shot signers, but it must not add a second append
path, caller-selected source, generic unsigned event envelope, or process that
receives more than one source seed.

Ordinary rows use immutable-deadline sessions for the append sequencer and all
eight role-fixed sources/readers. The Supervisor is one isolated row-scoped
signer process, consistent with the parent specification's bounded source
session: every authenticated request authorizes exactly one phase, decision,
or crash-action event, and the signer has neither provider credentials nor
append authority. Every process runs under the exact UID from source trust with
an empty environment. Workflow steps expose only one source seed each; the
source process receives it on stdin and never inherits it in its environment.
PID/status files and logs live outside public evidence and are removed during
always-cleanup.

ProviderProxy and ProviderObserver each use the same split fixed-role pattern:
one no-seed reader owns its authoritative input and one minimal one-seed signer
accepts only its typed record. Both append through the sole sequencer and must
receive its durable ACK before the controller can complete the phase. The
ProviderObserver reader is started with the runtime-read credential only in its
protected zone; that credential is absent from the signer and common collector.

### 4.4 Trust bootstrap

Trust materialization is a two-pass protected ceremony:

1. build the reviewed role-fixed tool bundle;
2. generate eight independent Ed25519 seeds outside the repository;
3. commit only their public keys, exact source/reader identities and UIDs, and
   freshly measured role artifacts;
4. rebuild the same attester revision and require every artifact digest to
   equal the checked registry; and
5. install the eight seeds and ledger seed in the protected environment under
   the exact fixed secret names.

The workflow verifies registry completeness, current key intervals, artifact
bindings, and process identities before provisioning. Each one-seed signer
verifies seed/public-key equality in that same process only after its first
authenticated record and before releasing a signature. Placeholders, a
separate seed-verifier process, and dynamic registry rewriting are forbidden.

Until that external ceremony populates both checked trust registries, the
workflow stops during ledger initialization or row preparation. The empty
registry is an intentional release blocker, not a development bypass.

### 4.5 Mixed ordinary and crash phases

One `run-phase` lifecycle is selected only by the current immutable ledger
phase's optional failpoint. Ordinary and crash phases share the same
READY/COMPLETE contract, candidate/state ownership, source sessions, journal
drain, receipt/profile verification, cgroup cleanup, and `ScenarioCompleted`
gate. Domain adapters cannot choose a crash mode or route a crash phase through
the ordinary path.

The candidate emits authenticated boundary checkpoints; the controller drains
the complete store-owned prefix and withholds release only at the selected
failpoint. `before-decision` uses the single pre-decision checkpoint. Every
later failpoint reuses the common durable boundary/transport gate. After the
exact process and cgroup are killed and reaped, the controller restarts
generation `n + 1` with the same pinned state and signing identities and drives
the typed status/recovery dispatcher to the reviewed terminal result. All
recovery, provider, profile-state, receipt, and observer facts receive durable
source ACKs before phase completion.

### 4.6 Source-authenticated admission faults

The protected ClientProxy, not the installed SDK or candidate agent, selects the
closed qualification-only admission fault for `configuration-mismatch`,
`connection-substitution`, `principal-substitution`, and `stale-evidence`. The
fault is carried only in the authenticated client-bridge binding. The agent first
authenticates the real SDK peer, then applies the selected fault to the internal
admission input; it never treats a substituted principal as the transport peer.

Configuration, connection, and principal substitution each produce one typed,
operation-free `Unavailable` result before credential access or provider entry.
Connection substitution must resolve two distinct nonexistent aliases through
the production registry and fail if either unexpectedly exists. Stale evidence
performs two exact calls: the first samples `expiresAt - 1` and succeeds, while
the second samples `expiresAt` and produces operation-free `Unavailable`. The
bridge fault is nullable for every other scenario and any unsupported,
duplicate, or out-of-order fault request is fatal.

### 4.7 Generated qualification routing and provider-write ownership

One generated qualification route, derived from each `profile-package.json`,
owns ProviderProxy execute/reconcile dispatch, ProviderObserver observation and
truth validation, ReceiptVerifier profile claims, and ProfileStateReader
snapshot path/inspection. Adding a domain cannot require a hand-maintained
profile switch in a common protected binary. The manifest's
`profileStateSnapshot` is a safe relative path and the reader opens that fixed
member only through the pinned scenario-state directory.

`ProviderRequestWritten` means the protected ProviderProxy has authenticated
and exact-bound the request to the pinned journal, redeemed the broker-owned
lease, durably accepted the request into its single at-most-once transport
obligation, and received the sequencer ACK. From that point the request may
reach the real provider even if the candidate is killed; the proxy completes or
reconciles that retained obligation and never accepts a second mutation intent.
This is the request-body commitment used by `crash-after-request-write`; it is
not a candidate claim that a network write completed. `ProviderResponseObserved`
is emitted only after the real provider call has returned a canonical response.

## 5. Failure behavior

- Static plan/trust/config/topology failure: no provider provisioning.
- Protected service startup or readiness failure: no SDK call.
- Source or sequencer deterministic failure: terminate the row and clean it.
- Ambiguous post-durable response loss: exact retry until the immutable
  deadline, without a duplicate event.
- SDK, candidate, or controller cancellation: complete the truthful terminal
  ClientProxy handoff before releasing or cleaning the row.
- Provider observation mismatch or incomplete cleanup: no qualification pass.
- Missing external seed, UID, or provider credential: explicit deployment
  prerequisite failure, never a skipped scenario.

## 6. Acceptance

The repository-controlled acceptance suite must include:

1. provider-free denied phase through phase start, source append, phase
   completion, `stage-common-phases`, event index, assembly, and sealing;
2. dead/missing/wrong-identity role refuses before adapter provisioning;
3. one successful and all reviewed hostile/live vectors for each domain;
4. PostgreSQL/OpenTofu preflight capability survives only into the paired
   effect phase and cannot be substituted;
5. response loss, cancellation, crash, reader restart, signer ACK loss, and
   sequencer ACK loss append one exact event per durable occurrence;
6. independent provider truth and cleanup cannot be derived from candidate
   collection or common journal output;
7. archives contain no seed, credential, raw provider identifier, opaque
   profile state, provider response, or undeclared member; and
8. the final installed and attestation jobs reverify the exact uploaded
   release/evidence identities from a fresh protected checkout.

The completion gate runs format, compile, unit, workflow/static compliance,
Linux integration, hostile protocol, and provider opt-in tests. A platform or
credential prerequisite that prevents an authoritative test remains a visible
release blocker; it is never converted into a passing synthetic result.

## 7. Implementation status

This contract is the remaining-work specification, not a declaration that
AP-SPEC-0044 has passed its completion gate.

Repository-controlled work implemented in the current tree:

- per-phase collection through the protected controller seam;
- root-only row topology materialization with role-specific ownership and
  exact plan/trust-file copies;
- mixed ordinary/crash phase dispatch selected from the immutable phase plan,
  with typed checkpoints for the complete reviewed failpoint roster, exact
  kill/reap, generation-two restart, and ordered crash-action evidence;
- executable eight-role workflow orchestration for the append sequencer,
  role-fixed signers, and no-seed readers;
- pre-provision validation of plan, trust, configuration, runtime-directory,
  and cgroup topology;
- one-seed source launch with in-process seed verification before signing; and
- three isolated agent-signing materializers, fixed scenario-state handles,
  shared receipt/recovery signer construction, plan-bound recovery identity,
  and a root-policy-authenticated setuid launcher (Linux acceptance remains
  listed below);
- retained PID/start-time process-group shutdown followed by root-only,
  plan-bound cleanup of the exact runtime and policy trees, empty delegated
  cgroup, signing handles, sockets/logs, and reviewed protected agent install;
- co-persisted journal-boundary evidence, protected CredentialBroker and
  ProfileStateReader services, and exact response-loss resume semantics;
- an authoritative ProviderProxy for execute and reconciliation traffic,
  including CredentialBroker lease binding, retained exact-response retry, and
  a durably accepted at-most-once request obligation across candidate crash;
- an in-row ProviderObserver that reads independently after candidate reap,
  durably appends redacted truth, and gates `ScenarioCompleted`;
- protected setup handoffs, exact generated-profile release artifacts, a common
  installed-client runner, and live setup/observer/cleanup implementations for
  Stripe, PostgreSQL, and OpenTofu;
- source-authenticated, operation-free admission faults for configuration,
  connection, principal, and exact freshness-edge/stale scenarios;
- one manifest-generated qualification route covering provider transport,
  provider observation/validation, receipt claims, and profile-state snapshot
  inspection; and
- focused compile, unit, phase-seam, workflow-shape, and shell/YAML checks.

Repository-controlled work still required for completion:

- bind every domain scenario to one protected immutable stimulus and an exact
  domain-owned outcome predicate; swapped, omitted, or happy-path-substituted
  scenario semantics must fail final verification;
- route every OpenTofu subprocess through the reviewed Linux namespace,
  filesystem, egress, seccomp, cgroup, pinned-executable, and process-tree
  cleanup policy, with hostile escape and timeout tests;
- compile and exercise a generated fourth provider through the full
  qualification lifecycle, not merely the scaffold/roster projection;
- run the provider-free denied-phase Linux integration through final staging,
  assembly, sealing, and fresh attestation verification;
- add Linux process tests for all twelve crash boundaries, including
  generation-two SDK recovery and ACK-loss uniqueness; and
- run the live provider matrices and Linux hostile process coverage for launcher
  caller authentication, restart identity reuse, and exact cancellation cleanup
  under the protected deployment identities.

Deployment work still required outside the repository:

- conduct the two-pass source/ledger key ceremony and populate both checked
  trust registries with the reviewed UIDs, public keys, and artifact digests;
- provision the matching protected seeds and fixed process identities; and
- provide independent live-provider and observer environments.

The authoritative qualification check must remain fail-closed while any item
above is unresolved. In particular, the checked empty trust registries are a
deliberate release blocker and must not be replaced with generated placeholders.
