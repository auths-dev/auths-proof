# Production gateway operations

Use the exact installed `auths-gateway` and `auths-qualification` binaries and
verified package checksums. Run operator commands as the gateway state owner,
with operator workload identity for credential mutations; the serving process
keeps its read-only runtime identity. Root is required only for doctor's
privilege-drop test. Application processes receive neither identity nor state.

## Diagnose and stop

`doctor --state-dir ... --app-socket ... --app-uid ... --app-gid ...` prints all
nine required typed checks and the optional observer state. It checks the
actual lifecycle record, recipe binding, current credential-store confirmation,
qualification, clock and process isolation. Any failed or unmade check yields
nonzero status. Keep the JSON report. A missing observer explicitly means
signed outcomes are unavailable. `status` reports the serving process's local
in-flight count; it is not a cluster-wide drainage claim.

If provider, custody or qualification inputs are unavailable, use
`disable --state-dir ... --store-only`. This needs only installation metadata
and the lifecycle store, so it also works with the gateway stopped. It is
idempotent, retains attempts unchanged and claims no drainage. Use
`revoke --state-dir ... --store-only` for permanent revocation. Later run the
`credential-collect` with healthy operator custody on every host that recorded
credential generations to delete the exact credentials;
a deletion error does not undo revocation. Never turn unknown into failure or
submit the operation again. Database failure means no durable stop can be
claimed; isolate app ingress at the host firewall and retain the incident.

## Provider-secret rotation

For the web-identity reference, the operator configuration must explicitly
provide `AUTHS_GATEWAY_RUNTIME_ROLE_ARN` and `AUTHS_GATEWAY_RUNTIME_TOKEN_FILE`
for read confirmation. `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE` name
the write-only operator identity. The operator process reads with the former
and creates/deletes with the latter; the serving process keeps only its
read-only identity. Neither role needs broader permissions.

Use the operator identity and `rotate-prepare --operator-process
--credential-stdin --state-dir ...`, piping the new provider secret. It runs
the recipe's fixed credential checks and stores a successor without publishing
it. Retain only the returned reference commitment. Then use `rotate-commit
--operator-process --state-dir ... --commitment ...` to atomically publish it.
Check status on both hosts; each must see the same shared generation and hold
the exact committed credential generation. The old generation remains for at
least the fixed 20-second retirement delay. Run `credential-collect --state-dir
...` under operator identity on each host that created a generation; it waits
20 seconds after observing the record, requires that record unchanged, then
deletes at most sixteen obsolete exact generations. It keeps the active and
future prepared generations. Rerun after a conflict or deletion failure.
Durable `credential-journal.json` notes are written before storing a candidate,
so partial setup or a process exit does not lose its cleanup obligation.
An abandoned future generation becomes collectable after disabling advances
the shared generation past it. Collect before preparing another successor. Repeat the exercise with a stop
between prepare and commit; a stale commitment must fail, leaving the old
record authoritative. For emergency cutover: disable, wait the fixed 20 seconds for entries on
both hosts, rotate while disabled, collect old generations under operator
identity, verify both hosts, then enable. Never retain a new secret in terminal history.
Operator-process drainage describes only that short-lived process; wait for
all serving hosts separately before retiring external credentials.

## Qualification signer, expiry and revocation

The offline owner certifies a new protected software release signer with the
ceremony tool. Publish the new certificate, current signed revocation list,
release index and exact attestations together. On each host, run
`auths-gateway qualification-import --state-dir ... --from ...`; add
`--admin-socket ...` when serving uses a nondefault socket. Import verifies and
stores the inputs, then automatically requests `qualification-reload` from
the serving operator socket. If the gateway is stopped, it reads them at its
next start. There is no separate `qualification-reload` CLI command. Inspect
`auths-gateway qualification-status --state-dir ...` and the serving `status`
response after import, so a failed reload cannot be mistaken for acceptance.
The production clock requires a synchronization sample at most fifteen minutes
old, with no future timestamp; stopping time synchronization must make
`gateway.qualification.clock-untrusted` appear once that bound is exceeded.
Restore synchronization through the reviewed time service, not by touching its
marker. The reference polling interval is at most five minutes.
Do not extend validity by editing files or the clock. Rehearse signer rotation,
signer revocation, stale revocation inputs and untrusted-clock refusal with
`auths-qualification stage-trust --tuple ... --out ...`, using the candidate's
public tuple. That tool uses disposable test signing material and proves the
trust mechanism; it does not rotate a production root or prove a gateway's
lease boundary. Separately exercise expired attestations, expired certificates,
revoked qualifications and those other signed input faults on the disposable
gateway deployment: every required recipe must stop before lease. Keep the
signed input digests,
closed codes and zero-entry/lease witnesses; no private key enters support
bundles or gateway hosts. Publish a root-signed revocation list at least every
24 hours (72 hours is the hard maximum), including when nothing is revoked.
Treat a missed update as an incident that disables required recipes.

A root replacement is a new reviewed gateway build pin and new qualification
run for its exact build/closure, not an operator override. Stop writes, retain
revocation floors, install the newly pinned candidate and import its new-root
inputs. Old-root inputs must refuse. Only resume after exact candidate evidence
and the human boundary review. No root private key is created on a gateway or
in an online agent workspace.

## Backup, point-in-time restore and restart

Archive PostgreSQL WAL continuously and take encrypted snapshots. Back up
public installation files, operator attestation, qualification inputs, credential
journals and host floors. Keep `connection-floor.json` and qualification verifier floors in an
independent current recovery record; never restore older floors together with
an older database. Before an exercise, record connection and credential
generations, recipe/lock digests, qualification issue-time/revocation floors
and attempt counts on both hosts. Disable app ingress and new entries; stop
both binaries and retain unknown/response-recorded operations.

For a self-hosted PostgreSQL server, take the physical backup with the
maintained PostgreSQL client: `pg_basebackup --host postgres.internal
--username auths_backup --pgdata /secure/backups/candidate --format plain
--wal-method stream --checkpoint fast`. Supply the password with an owner-only
PGPASSFILE and require `PGSSLMODE=verify-full` with the reviewed CA. Test WAL
archiving before the backup. Create a named point with
`SELECT pg_create_restore_point('reviewed_restore_point')` and retain its WAL.
On the isolated replacement server, restore the physical backup into an empty
private data directory, create `recovery.signal`, and set `restore_command`
to copy exact archived WAL files, `recovery_target_name` to that reviewed point
and `recovery_target_action` to `promote`. Start with the replacement's own TLS
certificate and hostname. Verify records committed before the target exist
and those committed after it do not; retain the closed exercise report.
The disposable hosted exercise automates these mechanics. It does not make a
claim about missing replay rows or external provider effects.

Restore snapshot plus WAL to a new PostgreSQL endpoint, validate its TLS name
and schema, and keep original hosts stopped. Start each replacement from its
current independently retained floor files and reviewed installed inputs.
A restored connection generation below the host floor, or different bytes at
the same generation, refuses before lease. Recipe drift, unavailable exact
credential generation and rolled-back qualification inputs also refuse.
Never delete floors to make readiness pass. If the store lost committed replay
or budget state, continuity is unproven: quarantine the restored deployment
and rebuild authority/connection state under owner review; do not serve old
operations as fresh. A newly created host without a floor cannot prove that a
database is current; recover its floors before starting it.

For each response-recorded or unknown operation, use `reobserve --state-dir
... --operation-id ...` once. It uses the stored plan and a fresh read-only
check under the declared capability. Confirmed evidence may advance the
record; missing or delayed evidence stays unknown. Reobserve again after
visibility returns; never issue a new provider write as recovery. Keep the
opaque operation digest and stage only in support evidence.

## Rolling upgrade

Require attestations for each candidate's exact binary/semantic closure and
platform tuple. Disable new writes, drain each serving host, capture bounded
support bundles and floors, and upgrade one host. It must derive the same
recipe and connection generations; the old host must refuse a changed binding
rather than choosing a stale credential. A binary without a current exact
tuple attestation stays disabled. Validate doctor and read-only reconciliation
before replacing the second host and enabling. Do not mix obsolete store
schemas or interpret restore as replay continuity. Keep expiry and revocation
updates running during the upgrade.

## Independent operator trial

Give a person unfamiliar with this implementation only the verified packaged
binaries, packages, public configuration and this runbook. Record participant
identity/role, artifact digests, dates, timings, attempted commands, redacted
reports and defects. They deploy both hosts, diagnose an unavailable credential,
rotate, disable during outages, restore with retained floors, reject a stale
restore and reconcile unknown without a write. Plant canaries in excluded
sources and scan the actual support archive. Fix every blocking defect and
have that participant rerun its failing step. The implementer cannot supply
this participant result; a simulated SDK onboarding pilot is separate evidence.
