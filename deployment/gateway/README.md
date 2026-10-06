# Production reference: two Ubuntu hosts, systemd, PostgreSQL TLS, AWS workload identity

This reference runs one connection per gateway process on two Ubuntu hosts,
with a shared TLS PostgreSQL lifecycle store and distinct local installation
and monotonic-floor directories. The application talks through a Unix socket;
provider and secret-manager traffic uses bounded HTTPS. There is no external
HTTP gateway listener to terminate. Install exact release binaries and package
checksums under `/opt/auths/bin`; neither source nor a compiler belongs on the
hosts. Current production builds refuse writes until the qualification root
ceremony and both live qualification gates have completed.

The `Gateway operator package` workflow supplies a source-free archive with
both binaries, these units, a bounded file-digest manifest and the runbook.
Verify the artifact checksum and each payload digest before using it in the
independent trial. A PR artifact is a trial input, not a signed release.

## Host setup

Create group `auths-app-socket` (GID 62000), user `auths-gateway` (UID 62001),
and application user (UID 62002). The gateway's primary group is
`auths-app-socket`. Create `/var/lib/auths/gateway`, owned by UID 62001, mode
0700, and `/run/auths-app`, owned by UID 62001 and GID 62000, mode 0750.
Recreate the latter with a systemd tmpfiles rule at each boot. The application's
only group access is the 0660 app socket; it cannot reach the gateway state,
admin socket, workload token, operator identity or PostgreSQL client identity.
Keep operator credentials in `/run/auths-identity/operator` and runtime
credentials in `/run/auths-identity/runtime`, each mode 0700. Provision
short-lived, audience-bound web identity tokens through the deployment's
identity issuer. The runtime role has GetSecretValue and the one encryption
key's Decrypt; the operator role has CreateSecret, DeleteSecret
and GenerateDataKey, with no secret-read permission. Neither role can list secrets or alter versions. The
operator executes administration as UID 62001 with its separate token path.
Its process uses the explicit runtime-role/token settings in `operator.conf.example`
for read confirmation, and the operator identity for creates and deletes.
Missing identities refuse the operation; neither falls back to the other.
The application receives neither identity directory nor runtime environment.

Copy `systemd/`, `run-with-postgres-url` and the reviewed public runtime configuration.
The protected `/etc/auths/postgres-url` file holds the PostgreSQL connection
string; systemd delivers it in its service credential directory. The wrapper
passes it only to the gateway process, whose doctor probe clears its environment. Never place a
provider token, static AWS access key or release signer in an environment file.
Use a dedicated PostgreSQL password delivered through systemd LoadCredential,
not an application environment or command argument. The maintained TLS client
authenticates the server with the expected name and reviewed CA; it does not
provide TLS client-certificate authentication.
Enable `synchronous_commit`, durable WAL and continuous archive to independent
storage. Let the shipped store apply its current schema; obsolete schemas are
refused rather than translated. Take and restore a database snapshot in the
preproduction exercise before admitting traffic.

Install the reviewed recipe, profile lock, trusted context, distinct operator
attestation and production credential store using `auths-gateway install`.
Pipe the disposable credential from the operator's secret source into stdin;
never put it in argv or a shell literal. The first install uses the write-only
operator role. A second host's `install --join` confirms the existing secret
under the read-only runtime role; it creates no secret. Copy the signed qualification inputs
with `qualification-import`; run `doctor` as root, then use `enable` only
after all other required checks pass. While disabled, the connection check
correctly fails: keep app ingress isolated, enable, rerun doctor, and only
admit app traffic after the full report passes. `doctor` prints `auths.gateway-readiness/1` and
returns nonzero on any failed check. Development installations always fail
production readiness. Follow the [operations runbook](../../docs/operations/GATEWAY_PRODUCTION_RUNBOOK.md).

## Network and privilege policy

Apply host firewall rules by UID/cgroup before starting the gateway. Permit
the application only its own explicit business endpoints and Unix socket;
deny it provider and AWS credential endpoints. Permit the gateway only DNS
to the host resolver, TCP 443 to the recipe's reviewed provider IP set and
regional Secrets Manager and STS IP sets, and TLS PostgreSQL to its fixed
address/port. Resolve and review endpoint changes before updating the allowlist;
a changed address is an outage until reviewed. Deny metadata/container
credential endpoints because this reference uses web identity. Deny all other
egress. No broad HTTPS proxy or arbitrary destination is permitted. Check the
application UID's denied egress from the host firewall separately: doctor
checks process/socket isolation and pinned transport construction, not an
unconfigured external firewall. A successful readiness report is not proof
that an application lacks an independently obtained provider token.

Enable systemd-timesyncd. Its fixed synchronization marker is the clock trust
input; missing synchronization disables required recipes. Monitor that marker,
not merely a running time service. The optional observer is absent in this
reference, explicitly reported as unavailable for signed outcomes. To add one,
provision the reviewed distinct custody-backed signing identity and restrict
its endpoint; never use a software observer in production.

## Health, limits and alerts

The unit bounds memory, CPU, processes, descriptors and shutdown time. The
process is live while its independently limited app/admin listeners answer;
provider, database and credential outages must not cause a liveness restart
loop. Use status/support-bundle for bounded attempt stage counts and in-flight
counts; export numeric metrics from these reports, never labels derived from
provider bodies or account/resource names. Alert on failed doctor checks,
qualification expiry/revocation-list next_update within 24 hours, untrusted
clock, unknown/attempting backlog, missing slot sweep, incomplete shutdown,
and credential deletion failure. Preserve the last report and stable codes.
A SIGTERM stops listeners, waits up to 25 seconds for admitted sessions, removes
socket paths, and reports incomplete drainage rather than success on timeout.

## Evidence and human trial

The PostgreSQL workflow also runs `tools/exercise-postgres-restore.sh`: it
takes a physical backup, archives WAL, restores to a named point, confirms
pre-target records survive and post-target records do not. This is a disposable
database rehearsal and explicitly makes no replay-continuity claim.

Hosted PostgreSQL and isolation workflows exercise the packaged command's
store, multi-host admin, actual application UID denial and restore-floor
refusal. They use disposable custody and do not establish production workload
identity, firewall or production point-in-time restore operation. Record those live
reference exercises before declaring Epic 4 complete. Use the trial protocol
in the runbook with a person unfamiliar with the implementation; an automated
or simulated onboarding run cannot close that gate.
