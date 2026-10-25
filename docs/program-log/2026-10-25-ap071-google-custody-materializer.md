# AP-071 development Google custody materializer

The gateway's provider-neutral `CredentialMaterializer` port now has a
development Google vertical in the gateway binary. A write installation or
separate read connection can store a versioned opaque source reference through
`--credential-source-stdin`; the ordinary bearer path refuses that marker if
no adapter is installed. The operator then installs one private canonical
materializer configuration for the exact connection IDs and reviewed recipe
digests. No agent action or recipe chooses the adapter or a grant path.

After a native task reservation, the adapter compares the stored reference and
connection generation to its pins, rechecks the exact demo_co producer
generation, reads the owner-private Jules grant, requires the original Desktop
client file and exact `openid`, `userinfo.email`, `drive.file` scopes, refreshes an
access token in memory, and checks Google's live UserInfo subject, verified
email and hosted domain. It returns a short-lived bearer to gateway custody;
the gateway alone executes the reviewed provider GET or write. Refusal leaves
the operation conservatively charged and sends no source reference or bearer
to the provider.

Synthetic evidence on 25 October 2026:

- Google adapter tests passed a refresh and UserInfo match, and refused a
  changed source, recipe, operation kind, saved-grant scope, returned scope,
  OAuth client secret, UserInfo subject and unsafe grant-file mode.
- A gateway test refused ordinary leasing of an opaque source reference when
  no materializer was installed.
- The new CLI installed separate source-reference write and read connections
  in an owner-private disposable state and loaded the private materializer
  configuration during task setup. No provider request occurred in this setup.

This is development and synthetic evidence. The installed Jules task runs
recorded earlier used a short-lived bearer installed before activation. A new
human-signed task, actual post-reservation refresh, provider effect and
independent demo_co readback are still needed for live renewal evidence.
Production multi-host custody and qualification are separate acceptance work.

The first source-backed installed read attempt used a fresh Jules-signed task
and a separate agent-signed action. Native admission charged one provider-call
allowance, but materialization refused before a Google GET or content release;
the task ledger recorded `release-refused`, zero releases and zero bytes. The
saved demo_co authorized-user file leaves its optional `account` field empty,
while the first adapter revision required an email there. The adapter now
accepts an empty saved field only if the pinned grant/client/scope checks pass
and Google's fresh UserInfo supplies the exact Jules subject, verified email
and hosted domain. Synthetic tests cover that actual file shape and reject a
conflicting nonempty account. The spent read cannot be retried under that task;
an installed live refresh remains to be rerun with a fresh signed task.

The development installer now checks the private producer evidence, saved
grant, original Desktop client and scope set before committing its immutable
materializer configuration. Runtime materialization repeats those local checks
after admission and still requires a fresh Google refresh and UserInfo match.
This catches malformed or mismatched local inputs before asking Jules to sign
another task; it does not prove that a future network refresh will succeed.

The development-only `task-materializer-probe --state-dir` command now makes
one OAuth refresh and UserInfo check for every installed pinned connection,
discards each token, and reports only the number of ready connections. It
does not admit an agent action, release document content or prove a later
provider read/write. It lets the operator check the live identity path before
another short-lived human signing ceremony; the task path still rechecks it.

The first live readiness probe used gateway binary SHA-256
`f17084b2796ba7deee148814054f1b3f50beeb8af5ab4e401359fe8ee50460a7`
against the existing owner-private Jules read and write installation. It
returned `materializer-probe-ready` with `count: 2`: both pinned grants
refreshed and matched Google's live UserInfo. No task action, Drive request,
document release or write was attempted by this command. demo_co separately
confirmed that the pinned Project A source remained a 51-byte unchanged
export; this is a source baseline, not evidence of the later agent read.

The earlier failed source-backed task `5Ll2BBfr_ZlCEvfbASOUq3iS` still held
one unused write slot after its read allowance was spent. The operator
revoked it; the redacted task status now reports `revoked=true`, the original
`release-refused` read, one charged call allowance, zero releases, zero bytes
and zero writes. No Google provider request was made during that read or this
revocation.
