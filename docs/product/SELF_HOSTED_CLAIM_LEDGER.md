# Self-hosted claim ledger

This ledger applies to application-owned MCP integrations, including the
Airtable and Todoist field-lab demos. It is not a provider qualification.

| Stage | What the evidence establishes | What it does not establish |
| --- | --- | --- |
| Native verification and command projection | The supplied proof authorizes the exact canonical action under the supplied trusted context; projected fields come from those verified bytes. | That the operator provisioned the context independently, that an application enforced the result everywhere, or that a provider effect occurred. |
| Atomic attempt claim | The configured store reserved that commitment and operation key within its documented deployment scope. | Global exactly-once effects, provider idempotency, or multi-host safety from the local file store. |
| Provider response classification | The application adapter says the provider accepted, definitely rejected, or may have applied the request. | An Auths-qualified execution result or a signed provider receipt. |
| Read-only observation | The application adapter reports a provider state it observed using its own method. | That an unobserved effect did not occur, or that the observation method is independently qualified. |

Here, **authorized** means a valid proof for the exact canonical action under
the supplied trust. Grant-level restriction of a closed-enumeration variant is
AP-SPEC-025 scope and is not wired into this self-hosted path today; the
proposed gateway must not assume that policy check already exists.

The field-lab demos use an ephemeral self-trusting testkit signer/context and
app-held API tokens. Their successful live read-backs show that the plumbing
works against those providers; they do not demonstrate production authority
provisioning, non-bypassable enforcement, or qualified provider behavior.
Applications that hold their own token can bypass the SDK gate. A separate
credential-owning gateway is needed for a stronger enforcement claim.

## Developer gateway claim boundary (AP-SPEC-053, in progress)

The new local gateway client surfaces accept proof and canonical action bytes
only. The Rust gateway compiles an operator-approved request recipe, reuses
native sealed verification and connection/credential stores, claims a logical
operation once, and distinguishes `not-entered`, `unknown`,
`response-recorded`, and optional `observed` read-back. A complete HTTP
response is not provider-effect confirmation; even matching read-back is not
exclusive causation. The first file claim store is single-host only.

This is **not** a production-qualified or universal non-bypassability claim.
Relative to the one credential bound to the exercised Docker deployment, the
distinct application UID cannot read or use that credential except by
submitting proof/action bytes to the gateway's restricted socket. The trusted
host operator and Docker daemon can change the deployment, and an app that
retains another provider token can still bypass Auths. The exercised trust is
development testkit trust, the provider is synthetic, and the attempt store is
single-host; none of those facts establish production custody, provider
semantics, multi-host exclusion, or provider effect.

The operator installer parses the supplied trusted-context bytes and refuses
malformed input before creating credential state. This checks structure, not
that the trust was provisioned independently or that a signer has durable
custody. The distinct-UID doctor establishes only the tested local
filesystem/socket boundary; it cannot detect a separate app-held token.

Field-lab commit `fbbeb58` records the
[`auths.gateway-hostile-suite-evidence/1`](https://github.com/auths-dev/auths-field-lab/blob/fbbeb58/prototypes/gateway-isolation/evidence/hostile-suite.json)
run against auths-proof `90973d64`. The app ran as UID 10002 with no network,
credential environment, gateway-state mount, admin socket, or Docker socket;
the gateway ran as UID 10001 on an internal network whose only provider was a
TLS counting service under UID 10003. A synthetic credential was installed
only in gateway state. Forged proof, altered action, direct provider access,
a competing gateway, replay, a fresh valid challenge for the same logical
operation, a two-request race, and retry after crash/restart produced three
deliberately authorized entries and **zero additional unauthorized provider
entries**. The fresh-challenge case used a test-only operator context rotation
while retaining recipe, credential, claim state, and logical operation ID; it
is replay evidence, not a public trust-rotation API.

On 2026-09-22, the developer-owned Airtable and Todoist gateway recipes made
live calls through the field-lab `run-demo.sh` gateway mode using the packaged
Python wheel. Airtable returned `observed` with a matching separate GET of
the disposable record. Todoist returned `response-recorded` (HTTP 200), then
a separate operator read found the created task. Provider dashboard links are
shared privately with the operator, not retained in this public ledger.
These runs used disposable self-trusting testkit authority and same-UID local
processes. They establish the request piping and observed provider state,
not independent production trust, credential unreadability by a distinct app
identity, provider-qualified effects, or exclusive causation. An earlier
same-run Airtable submission exposed a blocking-client runtime panic before
any durable claim or provider write; the transport was changed to bounded
async I/O before the successful fresh run.

Field-lab commit `afa733b` adds the redacted
[`auths.gateway-isolated-live-provider-evidence/1`](https://github.com/auths-dev/auths-field-lab/blob/afa733b/prototypes/gateway-isolation/evidence/live-provider-isolated.json)
record. Fresh Airtable and Todoist actions then ran through `--mode isolated`
under app UID 10002 after both the gateway doctor and network probe passed.
The trusted host operator parsed each ignored token file and piped the value
only to gateway-install stdin; it was not an app mount, environment value, or
command argument. Airtable returned `observed` with HTTP 200 and matching
read-back for `DemoStatus=Pending`. Todoist returned `response-recorded` with
HTTP 200, followed by an independent read-only observation of the created
task. Dashboard links were returned privately to the operator and are not
retained in the public ledger. The initial Airtable app process failed on a
container-relative source-path assumption before connecting to the gateway;
field-lab `8652573` fixed both demo imports, 15 Airtable tests and 13 Todoist
tests passed, and the unchanged one-use action was then submitted once.

Auths-proof `90973d64` passed
[exact-tip hosted CI](https://github.com/auths-dev/auths-proof/actions/runs/35690791146).
The live image used docs-only descendant `0c066abf`; its gateway implementation
is unchanged from `90973d64`. These runs establish the tested credential and
network boundary plus observed provider state. They still do not establish
production signing/trust custody, provider-qualified effects, exclusive
causation, multi-host claims, or protection from a separate app-held token.

## Commitment-bound provider evidence (AP-SPEC-059, repository-local only)

The gateway can now write an echo token into one recipe-declared provider
field and report `observed-by-provider`. The token is
`auths-e1-` followed by the lowercase hex SHA-256 of
`auths.gateway-echo/1`, NUL, the namespace, NUL, the logical operation ID,
NUL, and the verified action commitment stored in the attempt record. The
application never supplies it. The Airtable fixture recipe declares
`/fields/auths_echo`; Todoist and GitHub do not.

**Claim.** When the gateway reports `observed-by-provider`, the provider
returned, over the pinned TLS origin and under the gateway-held credential,
a record whose echo field equals the token for this namespace, logical
operation, and action commitment. The link to the authorization is only as
strong as the premise that no other party with write access to that
provider field wrote the same token.

**Not a claim.** The token is not a signature: anyone who knows the
namespace, operation ID, and commitment can compute it, and the application
knows all three, so an application that keeps another provider credential
can forge the link (the same alternate-credential premise as the gateway
section above). The TLS read-back cannot be shown to others; what is new is
that the account owner or an auditor can re-read the provider record with
their own access and find the token without trusting the gateway's store.
Not finding the token never proves that the write did not happen. Provider
business meaning stays unqualified.

Current evidence is repository-local unit tests against a synthetic
counting provider and the file attempt store: a normal write, a timeout
after delivery resolved by a later read-only observation, a provider-side
overwrite recorded as `echo-mismatch`, and replay or fresh challenges that
make no second provider entry. **The live Airtable run has not been done**,
no hosted CI result is cited here, and no document may yet describe gateway
outcomes as bound to real provider records. An `unknown` Todoist create
stays unresolved (it is `response-recorded` or `observed` at best) until
the recipe language has typed query segments. A crashed `attempting` record
is not re-observed, because it cannot be told apart from an in-flight
attempt.

## Gateway-observed preconditions (AP-SPEC-060, repository-local only)

The gateway can now hold an observer signing key and sign two kinds of
observation for the application to attach to its next action:
`auths.gateway-readback/1` (the value the gateway read from the recipe's
observed field, and the echo field when present) and
`auths.gateway-outcome/1` (the stored commitment and stage of one logical
operation). A grant's observation requirement can then require, for example,
that the record held the action's `expected` value, or that step N−1 is
`observed-by-provider`, before the verifier authorizes step N. The gateway
verifies at its own clock and exposes top-level verified MCP arguments as
action facts through the `mcp-arguments-v1` profile policy, which the trusted
context selects and whose configuration it pins.

**Claim.** When the gateway authorizes an action under such a grant, an
observer the operator trusted for that subject signed facts that satisfied
every condition, at an `observed_at` no earlier than the gateway's evaluation
time minus the requirement's maximum age. A requirement that is stale,
unmet, or has no observation is refused before any durable claim, credential
lease, or provider entry. For a read-back requirement whose subject is the
recipe's declared read-back subject argument, the gateway also refuses an
action whose written record is not the observed record.

**Not a claim.**

- The fact held when the provider applied the write. The record can change
  between the observation and the write; a short maximum age narrows that
  window and does not close it. Closing it needs a conditional provider write,
  which the recipe language does not have.
- The observer told the truth. The observer key is operator custody (a
  software seed in the gateway's private state directory), so observer trust
  is operator trust, exactly as for the credential. The key is not
  hardware-protected.
- A missing or differing observation means the fact is false. Missing
  observations are indeterminate. A signed outcome of another stage denies
  that action; the logical operation stays unclaimed.
- Read-back confidentiality. The application can ask for a signed read-back of
  any record the recipe's observation path admits, and so learns that field's
  value. The operator opts in by provisioning the observer key.
- Arguments a grant does not constrain. The recipe's verified-only arguments
  are compared only by observation requirements; a grant without one leaves
  them unchecked.

Current evidence is repository-local unit tests with signed grants and actions,
native verification, and a synthetic counting provider: a fresh matching
read-back authorizes the write; stale by one second, a changed value, or a
missing observation is refused with zero writes and no write-path lease; a
read-back of another record cannot license the write; a record replaced after
observation is still authorized (the non-claim above); step N is indeterminate
with no outcome observation, denied while step N−1 is `unknown`, and
authorized once step N−1 is `observed-by-provider`; an agent-signed or forged
observation never satisfies; and an observer that is also in the authority
chain is refused. **The live Airtable run has not been done**, no hosted CI
result is cited here, and no document may yet describe gateway grants as
conditioned on observed provider state. The Python and TypeScript gateway
clients do not yet expose the observation request.

## Packaged clean-consumer exercise

Exercised at auths-proof commit
`3aeb18ecf4a7ef954858f5023a44dda9210fa473` in hosted CI:

| Package | Exercise and result | Limit |
| --- | --- | --- |
| Installed Python wheel | The [external consumer](../../bindings/python/external/self_hosted_profile_consumer.py) generated and checked an exact profile, then used separately supplied signed-grant and trusted-context fixture bytes with an external Ed25519 signing adapter. Native verification denied a wrong tool before credential access; a synthetic provider write occurred once, replay was blocked, and an ambiguous second write became `unknown` before read-only reconciliation. The [Ubuntu installed-wheel job](https://github.com/auths-dev/auths-proof/actions/runs/35549196730/job/106181316749) passed with `FileAttemptStore`; Windows uses a memory store. | The signing seed and trust fixture are public CI vectors; the signer reports ephemeral custody. Neither production key custody nor independent operator trust provenance is established. The provider is synthetic, and the Windows store is not durable. |
| Installed npm tarball | The [packed-package consumer](../../bindings/typescript/test/package/packed-profile-cli.test.js) generated and type-checked an exact contract and, using the installed runtime, signed under separately supplied grant/trust fixtures. It checked denial before credentials, one synthetic write, replay blocking, and unknown-result read-only reconciliation. The [Node 20/22 matrix](https://github.com/auths-dev/auths-proof/actions/runs/35549196796) passed on macOS, Linux, and Windows. | The key/trust fixtures are public CI vectors and the attempt store is in memory. This is not production custody, durable multi-host recovery, live provider qualification, or a non-bypassable boundary. |

The package exercises establish a reproducible SDK path, not that an
application-owned token cannot be used outside `run_once`/`runOnce`.

The later exact SDK revision `0266fdc` passed [authoritative/formal CI](https://github.com/auths-dev/auths-proof/actions/runs/35663793124),
the [Python package](https://github.com/auths-dev/auths-proof/actions/runs/35663793077),
the [TypeScript package](https://github.com/auths-dev/auths-proof/actions/runs/35663793306),
and [installed-artifact recipes](https://github.com/auths-dev/auths-proof/actions/runs/35663793107).
Field-lab commit `92ac30d` pins that SDK revision; the Airtable and Todoist
demos passed local tests against its installed hosted wheel and previously
completed live write/read-back. Their hosted jobs did not start because of a
billing annotation in `auths-field-lab`. The owner directed that those jobs
not be pursued for PR #123's engineering handoff. This is not a claim that
the field-lab hosted workflows passed, nor a substitute for the distinct
AP-SPEC-057 Epic 1 hosted acceptance gate.

## Commit-title correction

Commit `9b31882` added conformance tooling and associated repository evidence;
it did **not** complete an independent unfamiliar-user trial. Its title predates
and violates the evidence-in-the-diff rule now recorded in AP-SPEC-057 §2. The
pushed commit is preserved rather than rewritten, and this forward correction
is the authoritative interpretation of that title. The later
[third-adapter engineering trial](SELF_HOSTED_THIRD_ADAPTER_TRIAL.md) is separate
evidence, not retroactive evidence in `9b31882` and not a human adoption test.

## Independent third-adapter engineering trial

A separate zero-context agent built an inventory status adapter from a packaged
Python wheel and reran it from a clean consumer workspace after SDK fixes.
The [redacted report](SELF_HOSTED_THIRD_ADAPTER_TRIAL.md) records the exact
action, disposable proof, projected command, one-use claim, adapter-classified
provider response, local HTTP read-back, denial, and replay separately. It
satisfies AP-SPEC-054 Epic 5's engineering clean-room criterion, not a market
adoption claim. The credential and provider mapping were application-owned;
the fake provider did not independently qualify those semantics.
