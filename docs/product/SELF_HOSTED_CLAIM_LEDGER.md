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

This is **not yet** a production-qualified or non-bypassable product claim.
The separate Unix process and admin/app sockets still require hosted green
tests, a documented distinct-UID deployment in which the app cannot read the
gateway credential or reach the admin socket, egress and hostile-action
evidence, and production-style independent trust. The SDK clients
alone establish none of those deployment facts. An app that retains a
separate provider token can still bypass Auths.

The operator installer parses the supplied trusted-context bytes and refuses
malformed input before creating credential state. This checks structure, not
that the trust was provisioned independently or that a signer has durable
custody. A hosted distinct-UID doctor probe is required to establish only the
local filesystem/socket boundary; it cannot detect a separate app-held token
or prove outbound network isolation.

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
async I/O before the successful fresh run. The repaired revision still needs
hosted CI and hostile deployment evidence.

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
