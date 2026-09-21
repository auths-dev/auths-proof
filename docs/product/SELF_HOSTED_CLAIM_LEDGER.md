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

## Packaged clean-consumer exercise

Exercised at auths-proof commit
`3aeb18ecf4a7ef954858f5023a44dda9210fa473` in hosted CI:

| Package | Exercise and result | Limit |
| --- | --- | --- |
| Installed Python wheel | The [external consumer](../../bindings/python/external/self_hosted_profile_consumer.py) generated and checked an exact profile, then used separately supplied signed-grant and trusted-context fixture bytes with an external Ed25519 signing adapter. Native verification denied a wrong tool before credential access; a synthetic provider write occurred once, replay was blocked, and an ambiguous second write became `unknown` before read-only reconciliation. The [Ubuntu installed-wheel job](https://github.com/auths-dev/auths-proof/actions/runs/35549196730/job/106181316749) passed with `FileAttemptStore`; Windows uses a memory store. | The signing seed and trust fixture are public CI vectors; the signer reports ephemeral custody. Neither production key custody nor independent operator trust provenance is established. The provider is synthetic, and the Windows store is not durable. |
| Installed npm tarball | The [packed-package consumer](../../bindings/typescript/test/package/packed-profile-cli.test.js) generated and type-checked an exact contract and, using the installed runtime, signed under separately supplied grant/trust fixtures. It checked denial before credentials, one synthetic write, replay blocking, and unknown-result read-only reconciliation. The [Node 20/22 matrix](https://github.com/auths-dev/auths-proof/actions/runs/35549196796) passed on macOS, Linux, and Windows. | The key/trust fixtures are public CI vectors and the attempt store is in memory. This is not production custody, durable multi-host recovery, live provider qualification, or a non-bypassable boundary. |

The package exercises establish a reproducible SDK path, not that an
application-owned token cannot be used outside `run_once`/`runOnce`.
