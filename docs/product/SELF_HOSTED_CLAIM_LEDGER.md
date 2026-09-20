# Self-hosted claim ledger

This ledger applies to application-owned MCP integrations, including the
Airtable and Todoist field-lab demos. It is not a provider qualification.

| Stage | What the evidence establishes | What it does not establish |
| --- | --- | --- |
| Native verification and command projection | The supplied proof authorizes the exact canonical action under the supplied trusted context; projected fields come from those verified bytes. | That the operator provisioned the context independently, that an application enforced the result everywhere, or that a provider effect occurred. |
| Atomic attempt claim | The configured store reserved that commitment and operation key within its documented deployment scope. | Global exactly-once effects, provider idempotency, or multi-host safety from the local file store. |
| Provider response classification | The application adapter says the provider accepted, definitely rejected, or may have applied the request. | An Auths-qualified execution result or a signed provider receipt. |
| Read-only observation | The application adapter reports a provider state it observed using its own method. | That an unobserved effect did not occur, or that the observation method is independently qualified. |

The field-lab demos use an ephemeral self-trusting testkit signer/context and
app-held API tokens. Their successful live read-backs show that the plumbing
works against those providers; they do not demonstrate production authority
provisioning, non-bypassable enforcement, or qualified provider behavior.
Applications that hold their own token can bypass the SDK gate. A separate
credential-owning gateway is needed for a stronger enforcement claim.
