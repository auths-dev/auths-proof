# ADR 0017: Closed, credential-isolated content release to a delegated agent

**Status:** Proposed for AP-SPEC-071. An internal executor and synthetic
provider-to-agent test exist; no installed managed release or qualification
claim is approved by this draft.

**Date:** 25 October 2026

## Context

The gateway's current GETs check credentials, inspect pre-entry state, or
observe a write. Their responses stay inside the credential-owning process;
they do not authorize releasing private content to an agent. AP-SPEC-070 has
an application-owned Google read broker that proves a bounded vertical, but
it is not a reusable managed read boundary. AP-SPEC-071 needs that boundary
for the same human task to read from Google and another service without a new
delegation protocol. [Case 0009](../research/domains/abstraction-cases/0009-agent-content-release.md)
compares Google Drive export with an Airtable record GET. The comparison is
mechanical: the meaning of each source and its permission model remain with
the provider vertical.

## Proposed decision

Add a **separate closed release recipe type and application operation** to
the credential-isolated product gateway. Do not reinterpret a write recipe's
observation GET as a content release or add a provider-name switch. The
operator pins a versioned recipe digest, connection and subject generation,
origin, GET path and fixed query, typed resource fields, accepted response
status and media type, bounded extraction, maximum provider/released bytes,
recipient channel and budgets. The application submits only the native proof
and canonical action. No application-selected URL, arbitrary selector,
credential, header, body or release recipient reaches the runtime.

The first extraction grammar needs two response forms: complete bounded
`text/plain` bytes for the Google Drive export, and one bounded JSON scalar
at a fixed pointer for Airtable. The compiler rejects every other form. A
future need for traversal, pagination or a different media type is a new
reviewed capability, not permissive callback code. One request produces at
most one recipient-bound release. Existing write recipe source `/2` remains
write-only; the release source has its own schema and review output. Both may
share custody and typed leaf mechanisms only after their contracts are shown
identical.

The runtime spends a provider-call allowance before request entry. It
releases nothing from an incomplete, oversized, redirected, wrong-type or
otherwise unavailable response. After projection and before agent-channel
entry, one durable operation claim atomically records `release-entered` and
charges the projected bytes and one release. The same operation ID cannot
enter delivery twice. A complete authenticated agent acknowledgement records
`agent-acknowledged`; missing acknowledgement after possible entry records
`delivery-unknown` with budgets spent. Durable proof that no transport began
may record `not-delivered`, without refund. These stages are separate from
write attempt stages and never claim that the agent used or understood the
content.

Receipt evidence contains a task/resource/operation-domain-separated keyed
content commitment, byte counts, key version and transport state. No public
raw content hash is emitted; short fields such as Airtable `DemoStatus` must
not be dictionary-recoverable from a receipt. A private verifier may compare
actual bytes and export only a verdict. The receipt key stays in custody and
old retained receipts remain verifiable after rotation under a documented
key-retention rule.

## Ownership and limits

- Existing native `auths.mcp/v2` verification owns exact authority; this ADR
  proposes no new offline verifier or generic action format.
- The product gateway owns compiled release recipes, credential custody,
  bounded request/response mechanics, operation claims, budgets and delivery
  stages. It interprets no provider field beyond the typed extraction rule.
- A read connection has its own recipe descriptor, subject and credential
  generation, and its own qualification gate. A write recipe's attestation
  cannot qualify a different read digest. Installation must bind the gate to
  the exact read tuple before any lease; a development optional gate is only
  synthetic evidence.
- The Google and Airtable vertical references own provider account meaning,
  permission probes, content semantics, freshness and independent checks.
- The task UI owns human-readable names and approval presentation, never
  credential access or runtime recipe mutation.
- A provider's refusal stays a provider refusal after Auths task admission;
  a 2xx response alone does not prove the agent received content.
- Release through a self-hosted, application-owned adapter remains possible
  under AP-SPEC-051, but it is not this managed custody claim.

The Atlas producer's protected Jules grant can refresh a bearer on demand.
Auths may bind distinct read and write connection records to the same Google
subject and Desktop OAuth client, but the current generic credential store
leases the exact installed secret generation. A freshly refreshed access
token is not that stored secret. The installed design therefore needs a
reviewed custody lease port that matches a stable, protected grant reference
and connection generation before returning a short-lived bearer to gateway
transport. Its implementation must keep refresh material outside the agent,
task, ordinary command arguments and receipts. A one-time installed access
token is only a development shim with an explicit expiry, not renewal or a
general managed-read claim. This ADR does not approve provider-specific token
refresh code inside the data-only gateway.

## Evidence before acceptance

The new AST and compiler need canonical and hostile fixtures for origin,
method, path, query, recipient, connection generation, media type, selector,
byte bounds and digest substitution. The installed engine needs denial before
credential use, concurrent claim races, response truncation, transport and
acknowledgement loss, restart at each stage, replay refusal, key rotation,
and zero agent-visible bytes on pre-release refusal. Google and Airtable must
use the same interpreter and receipt contract, with their test-only verticals
as independent oracles. Hosted CI and installed-provider evidence are needed
before this ADR can become accepted or the mechanism can be called general.

## Rejected shapes

1. Expose an existing observation GET result to the agent: its current AST
   has no release recipient, content or budget contract.
2. Put the Google broker in the production gateway: that adds provider
   semantics and provider code to the credential-owning process.
3. Accept a runtime URL or projection from the agent: the task proof would
   no longer fix which private content is released.
4. Report plain content digests in public receipts: low-entropy values can be
   guessed offline.
5. Refund budget or resend automatically when acknowledgement is lost: bytes
   may already have reached the agent.
