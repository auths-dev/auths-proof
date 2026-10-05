# Case 0008: provider-secret custody and recipe qualification

## Candidate and owner

Two product-layer mechanisms, reviewed together because AP-SPEC-066 ships them
together and each must stay free of provider meaning.

1. **Provider-secret custody.** The sealed `ConnectionCredentialStore` of
   `auths-connections`: a store that is told a connection identity, a
   credential generation, and a commitment, and leases bounded secret bytes
   for exactly that generation. The candidate adds a closed
   `CredentialStoreKind` and makes the credential generation explicit in the
   sealed `ConnectionBinding`. Owner: `auths-connections`.
2. **Recipe qualification.** A canonical record of what a protected run
   showed about one pinned recipe and provider contract, the release trust
   artifacts that say who may attest to it, and the closed state a gateway
   derives from them. Owner: `auths-recipe-qualification` for types, schemas,
   and bounds; the gateway owns only the gate that reads a verified result.

Neither candidate is request construction (case 0007), a provider adapter, a
status classifier, or signing custody. `auths-custody` keeps Auths root and
observer signing keys; a provider API secret is not a signing key and does not
pass through it.

## Consumers compared

Three recipes exist in this repository or the field lab. The fourth is a
paper comparison only: no recipe, credential, or live call exists for it. It
is here because the first three all inject a bearer token, and the mechanism
must be shown not to depend on that.

| Recipe | Credential the gateway injects | Provider environment for qualification | Provider-side rotation | Effect and evidence deliberately outside shared meaning |
| --- | --- | --- | --- | --- |
| Stripe refund (`POST /v1/refunds`) | Restricted key as `Authorization: Bearer`; a connected account is named by a separate `Stripe-Account` header the recipe binds | Provider test mode, selected by the key itself | The provider can keep the old key valid for a chosen period after rolling | Refund eligibility, the idempotency key's retention, connected-account scope, and whether a refund settles are Stripe semantics |
| Airtable field update (`PATCH` one record) | Personal access token as `Authorization: Bearer`; scopes and base access are properties of the token | No test mode: disposable base in a live account | Tokens are created and revoked independently, so two can be valid at once | Expected-old-value meaning, field typing, and what a later matching read proves |
| Todoist task creation (`POST` one command) | API token as `Authorization: Bearer` | No test mode: disposable project in a live account | A personal token is replaced, not overlapped; the old value stops working when the new one is issued | Command status mapping, temporary-identifier mapping, and delayed visibility of a created task |
| Postmark message send (`POST /email`), paper only | Server token in the `X-Postmark-Server-Token` header, not `Authorization` | A published test token that validates a request without sending | Tokens belong to one server and are replaced by the operator | Delivery, bounce, and suppression are Postmark semantics; a `200` is acceptance, not delivery |

The provider columns record behavior as documented when this case was written.
Each family's decision record must recheck them against the live provider
before any qualification claim; this table is a comparison, not evidence.

## Exact shared contract and exclusions

**Custody, identical in all four.** The credential is opaque bytes of at most
65,536. It is installed only through the operator channel and is never an
argument, an environment variable, or an application input. It is stored under
a connection identity and a credential generation. The shared connection
record carries the generation and a commitment, never the bytes or where they
are kept. A lease is requested only after the claim, names exactly one sealed
generation, has a deadline, and is zeroized when dropped. The store is not told
the provider, recipe, origin, header name, or action. Which header carries the
bytes is the recipe's committed declaration, applied by the gateway after the
lease; the store behaves the same for `Authorization` and for
`X-Postmark-Server-Token`.

**Qualification, identical in all four.** The unit is the tuple of recipe
family, compiled recipe digest, profile-lock digest, provider contract
identifier, gateway semantic-closure digest, and exact target. The provider
contract is a digest of bounded inputs and is opaque to the gateway. The
record lists the same ten evidence members and the same twelve capabilities
for every family; a capability the family lacks is listed as not applicable
with a reason. The record, its attestation, the signer certificate, the
revocation list, and the release index have one canonical form each, one size
limit each, and no provider-specific member.

**Excluded from both.** Provider account discovery; scopes and what a token
may do; test-mode detection (a recipe's credential guard decides that, case
0007); the provider's idempotency rules; whether a provider keeps an old
credential valid; status-to-effect mapping; what a read-back proves about
cause; the pure oracle that judges a family's corpus; and any conclusion about
the provider's business effect. None of these may be supplied by a callback,
a plugin, or a field the store or the qualification types interpret.

## Classification

| Surface | Stripe | Airtable | Todoist | Postmark (paper) | Classification |
| --- | --- | --- | --- | --- | --- |
| Secret bytes, bound, zeroization, redaction | opaque | opaque | opaque | opaque | identical mechanism; existing owner |
| Keying by connection and credential generation | same | same | same | same | identical mechanism |
| Reference commitment in the shared record | same | same | same | same | identical mechanism |
| Lease after claim, exact generation, deadline | same | same | same | same | identical mechanism |
| Injection header | `Authorization` | `Authorization` | `Authorization` | provider header | recipe data; not a store input |
| Credential mode guard | key prefix and probe | none available | none available | test token is a different key | profile semantic; stays in the recipe |
| Old credential valid after rotation | provider option | yes | no | operator choice | domain semantic; the gateway assumes nothing |
| Retention of the old generation in the store | 20 s | 20 s | 20 s | 20 s | identical mechanism; fixed, not per provider |
| Qualification tuple and record shape | same | same | same | same | identical mechanism |
| Provider contract inputs | OpenAPI slice plus assumptions | assumptions only | assumptions only | assumptions only | identical carrier, family-owned content |
| Environment class | provider test mode | disposable live resources | disposable live resources | provider test mode | closed enumeration, family-chosen |
| Corpus, oracle, live cases | refund | field update | task creation | none | domain semantic; test-only, family-owned |
| Capabilities present | most | few | few | few | identical accounting, family-owned reasons |
| Read-back that confirms a live write | refund read | record read | task read | none declared | recipe data; no shared meaning of success |

The retention row is the one place a provider difference might have argued
for a parameter. It does not. The 20 seconds protect an attempt that already
entered transport from losing the secret it leased; they exceed the gateway's
own 15-second transport bound and nothing else. Whether the provider still
accepts the old secret is the provider's answer to that request and is
recorded as such. A per-provider retention would put provider behavior into
the store.

## Versioning and compatibility

`auths.connection-credential-store/1` and `auths.provider-connection/2` are
unchanged on the wire: the record already carried `credential_generation`.
The sealed binding now carries it too, which is an in-process type change with
no persisted form. Qualification artifacts are new schemas at version 1. The
project is prelaunch: a later incompatible change is a new schema identifier
and a direct cutover, with no reader for the old one.

## Invariants and evidence

Each type has one named invariant, stated on the type and listed in
AP-SPEC-066 §4. Executable evidence in this change:

- `auths-connections`: a lease reads exactly the named credential generation
  and searches for no other; a superseded credential never serves a later
  generation; the closed store kind accepts only its two canonical tokens.
- `auths-gateway`: the retirement delay exceeds the transport bound at compile
  time; readiness is the conjunction of every required precondition, over all
  1,536 combinations; a recipe or a submission frame that tries to select
  custody or declare qualification is refused.
- `auths-recipe-qualification`: every artifact decodes only from its canonical
  bytes; 78 structural cases are each refused with a pinned reason; eight
  contract drifts each change the contract identifier.

Fixtures: `bindings/fixtures/qualification/schema-vectors.json` and
`verification-vectors.json`, and `bindings/fixtures/gateway/custody-hostile.json`
and `production-codes.json`. The verification vectors, the adapter vectors,
the rotation and crash scenarios, and the redaction canaries are pending: no
release verifier, production adapter, or support bundle exists, and a test
asserts that shortfall.

No formal claim is added. The translated lease leaf in
`auths-connections::kernel` is unchanged and still decides which stored
generation a lease may use.

## Cutover

Direct. The sealed binding gains a field and both in-repository stores read
it; no state is converted because the binding is never persisted. No
compatibility reader, dual path, or runtime switch is added. The local file
store stays as the development kind and will be refused under production
policy by the custody epic.

## Performance

Custody: a lease is one exact-key lookup and one constant-time comparison, as
before. Qualification: decoding is bounded by the size limits (at most
128 KiB for the release index); signature verification happens once per input
digest and is the verifier epic's cost to measure, not this change's.

## Why smaller primitives are insufficient

Custody already is the smaller primitive: bytes, a generation, a commitment.
What this case adds is the explicit generation, because a store that searches
for "the newest generation not after this one" cannot be implemented by a
secret manager that must read one exact immutable version without listing.

Qualification cannot be a per-family document. The gateway must compare a
connection against an attestation without knowing the family, and
`stable_launch_ready` must count families without reading their meaning. That
needs one record shape. It does not need one oracle, one corpus, or one
meaning of success, and none is shared.

## What remains recipe- and family-owned

The injection header and credential guard; the provider contract's content;
the family identifier and its decision record; the corpus, the pure oracle,
and the live cases; the reason a capability does not apply; the read-back that
confirms a write; expiry cadence and revocation triggers; and every statement
about what the provider did.
