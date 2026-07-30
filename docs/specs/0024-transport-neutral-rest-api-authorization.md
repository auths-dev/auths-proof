# 0024: Transport-neutral REST API authorization without reusable client API keys

Status: Proposed  
Exact action profiles: `auths.demo.records.create/1`,
`auths.demo.records.read/1`  
Policy family: `auths.demo.bounded-record-api-policy/1`  
Product package: `product/integrations/auths-records-api`  
Demo: `demos/rest-api-authorization`  
Tracking issue: [#22](https://github.com/auths-dev/auths-proof/issues/22)

## 1. Decision

Build a concrete records API vertical demonstrating that an untrusted agent or
client can make authenticated `POST` and `GET` requests without receiving a
reusable API key, OAuth bearer token, session cookie, database credential, or
other downstream secret.

The caller presents an Auths proof plus a request presentation. The protected
API independently verifies that evidence against a typed canonical product
action, trusted context, required and executed configuration, and durable
bounded state before reading protected data or performing a mutation.

HTTP is one delivery and enforcement adapter. It does not define the authority
algebra. The semantic action is `CreateRecord` or `ReadRecord`, not an
arbitrary HTTP request.

## 2. Product claim

The precise claim is:

> No reusable API credential is placed in the agent. Each call carries
> independently verifiable, bounded authority for what it is actually trying
> to do.

This is not anonymous access and does not claim that credentials disappear
from every trusted component. An Auths proof is authorization evidence. It may
be short-lived, action-bound, audience-bound, presenter-bound, attenuated, and
replay-controlled. Any database or downstream credential remains confined to
the protected executor.

The verifier does not call an issuer, identity database, OAuth server, or
hosted policy service for every request. Issuance and verification are
separate. Once issued, a proof can be carried over any supported exchange and
verified locally from explicit trusted inputs.

## 3. Goals

The vertical must:

1. expose real protected `POST` and `GET` operations through a public REST API;
2. require no reusable API key, bearer token, or session cookie from the
   caller;
3. support both one exact action and a bounded family of future actions;
4. bind each request to a typed canonical product action;
5. bind proof presentation to the intended presenter, audience, challenge,
   action digest, and request lifetime;
6. deny before protected reads, mutation credentials, or writes;
7. enforce aggregate limits atomically under concurrency;
8. make exact mutation replay incapable of producing a second effect;
9. treat data disclosure as a bounded effect;
10. distinguish authorization, execution, and observation receipts;
11. expose required and executed verifier configuration;
12. prove that HTTPS carries authority evidence but cannot create or upgrade
    authority; and
13. provide a complete Docker-local and public browser demonstration with
    copyable `curl` requests.

## 4. Non-goals

V1 does not:

- provide anonymous or credential-free authorization;
- replace TLS, origin security, availability controls, or traffic protection;
- authorize arbitrary URLs, methods, headers, query strings, or bodies;
- accept a raw policy language or OpenAPI document from the caller;
- turn reverse-proxy identity or successful TLS into authorization;
- expose a generic API gateway or universal HTTP middleware;
- standardize a permanent Auths HTTP header format;
- allow unrestricted record search, listing, filtering, or pagination;
- support arbitrary JSON record values;
- expose another visitor's records;
- place HTTP routing, mutable replay state, or product policy in `core/`;
- treat a successful HTTP response as proof that an external effect was
  observed; or
- infer that every REST integration has the same evidence, state, or receipt
  semantics.

Future `auths-http` and OpenAPI tooling may be designed from this vertical, but
they are not implementation prerequisites and must not be extracted
prematurely.

## 5. Architectural boundary

The required path is:

```text
untrusted HTTP bytes
  -> bounded route-specific decoder
  -> typed records-domain action
  -> canonical action bytes and digest
  -> Auths proof and presentation verification
  -> records policy evaluation
  -> durable claim or disclosure reservation
  -> profile-specific verified command
  -> protected records store
  -> observation and receipts
```

The prohibited path is:

```text
GenericHttpAction {
  method,
  arbitrary_url,
  arbitrary_headers,
  arbitrary_query,
  arbitrary_json
}
  -> generic executor
```

The records package owns:

- record identifiers and values;
- create and read actions;
- exact and bounded records policy;
- protected records evidence;
- action evaluators;
- mutation and disclosure state transitions;
- verified commands;
- records-store port;
- receipt meanings and stable codes; and
- route-to-action mapping for this API.

The demo owns HTTP serving, browser sessions, public experiment selection,
deployment, and presentation.

Core continues to own portable proof, canonical action, attenuation,
composition, and three-valued verification semantics. Exchange packages may
carry opaque proof bytes. Neither HTTP nor the records package may redefine
core verification.

## 6. Trust and credential boundaries

### Untrusted

- browser and `curl` request bytes;
- session handles;
- proof and presentation bytes;
- methods, paths, query parameters, headers, and bodies;
- record identifiers and values;
- caller timestamps;
- experiment selection; and
- all network and proxy metadata not explicitly supplied by trusted
  configuration.

### Trusted context

- issuer trust roots;
- configured API audience and external origin;
- executed profile and canonicalization versions;
- server time;
- server-issued challenge;
- protected namespace ownership;
- route identity after trusted routing;
- records-store identity and schema;
- durable claim, replay, and aggregate state; and
- receipt-store identity.

### Credentials

The public client receives no API key, OAuth access token, session cookie,
database password, or provider credential.

If the records store requires a credential, only the native executor may
acquire it, and only after proof verification, configuration equality, a
durable decision, and the applicable exact claim or disclosure reservation.
The credential interface is specific to the records store and cannot be
serialized, logged, or exposed through receipts.

The public demo issuer owns a signing key logically separate from the
verifier. Co-locating issuer and verifier processes for an economical demo
does not permit verifier code to call the issuer during request verification.
Production guidance must describe separate custody and deployment.

## 7. Principal and presentation model

Each browser session creates or supplies an ephemeral presenter key. The demo
issuer binds the granted authority to that presenter and to one isolated
namespace.

Every protected request includes:

- the Auths proof;
- a versioned presentation;
- the server challenge;
- the presenter public-key identity;
- a signature over the presentation input; and
- the typed action payload or route parameters needed to derive the action.

The presentation input commits to:

```text
presentation_version
proof_digest
presenter_principal
api_audience
application_route_id
canonical_action_digest
challenge
created_at
expires_at
presentation_nonce
```

HTTP method, route, query, and body are not independently granted authority.
The trusted adapter derives the application route and typed action, then
requires their commitments to match the presentation.

An HTTP adapter may carry the presentation through versioned Auths headers or
HTTP Message Signatures. The semantic presentation above remains independent
of that carrier. V1 does not declare a permanent Internet-wide header
standard.

For copyable `curl`, the browser generates a complete, short-lived,
single-action presentation. Copying the command does not expose the
presenter's private key or a reusable general capability. The corresponding
action is still protected by claim/replay state.

## 8. Exact create action

`CreateRecordV1` commits to:

```text
profile = "auths.demo.records.create/1"
namespace_id
record_id
value
value_encoding = "utf8-text/1"
expected_absent = true
policy_digest
required_evaluator
required_configuration_digest
api_audience
expires_at
nonce
```

V1 values are UTF-8 strings with an explicit byte ceiling. Record and
namespace identifiers use closed ASCII grammars and hard length limits.
Unknown fields, duplicate JSON members, invalid encodings, and identifiers
outside the grammar are malformed.

The verified command is constructed only from canonical action bytes. The
executor never writes an unverified body that merely resembles the verified
action.

## 9. Exact read action

`ReadRecordV1` commits to:

```text
profile = "auths.demo.records.read/1"
namespace_id
record_id
allowed_fields[]
maximum_response_bytes
expected_record_version
policy_digest
required_evaluator
required_configuration_digest
api_audience
expires_at
nonce
```

V1 fields are selected from a closed set:

- `record_id`;
- `value`;
- `created_at`;
- `updated_at`; and
- `version`.

Fields are unique and canonically sorted. A read does not authorize listing,
searching, reading adjacent records, following references, increasing the
response ceiling, or returning internal receipt and namespace metadata.

Protected record contents must not be loaded into an externally observable
response path before authorization. After authorization, the executor reads
the exact record and constructs only the allowed projection. If canonical
response bytes exceed `maximum_response_bytes`, nothing is disclosed.

## 10. Bounded records policy

`BoundedRecordApiPolicyV1` contains:

```text
policy_type = "auths.demo.bounded-record-api-policy"
policy_version = 1
policy_id
namespace_id
presenter_principal
allowed_operations[]
allowed_record_ids[]
allowed_record_id_prefixes[]
maximum_value_bytes
maximum_response_bytes
allowed_read_fields[]
maximum_creates
maximum_reads
fixed_and_rolling_budgets[]
valid_from
expires_at
maximum_action_lifetime_seconds
maximum_presentation_lifetime_seconds
maximum_evidence_age_seconds
api_audience
```

The exact mode uses a policy narrowed to one operation, record, and value
commitment. The bounded mode may permit, for example:

> create at most three records in namespace `visitor-abc`, with identifiers
> under `demo-`, values no larger than 1 KiB, during the next ten minutes.

The agent chooses the concrete records after issuance. Each eligible action
reserves one create unit before execution. Concurrent requests for the final
unit must result in exactly one reservation.

A bounded read policy may authorize a finite number of reads over an explicit
record allowlist or prefix and a closed field set. It never implies arbitrary
query or discovery authority.

Policy attenuation may remove operations, records, fields, time, bytes, and
budget. It cannot add scope or replenish consumed capacity.

## 11. Evidence and evaluator configuration

Protected evaluation inputs include:

- namespace identity and presenter binding;
- action-specific policy and proof commitments;
- current aggregate create and read usage;
- active reservations and unknown outcomes;
- exact-record existence or version metadata where required;
- server challenge identity and lifetime;
- API audience;
- records-store and receipt-store configuration commitments;
- observation time; and
- evidence source and freshness.

The required and executed configuration is:

```text
RecordsApiVerifierConfigurationV1 {
  create_profile
  read_profile
  policy_type_and_version
  evaluator_semantic_id_and_version
  canonicalization_version
  presentation_version
  configured_api_audience
  trusted_route_ids
  identifier_grammar_version
  value_encoding
  maximum_http_header_bytes
  maximum_proof_bytes
  maximum_presentation_bytes
  maximum_request_body_bytes
  maximum_value_bytes
  maximum_response_bytes
  maximum_policy_items
  maximum_evaluator_work
  maximum_active_reservations
  maximum_action_lifetime_seconds
  maximum_presentation_lifetime_seconds
  challenge_schema
  claim_and_replay_schema
  records_store_schema
  receipt_schema
}
```

The decision and receipts report both configurations. Canonical inequality
produces `verifier-configuration-mismatch` before decision persistence,
reservation, protected reads, credential acquisition, or mutation.

A mandatory regression test requires `maximum_response_bytes = 4096` and runs
an otherwise identical executor configured with `4097`. Verification must
deny before accessing the protected record.

## 12. Decision semantics

The pure evaluator accepts explicit policy, action, protected metadata,
aggregate state, required/executed configuration, presenter context, audience,
challenge context, and time.

It returns:

```text
eligible {
  exact action commitments
  create or read reservations
  disclosure limits
  obligations
}

denied {
  stable code
  stage
}

indeterminate {
  stable code
  stage
}
```

Complete trustworthy inputs establish `eligible` or `denied`. Missing or
untrustworthy protected context, storage failure, or unavailable required
evidence is `indeterminate`; it is never converted into authorization.

Transport authentication, successful TLS, a valid presenter signature, a
recognized issuer, or an existing session alone is insufficient.

## 13. Create execution protocol

After bounded decoding:

```text
derive typed create action
  -> verify presentation and exact Auths proof
  -> compare required/executed configuration
  -> evaluate records policy
  -> persist decision receipt
  -> atomically reserve aggregate create capacity
  -> claim exact action digest
  -> acquire records-store credential if required
  -> recheck namespace and expected absence
  -> atomically insert record and execution-ledger entry
  -> persist execution result
  -> read back exact record version
  -> append observation receipt
  -> commit reservation
```

The records store must provide an atomic uniqueness boundary over namespace and
record ID plus a unique execution ledger keyed by action digest. Auths claim
state prevents concurrent execution before protected access. The store
transaction proves whether the local effect committed. Neither replaces the
other.

A definite pre-delivery failure releases reserved capacity. An ambiguous
disconnect after transaction submission retains capacity as
`outcome-unknown`. Reconciliation reads the exact ledger and record; it never
blindly creates the record again.

HTTP response loss does not erase the durable result. Repeating the same exact
request returns replay and the original execution commitment without a second
insert.

## 14. Read execution protocol

After proof verification, configuration equality, policy evaluation, and any
configured read reservation:

1. claim or register the exact disclosure according to policy;
2. acquire the narrow protected-read capability if required;
3. retrieve only the exact namespace and record;
4. verify expected version where present;
5. construct the allowed field projection;
6. canonicalize the response and enforce its byte ceiling;
7. record the disclosure commitment and byte count; and
8. return the protected representation.

The receipt includes a digest and size of the disclosed canonical response,
not the protected value by default.

An exact one-time read replays without performing a second disclosure. A
bounded multi-read capability consumes its configured count atomically.
Whether repeated retrieval of an already disclosed record consumes another
unit is fixed by the policy version and visible in the receipt.

`GET` responses use `Cache-Control: no-store` and must not be placed in shared
proxy or browser caches.

## 15. HTTP mapping and canonicalization

V1 protected routes are:

```text
POST /v1/records
GET  /v1/records/{record_id}
```

The trusted router supplies closed route identifiers:

```text
records.create.v1
records.read.v1
```

The application route identifier, not a raw externally supplied URL, enters
the presentation. The configured audience supplies scheme, authority, and
deployment identity; untrusted `Host`, forwarding, or proxy headers cannot
select it.

The adapter must:

- reject unsupported methods before protected access;
- enforce header and body limits before allocation-heavy parsing;
- accept only the expected media type and encoding;
- reject duplicate JSON members and unknown fields;
- reject unknown or duplicate query parameters;
- define percent-decoding exactly once;
- reject path traversal, encoded separators, ambiguous path normalization, and
  invalid UTF-8;
- ignore hop-by-hop headers for semantic authorization and reject forbidden
  Auths header duplication;
- derive the canonical action after trusted routing and typed decoding;
- compare the derived action digest with the presentation commitment; and
- ensure proxy and direct-server paths produce the same route identity and
  action.

Whitespace or member-order differences that decode to the same permitted typed
action have the same canonical action. A semantic value change produces a
different action digest. The UI must describe this accurately rather than
claiming every raw HTTP byte is independently authorized.

## 16. Transport independence

The REST service proves one HTTP adapter; it does not make HTTP part of core
authority.

Conformance tests must carry the same canonical action and proof through at
least:

- an in-memory exchange;
- the repository file exchange; and
- the HTTPS demo path.

After transport framing is removed, all three paths must produce identical
canonical action digests and verifier results for the same trusted context.
Mutation of proof bytes must deny identically. Authenticated or configured
HTTPS transport must not upgrade an invalid proof.

The receipt records the delivery adapter as operational evidence, separately
from the authority decision. Product policy may require trusted channel facts
as explicit context, but those facts alone never authorize the action.

The public UI explains:

> HTTPS carried the proof. The API authorized the typed action by verifying
> the proof itself.

An additional public Iroh, queue, or file-relay control is deferred until it
can exercise a real exchange path rather than simulate one.

## 17. Stable codes

- `malformed-http-request`
- `unsupported-method`
- `unsupported-media-type`
- `request-limit-exceeded`
- `malformed-create-action`
- `malformed-read-action`
- `unsupported-profile`
- `proof-invalid`
- `proof-presenter-mismatch`
- `presentation-invalid`
- `presentation-expired`
- `challenge-invalid`
- `challenge-replayed`
- `api-audience-mismatch`
- `route-action-mismatch`
- `action-body-mismatch`
- `verifier-configuration-mismatch`
- `policy-invalid`
- `policy-expired`
- `operation-denied`
- `namespace-denied`
- `record-denied`
- `read-field-denied`
- `value-limit-exceeded`
- `response-limit-exceeded`
- `aggregate-create-limit-exceeded`
- `aggregate-read-limit-exceeded`
- `already-claimed`
- `record-already-exists`
- `record-version-mismatch`
- `protected-store-unavailable`
- `execution-outcome-unknown`
- `reconciliation-required`

Codes remain profile and stage specific. HTTP status mapping is an adapter
concern and must not erase the canonical three-valued decision or stable code.

## 18. Receipts

### Decision receipt

Contains proof and presenter commitments, action and policy digests, exact
profile, namespace commitment, required and executed configuration, bounded
usage before the action, verdict, stable code, stage, and whether protected
storage or a credential was accessed.

### Execution or disclosure receipt

For create, contains claim and reservation identities, exact record
commitments, store transaction and ledger commitment, resulting record
version, mutation count, and outcome classification.

For read, contains the exact field set, response digest and byte count,
protected-read boundary, disclosure count, and record-version commitment. It
does not expose the record value by default.

### Observation receipt

Contains a fresh exact record or ledger observation, reconciliation source,
previous receipt digest, observation time, and whether the observed state
matches the authorized effect.

Authorization, attempted execution, HTTP response delivery, and observed
effect remain separate facts. A `200` or `201` status does not rewrite the
authorization receipt.

## 19. Demo API

Control-plane routes are:

```text
POST /api/v1/sessions
GET  /api/v1/sessions/{id}
POST /api/v1/sessions/{id}/grants
GET  /api/v1/sessions/{id}/challenges
GET  /api/v1/executions/{id}
POST /api/v1/executions/{id}/reconcile
GET  /api/v1/receipts/{id}
GET  /receipts/{id}
GET  /healthz
GET  /readyz
```

`grants` accepts only repository-owned exact and bounded experiments. It does
not accept arbitrary policy JSON, issuer keys, trust roots, namespace IDs,
audiences, route definitions, or verifier configuration.

The protected `/v1/records` routes accept the proof and presentation using the
versioned demo carrier plus their route-specific action input. They never
accept an API key, OAuth access token, database credential, arbitrary
downstream URL, or server-selected idempotency identity from the caller.

Session identifiers are opaque routing handles, not authorization. Possessing
one cannot read or mutate records.

## 20. End-to-end demonstration

### Workbench

The primary workbench places authority and exact action controls beside the
live API result:

```text
+------------------------------+------------------------------+
| Granted authority            | Proposed REST call           |
| exact or bounded             | method, route, typed body     |
| namespace, fields, limits    | copyable curl, no API key     |
+------------------------------+------------------------------+
| proof | configuration | claim | protected access | observed |
+-------------------------------------------------------------+
| aggregate capacity, replay, and disclosure state            |
+-------------------------------------------------------------+
| inline canonical receipt JSON            [Designed receipt] |
+-------------------------------------------------------------+
```

The page visibly reports:

- `reusable_api_key_present: false`;
- proof and presenter status;
- canonical product action;
- delivery adapter;
- required/executed configuration equality;
- current verdict and stable code;
- whether protected storage was read or mutated;
- aggregate capacity before and after;
- replay and reconciliation state; and
- decision, execution/disclosure, and observation commitments.

Copy explains exactly what occurred. It does not say “no authentication” or
“no credentials anywhere.”

### Experiments

Required experiments are:

1. exact valid create;
2. create body value changed;
3. record ID changed;
4. method or route changed;
5. wrong audience;
6. expired presentation;
7. required/executed configuration mismatch;
8. exact create replay;
9. bounded create at zero, exact limit, and limit plus one;
10. concurrent requests for the final create unit;
11. exact allowed read;
12. another namespace or record requested;
13. additional field requested;
14. response limit reduced below the canonical response;
15. exact read replay or bounded disclosure exhaustion;
16. invalid proof over the valid HTTPS path; and
17. injected lost create response followed by reconciliation.

Selecting an experiment immediately updates the visible authority, action, and
generated `curl`. Executing it calls the real native backend. Denied paths
prove that protected storage was not accessed.

### Copyable curl

The successful exact experiment provides a complete short-lived command
conceptually equivalent to:

```text
curl -X POST https://<public-api>/v1/records \
  -H 'Content-Type: application/json' \
  -H 'Auths-Proof: <proof>' \
  -H 'Auths-Presentation: <single-action-presentation>' \
  --data '{"record_id":"example-1","value":"hello"}'
```

The command contains no API key, OAuth token, session cookie, presenter private
key, database credential, or reusable unrestricted capability. The proof and
presentation are redacted from ordinary logs and expire promptly.

## 21. Frontend and receipt interface

The frontend is a required implementation surface. A backend-only API,
Swagger page, static mockup, or `file://` page does not satisfy this
specification.

It must:

- use the `auths-proof-site` design language and plain factual copy;
- keep the selected experiment and current result adjacent;
- make clickable controls visibly interactive;
- distinguish loading, unavailable, denied, indeterminate, eligible, claimed,
  executed, disclosed, observed, replay, and unknown outcomes;
- render the complete canonical receipt JSON inline from the receipt API;
- link to a designed `/receipts/{id}` page rather than raw JSON;
- explain the receipt before showing its complete raw representation;
- render malformed, missing, expired, or unverifiable receipt IDs fail-closed;
  and
- work on desktop and mobile without separating cause from result through
  several screens of scrolling.

Browser tests must start from the rendered public page and exercise exact
create, material denial, replay, bounded exhaustion, exact read, disclosure
denial, lost response/reconciliation, inline receipt JSON, the dedicated
receipt page, and a copyable command through the same routes used in
deployment.

## 22. Local and public deployment

Provide:

- Docker-local operation through a documented HTTP `localhost` URL;
- a public frontend deployment;
- a public native API deployment;
- durable isolated demo records, claims, budgets, and receipts;
- automatic expiry and bounded retention for public sessions;
- explicit CORS and trusted-origin configuration;
- TLS at the public boundary;
- health and readiness that do not mutate or disclose protected records;
- proof and secret header redaction in platform, proxy, and application logs;
- rate and resource limits appropriate to an adversarial public demo; and
- an incident shutdown and data-reset procedure.

The deployment must test the actual proxy chain used publicly. Direct local
server success is insufficient because path, header, authority, and body
normalization can differ at a reverse proxy.

Opening a static HTML file, deploying only the frontend, committing deployment
configuration without deploying it, or serving fixture-only decisions is
incomplete.

## 23. Verification

### Unit and property tests

- bounded identifier, header, proof, presentation, body, value, policy, and
  response limits;
- unknown and duplicate field rejection;
- Unicode and JSON canonicalization;
- exact create and read action vectors;
- method, route, query, body, audience, presenter, challenge, and expiry
  mutations;
- required/executed configuration mismatch;
- policy tightening never expands eligible records, fields, bytes, time, or
  capacity;
- checked aggregate arithmetic;
- response projection cannot return an unlisted field;
- stable code and receipt serialization; and
- malformed external input never panics.

### Concurrency, crash, and recovery

- concurrent final create unit;
- concurrent exact-action claim;
- duplicate record insertion;
- response loss before and after store commit;
- receipt persistence failure before protected access;
- process restart with active reservation;
- replay after restart;
- reconciliation through the execution ledger;
- read budget exhaustion under concurrency; and
- unknown outcomes continue to hold capacity.

### HTTP and deployment

- direct and reverse-proxy route identity parity;
- request-smuggling and conflicting length/transfer framing rejection at the
  public edge;
- duplicate Auths, host, forwarding, content-type, and query handling;
- percent-encoding and path normalization;
- unsupported method and media type;
- CORS preflight does not authorize protected action;
- protected GET responses are not cached;
- proof, presentation, challenge, and protected values are absent from logs,
  traces, error pages, frontend bundles, source maps, and receipts where
  prohibited;
- public frontend/native readiness and browser interaction; and
- copyable `curl` succeeds before its short expiry and replays safely.

### Transport conformance

- memory, file, and HTTPS delivery produce the same action digest and verifier
  result;
- malformed or invalid proof remains invalid through every transport;
- transport success without a valid proof denies;
- transport failure does not create an authorization result; and
- operational transport evidence remains separate from semantic decision
  fields.

## 24. Formal assurance

This vertical does not justify a generic formal HTTP policy algebra.

Use property tests and bounded model checking for:

- policy tightening;
- aggregate capacity conservation;
- exact claim uniqueness;
- replay;
- disclosure field containment;
- response-byte ceilings;
- configuration inequality ordering; and
- create reservation transitions through commit, release, unknown, and
  reconciliation.

If records-domain pure predicates become a formal target, follow specification
0011: mechanically connect production Rust predicates to the rich Lean model.
An independently rewritten Lean evaluator is not evidence that shipping HTTP
or records code refines it.

Network, proxy, filesystem, and database behavior remain explicit external
boundaries. Formal models may reason about allowed commands, recorded outcomes,
and observations; they must not assume HTTP delivery or store commit is
atomic.

## 25. Completion evidence

Before changing status from Proposed:

- commit canonical valid, denial, boundary, replay, receipt, and recovery
  fixtures;
- prove exact POST creates one durable record without a reusable client API
  credential;
- prove replay and concurrent duplicate execution create no second record;
- prove bounded create capacity at zero, exact limit, and limit plus one;
- prove exact and bounded GET disclose only authorized records and fields;
- prove every material denial stops before protected access;
- exercise lost-response and restart reconciliation against the real store;
- pass memory, file, and HTTPS transport conformance;
- pass direct-server and public reverse-proxy canonicalization tests;
- complete Docker-local frontend/backend/browser tests;
- complete public frontend/backend/browser tests;
- expose inline canonical JSON and a designed receipt page;
- record tested public URLs, deployment identifiers, source revision, regions,
  configuration commitments, and timestamps;
- scan repository, images, frontend artifacts, logs, errors, and receipts for
  proofs, private keys, cookies, API keys, and protected values;
- register architecture and compliance evidence; and
- pass authoritative CI on the exact revision.

The status remains Proposed if the implementation is fixture-only,
backend-only, frontend-only, localhost-only, inaccessible through a copyable
client request, or if the public path bypasses the native verifier.

## 26. Acceptance criteria

1. A visitor performs successful protected `POST` and `GET` requests without
   receiving a reusable API key, OAuth bearer token, or session cookie.
2. The API verifies Auths proof and presenter evidence locally.
3. HTTP is the delivery adapter; typed product actions define authority.
4. Changing the method, route, typed body, record, field set, audience,
   presenter, proof, presentation, or configuration produces the expected
   stable result.
5. Exact create executes once under replay, concurrency, response loss, and
   restart.
6. Bounded creates and reads conserve aggregate capacity.
7. Unauthorized reads return no protected data.
8. Denial occurs before protected storage or credential access.
9. Required and executed configurations are visible and equal on success.
10. Decision, execution or disclosure, HTTP delivery, and observation remain
    separate receipt facts.
11. Memory, file, and HTTPS delivery agree on canonical action and verifier
    result.
12. Invalid proof over trusted HTTPS remains invalid.
13. The public frontend and copyable command use the real deployed native API.
14. Core remains independent of HTTP routing, the records domain, replay
    storage, and mutable product state.

## 27. Deferred work

- standardized Auths HTTP authorization and presentation headers;
- reusable `auths-http` middleware for Axum, Actix, Go, Node, and Python;
- OpenAPI extensions and typed action generation;
- a generic API-gateway adapter;
- public Iroh, queue, or file-relay delivery controls;
- WebAuthn-backed long-lived presenter identity;
- richer record schemas and typed values;
- query, list, pagination, and streaming disclosure profiles;
- cross-service proof forwarding;
- multi-action and transactional API workflows;
- issuer and verifier deployment as separate public services;
- production credential broker integrations; and
- extracting shared HTTP mechanisms only after several independent domain
  profiles prove identical contracts.

Relevant standards for later adapter design include HTTP Semantics
(RFC 9110), JSON Canonicalization Scheme (RFC 8785), HTTP Message Signatures
(RFC 9421), and Digest Fields (RFC 9530). Their use does not replace the Auths
proof or make transport semantics part of the core authority model.
