# 0024: Transport-neutral REST API authorization without reusable client API keys

Status: Implemented
Exact action profiles: `auths.demo.records.create/1`,
`auths.demo.records.read/1`  
Policy family: `auths.demo.bounded-record-api-policy/1`  
Product package: `product/integrations/auths-records-api`  
Demo: `demos/rest-api-authorization`  
Required delivery adapters: HTTPS, Iroh

Tracking issue: [#22](https://github.com/auths-dev/auths-proof/issues/22)

## 1. Decision

Build a concrete records API vertical demonstrating that an untrusted agent or
client can make authenticated `POST` and `GET` requests without receiving a
reusable API key, OAuth bearer token, session cookie, database credential, or
other downstream secret. The same logical request must be accepted through
either a public HTTPS endpoint or a real Iroh endpoint.

The caller presents an Auths proof plus a request presentation. The protected
API independently verifies that evidence against a typed canonical product
action, trusted context, required and executed configuration, and durable
bounded state before reading protected data or performing a mutation.

HTTP and Iroh are delivery and enforcement adapters. Neither defines the
authority algebra. Both normalize into the same bounded records request
envelope and the same semantic `CreateRecord` or `ReadRecord` action. The
authority is not an arbitrary HTTP request, Iroh message, URL, or node
identity.

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
12. accept the same proof and canonical action over HTTPS and Iroh;
13. prove that neither authenticated HTTPS nor an authenticated Iroh
    connection can create or upgrade authority;
14. share claim, replay, aggregate, execution, and reconciliation state across
    both delivery paths;
15. execute cross-transport replay and concurrency experiments; and
16. provide a complete Docker-local and public browser demonstration with
    copyable `curl` and native Iroh commands.

## 4. Non-goals

V1 does not:

- provide anonymous or credential-free authorization;
- replace TLS, origin security, availability controls, or traffic protection;
- authorize arbitrary URLs, methods, headers, query strings, or bodies;
- accept a raw policy language or OpenAPI document from the caller;
- turn reverse-proxy identity or successful TLS into authorization;
- expose a generic API gateway or universal HTTP middleware;
- expose a generic multi-transport execution framework;
- standardize a permanent Auths HTTP header format;
- make an Iroh node ID, connection, ticket, relay, or encrypted channel
  sufficient authorization;
- allow unrestricted record search, listing, filtering, or pagination;
- support arbitrary JSON record values;
- expose another visitor's records;
- place HTTP routing, Iroh addressing, mutable replay state, or product policy
  in `core/`;
- treat a successful HTTP response as proof that an external effect was
  observed; or
- infer that every REST integration has the same evidence, state, or receipt
  semantics.

Future `auths-http` and OpenAPI tooling may be designed from this vertical, but
they are not implementation prerequisites and must not be extracted
prematurely.

## 5. Architectural boundary

The required paths converge before semantic verification:

```text
untrusted HTTP bytes
  -> bounded route-specific HTTP adapter ----+
                                              |
untrusted Iroh message                        |
  -> bounded records-protocol Iroh adapter ---+
                                              v
                                  RecordsRequestEnvelopeV1
                                              |
                                              v
                                 typed records-domain action
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
- the transport-neutral records request envelope and operation identities;
- create and read actions;
- exact and bounded records policy;
- protected records evidence;
- action evaluators;
- mutation and disclosure state transitions;
- verified commands;
- records-store port;
- receipt meanings and stable codes; and
- route-to-action mapping for this API.

The demo owns HTTP and Iroh serving, browser sessions, the native Iroh client,
public experiment selection, deployment, and presentation.

Core continues to own portable proof, canonical action, attenuation,
composition, and three-valued verification semantics. Exchange packages may
carry opaque proof bytes. The implementation must use the repository
`auths-proof-exchange-iroh` adapter rather than recreating Iroh framing or
identity semantics inside the records package. Neither transport nor the
records package may redefine core verification.

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
- configured semantic executor audience;
- trusted mappings from HTTPS origin and Iroh endpoint to that executor;
- executed profile and canonicalization versions;
- server time;
- server-issued challenge;
- protected namespace ownership;
- operation identity after trusted adapter decoding;
- records-store identity and schema;
- durable claim, replay, and aggregate state; and
- receipt-store identity.

### Credentials

The public client receives no API key, OAuth access token, session cookie,
database password, or provider credential. An Iroh ticket or node address is
delivery information, not a bearer authorization credential.

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
executor_audience
operation_id
canonical_action_digest
challenge
created_at
expires_at
presentation_nonce
```

HTTP method, route, query, and body are not independently granted authority.
An Iroh protocol name, node ID, connection identity, and message framing are
also not independently granted authority. Each trusted adapter derives one of
the transport-neutral operation identities:

```text
records.create.v1
records.read.v1
```

and the same typed action. The adapter then requires the operation and action
commitments to match the presentation.

An HTTP adapter may carry the presentation through versioned Auths headers or
HTTP Message Signatures. The semantic presentation above remains independent
of that carrier. The Iroh adapter carries the same semantic presentation in a
bounded versioned message. V1 does not declare a permanent Internet-wide
header standard.

For copyable `curl`, the browser generates a complete, short-lived,
single-action presentation. Copying the command does not expose the
presenter's private key or a reusable general capability. The corresponding
action is still protected by claim/replay state.

## 8. Transport-neutral request envelope

Both delivery adapters produce:

```text
RecordsRequestEnvelopeV1 {
  envelope_version
  operation_id
  canonical_action
  proof
  presentation
}
```

The envelope contains no HTTP URL, arbitrary header map, Iroh ticket, relay
URL, node-selection instruction, credential, or generic provider parameters.
Transport-specific addressing and framing are consumed outside this semantic
boundary.

The HTTPS adapter derives the operation and action from its trusted route and
bounded request decoder before constructing the envelope. The Iroh adapter
decodes the closed records protocol message and constructs the same envelope.
Both must produce byte-identical canonical action bytes and the same envelope
fields for the same logical request.

The envelope is not a generic product executor API. It is owned by the records
vertical and can carry only the two profiles defined here. A future shared
submission carrier requires the abstraction evidence and review process in the
profile and domain boundary plan.

## 9. Exact create action

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
executor_audience
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

## 10. Exact read action

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
executor_audience
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

## 11. Bounded records policy

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
executor_audience
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

## 12. Evidence and evaluator configuration

Protected evaluation inputs include:

- namespace identity and presenter binding;
- action-specific policy and proof commitments;
- current aggregate create and read usage;
- active reservations and unknown outcomes;
- exact-record existence or version metadata where required;
- server challenge identity and lifetime;
- semantic executor audience;
- HTTPS and Iroh adapter identities mapped to that executor;
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
  configured_executor_audience
  trusted_operation_ids
  trusted_https_origin_mappings
  trusted_iroh_endpoint_mappings
  iroh_protocol_version
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

## 13. Decision semantics

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

## 14. Create execution protocol

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

## 15. Read execution protocol

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

## 16. HTTP mapping and canonicalization

V1 protected routes are:

```text
POST /v1/records
GET  /v1/records/{record_id}
```

The trusted router maps the routes to closed transport-neutral operation
identities:

```text
records.create.v1
records.read.v1
```

The operation identity, not a raw externally supplied URL, enters the
presentation. Trusted configuration maps the public HTTPS origin to the
semantic executor audience. Untrusted `Host`, forwarding, or proxy headers
cannot select either the audience or operation.

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
- ensure proxy and direct-server paths produce the same operation identity and
  action.

Whitespace or member-order differences that decode to the same permitted typed
action have the same canonical action. A semantic value change produces a
different action digest. The UI must describe this accurately rather than
claiming every raw HTTP byte is independently authorized.

## 17. Required Iroh delivery

The native service exposes the closed records protocol through a real public
Iroh endpoint using `auths-proof-exchange-iroh`. The protocol accepts only
`RecordsRequestEnvelopeV1` messages for the two operation identities defined
by this specification.

The Iroh adapter:

- enforces framing, message, proof, presentation, action, and work limits
  before semantic processing;
- rejects unsupported protocol and envelope versions;
- maps its configured node and protocol endpoint to the same semantic executor
  audience as HTTPS;
- records peer and local node commitments as delivery evidence;
- never treats a valid Iroh connection or node identity as authorization;
- passes the normalized envelope to the same verifier, evaluator, claim store,
  executor, and receipt store used by HTTPS; and
- returns a bounded result envelope containing the canonical decision,
  execution reference, and receipt reference.

The public demo includes a native CLI or equivalent packaged client that sends
the exact request directly to the Iroh endpoint. The CLI receives a proof,
presentation, and action envelope; it does not receive an API key, issuer
private key, database credential, arbitrary node-selection policy, or generic
remote command.

A browser button may ask a native sender service to exercise the Iroh path for
accessibility, but the implementation and receipts must prove that a real Iroh
connection reached the verifier. Relabeling an HTTP request as “Iroh” does not
satisfy this specification.

## 18. Transport independence and parity

Conformance tests must carry the same canonical action and Auths proof through:

- an in-memory exchange;
- the repository file exchange;
- the public HTTPS path; and
- the public Iroh path.

After transport framing is removed, all four paths must produce identical
canonical action bytes, action digests, proof digests, semantic executor
audiences, verifier results, policy results, and stable codes for the same
trusted semantic context.

The exact same proof and action may use a fresh transport presentation when
challenge or channel binding requires it. The presentation must still resolve
to the same presenter, operation, action digest, and executor audience.

Claim, replay, aggregate, execution-ledger, and reconciliation state is shared
across transports. Transport selection cannot create a new authorization or
idempotency namespace.

Required cross-transport behavior includes:

```text
execute over HTTPS -> replay over Iroh  -> one effect
execute over Iroh  -> replay over HTTPS -> one effect
race HTTPS and Iroh for final capacity  -> one reservation and one effect
lose HTTPS response after commit        -> reconcile through shared ledger
lose Iroh acknowledgement after commit  -> reconcile through shared ledger
```

Mutation of proof or action bytes must deny identically. Authenticated HTTPS
and authenticated Iroh transport must not upgrade an invalid proof.

The receipt records delivery separately from authority:

```text
DeliveryReceiptV1 {
  transport = https | iroh
  endpoint_commitment
  peer_or_origin_commitment
  received_at
  delivery_status
  envelope_digest
}

DecisionReceiptV1 {
  executor_audience
  operation_id
  proof_digest
  action_digest
  policy_digest
  configuration
  verdict
  stable_code
}
```

For equivalent fresh state and trusted semantic context, only the delivery
receipt changes when transport changes. Product policy may require trusted
channel facts as explicit context, but those facts alone never authorize the
action. Replay and later lifecycle receipts may naturally differ because the
first transport already changed durable state.

The public UI explains:

> HTTPS or Iroh carried the same authority evidence. The executor authorized
> the typed action by verifying the proof itself.

## 19. Stable codes

- `malformed-http-request`
- `malformed-iroh-message`
- `unsupported-method`
- `unsupported-media-type`
- `unsupported-iroh-protocol`
- `unsupported-transport-envelope`
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
- `executor-audience-mismatch`
- `operation-action-mismatch`
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

Codes remain profile and stage specific. Malformed framing that never produces
a bounded semantic envelope is a delivery result, not an authorization
decision. HTTP status and Iroh result-envelope mappings are adapter concerns
and must not erase a canonical three-valued decision or stable code after the
semantic boundary is reached.

## 20. Receipts

### Delivery receipt

Contains transport kind, protocol or HTTP adapter version, endpoint and peer
or origin commitments, envelope digest, receipt time, and delivery outcome. It
does not claim authorization and does not contain raw proof, presentation,
ticket, IP address, or node identity unless a non-public deployment explicitly
requires those values.

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

Delivery, authorization, attempted execution, HTTP response or Iroh
acknowledgement, and observed effect remain separate facts. A `200`, `201`, or
successful Iroh result envelope does not rewrite the authorization receipt.

## 21. Demo API

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

The public Iroh service advertises one configured endpoint and records protocol
version:

```text
protocol = "auths.records-api/1"
operations = records.create.v1 | records.read.v1
```

It accepts the same semantic envelope as the HTTPS adapter and returns bounded
canonical result and receipt references. It does not expose the HTTP
control-plane routes through a generic remote-call message.

## 22. End-to-end demonstration

### Workbench

The primary workbench places authority and exact action controls beside the
live API result:

```text
+------------------------------+------------------------------+
| Granted authority            | Proposed records action      |
| exact or bounded             | method/operation, typed body  |
| namespace, fields, limits    | HTTPS or Iroh, no API key     |
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
- semantic executor audience;
- delivery adapter and separate delivery evidence;
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

1. exact valid create over HTTPS;
2. the same exact create delivered first over Iroh;
3. execute over HTTPS and replay over Iroh;
4. execute over Iroh and replay over HTTPS;
5. race HTTPS and Iroh for the final bounded unit;
6. exact valid read over both transports;
7. lose an HTTPS response after commit and reconcile;
8. lose an Iroh acknowledgement after commit and reconcile;
9. invalid proof over authenticated HTTPS and Iroh paths;
10. authenticated transport with no valid proof;
11. create body value changed;
12. record ID changed;
13. HTTP method or route, or Iroh operation, changed;
14. wrong executor audience;
15. expired presentation;
16. required/executed configuration mismatch;
17. exact create replay on the same transport;
18. bounded create at zero, exact limit, and limit plus one;
19. concurrent requests for the final create unit;
20. exact allowed read;
21. another namespace or record requested;
22. additional field requested;
23. response limit reduced below the canonical response; and
24. exact read replay or bounded disclosure exhaustion.

Selecting an experiment immediately updates the visible authority, action,
delivery adapter, generated `curl`, and native Iroh command. Executing it calls
the real native backend through the selected adapter. Denied paths prove that
protected storage was not accessed.

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

### Native Iroh command

The same experiment provides a command conceptually equivalent to:

```text
auths-records-demo send \
  --transport iroh \
  --endpoint <public-iroh-endpoint> \
  --envelope <short-lived-envelope-file>
```

The command must open a real Iroh connection using the repository exchange
adapter. Its result displays the same canonical action digest, executor
audience, verdict, stable code, execution reference, and semantic receipt as
HTTPS, plus separate Iroh delivery evidence.

## 23. Frontend and receipt interface

The frontend is a required implementation surface. A backend-only API,
Swagger page, static mockup, or `file://` page does not satisfy this
specification.

It must:

- use the `auths-proof-site` design language and plain factual copy;
- keep the selected experiment and current result adjacent;
- make clickable controls visibly interactive;
- expose a clear `HTTPS` / `Iroh` delivery selector;
- keep proof, action, audience, and semantic result visibly stable when only
  the transport changes;
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
create over HTTPS and Iroh, material denial over both, cross-transport replay,
cross-transport final-capacity concurrency, bounded exhaustion, exact read,
disclosure denial, lost response or acknowledgement reconciliation, inline
receipt JSON, the dedicated receipt page, and both copyable commands through
the real deployed adapters.

## 24. Local and public deployment

Provide:

- Docker-local operation through a documented HTTP `localhost` URL;
- Docker-local Iroh operation through a documented native endpoint;
- a public frontend deployment;
- a public native HTTPS API deployment;
- a public native Iroh endpoint using the repository exchange adapter and a
  reachable relay or direct-connect configuration;
- durable isolated demo records, claims, budgets, and receipts;
- automatic expiry and bounded retention for public sessions;
- explicit CORS, trusted-origin, Iroh protocol, endpoint, and executor-audience
  mappings;
- TLS at the public boundary;
- health and readiness that do not mutate or disclose protected records;
- proof and secret header redaction in platform, proxy, and application logs;
- rate and resource limits appropriate to an adversarial public demo; and
- an incident shutdown and data-reset procedure.

The deployment must test the actual proxy chain and Iroh connectivity used
publicly. Direct local server success is insufficient because path, header,
authority, body normalization, relay reachability, and node addressing can
differ in deployment.

Opening a static HTML file, deploying only the frontend, committing deployment
configuration without deploying it, simulating Iroh through an HTTP label, or
serving fixture-only decisions is incomplete.

## 25. Verification

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

- direct and reverse-proxy operation identity parity;
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

### Iroh and deployment

- direct native client connects to the deployed Iroh endpoint;
- protocol and envelope version negotiation is closed and bounded;
- peer or node authentication alone never authorizes an action;
- wrong endpoint mapping produces executor-audience mismatch;
- malformed, truncated, oversized, duplicated, and unsupported messages fail
  before semantic execution;
- relay and direct-connect behavior preserve envelope bytes;
- lost acknowledgement after commit reconciles without a second effect;
- restart preserves cross-transport replay and reservations;
- proof, presentation, ticket, node material, and protected values are absent
  from prohibited logs and receipts; and
- the copyable native command succeeds before expiry and replays safely.

### Transport conformance

- memory, file, HTTPS, and Iroh delivery produce the same action digest,
  executor audience, verifier result, policy result, and stable code;
- HTTPS-to-Iroh and Iroh-to-HTTPS replay produce one effect;
- a concurrent HTTPS/Iroh final-capacity race produces one reservation and one
  effect;
- malformed or invalid proof remains invalid through every transport;
- transport success without a valid proof denies;
- transport failure does not create an authorization result; and
- operational transport evidence remains separate from semantic decision
  fields.

## 26. Formal assurance

This vertical does not justify a generic formal HTTP or multi-transport policy
algebra.

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

Network, proxy, Iroh relay, filesystem, and database behavior remain explicit
external boundaries. Formal models may reason about allowed commands, recorded
outcomes, and observations; they must not assume HTTP delivery, Iroh delivery,
or store commit is atomic.

## 27. Completion evidence

Before changing status from Proposed:

- commit canonical valid, denial, boundary, replay, receipt, and recovery
  fixtures;
- prove exact POST creates one durable record without a reusable client API
  credential;
- prove replay and concurrent duplicate execution create no second record;
- prove bounded create capacity at zero, exact limit, and limit plus one;
- prove exact and bounded GET disclose only authorized records and fields;
- prove every material denial stops before protected access;
- exercise lost HTTP response, lost Iroh acknowledgement, and restart
  reconciliation against the real store;
- pass memory, file, HTTPS, and Iroh transport conformance;
- prove HTTPS-to-Iroh and Iroh-to-HTTPS replay create one effect;
- prove a concurrent cross-transport final-capacity race creates one
  reservation and one effect;
- pass direct-server and public reverse-proxy canonicalization tests;
- complete Docker-local HTTPS/Iroh frontend/backend/browser/native-client
  tests;
- complete public HTTPS/Iroh frontend/backend/browser/native-client tests;
- expose inline canonical JSON and a designed receipt page;
- record tested public URLs, deployment identifiers, source revision, regions,
  configuration commitments, and timestamps;
- scan repository, images, frontend artifacts, logs, errors, and receipts for
  proofs, private keys, cookies, API keys, and protected values;
- register architecture and compliance evidence; and
- pass authoritative CI on the exact revision.

The status remains Proposed if the implementation is fixture-only,
backend-only, frontend-only, localhost-only, inaccessible through copyable
HTTP and Iroh client requests, simulates Iroh over HTTP, or if either public
path bypasses the native verifier.

## 28. Acceptance criteria

1. A visitor performs successful protected `POST` and `GET` requests without
   receiving a reusable API key, OAuth bearer token, or session cookie.
2. The API verifies Auths proof and presenter evidence locally.
3. HTTPS and Iroh are delivery adapters; typed product actions define
   authority.
4. For equivalent fresh state and trusted semantic context, the same proof,
   canonical action, executor audience, evaluator, and stable result are used
   across both public adapters.
5. Changing the HTTP method or route, Iroh operation, typed body, record, field
   set, audience, presenter, proof, presentation, or configuration produces
   the expected stable result.
6. Exact create executes once under replay, concurrency, response loss, and
   restart.
7. Cross-transport replay and concurrency create one effect and consume
   capacity once.
8. Bounded creates and reads conserve aggregate capacity.
9. Unauthorized reads return no protected data.
10. Denial occurs before protected storage or credential access.
11. Required and executed configurations are visible and equal on success.
12. Delivery, decision, execution or disclosure, and observation remain
    separate receipt facts.
13. Memory, file, HTTPS, and Iroh delivery agree on canonical action and
    verifier result.
14. Invalid proof over trusted HTTPS or authenticated Iroh remains invalid.
15. The public frontend, copyable `curl`, and native Iroh command use the real
    deployed native verifier and shared state.
16. Core remains independent of HTTP routing, Iroh addressing, the records
    domain, replay storage, and mutable product state.

## 29. Deferred work

- standardized Auths HTTP authorization and presentation headers;
- reusable `auths-http` middleware for Axum, Actix, Go, Node, and Python;
- OpenAPI extensions and typed action generation;
- a generic API-gateway adapter;
- public queue, Unix-socket, or file-relay delivery controls;
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

## 30. Milestone 5 direct source cutover

The Milestone 5 Records API cutover replaces the original combined
`RecordsLedger` orchestration with the shared bounded-policy commitment and
durable lifecycle mechanisms. It does not move records, disclosure, HTTPS, or
Iroh meaning into a shared package.

This is a prelaunch source cutover. There are no users or production records.
The implementation MUST NOT add a legacy reader, converter, dual write,
compatibility shim, deprecation path, or runtime rollback format.

### 30.1 Profile and transport boundary

Create and read remain separate profiles:

```text
CreateRecordV1
  -> records create evaluator
  -> shared commitment projection
  -> verified create command
  -> records create provider contract

ReadRecordV1
  -> records read evaluator
  -> shared commitment projection
  -> verified read command
  -> records disclosure provider contract
```

The two profiles retain separate actions, evaluator entry points, obligations,
provider commands, effect outcomes, and receipt payloads. They share only the
closed records policy carrier, canonical commitment leaves, and already
qualified lifecycle mechanisms.

HTTPS, Iroh, memory, and file delivery continue to normalize into the same
records envelope before the profile boundary. Transport identity MUST NOT
select a lifecycle store, reservation namespace, workflow identity, or retry
identity. The same policy and exact action use the same lifecycle state across
all delivery adapters.

### 30.2 Shared commitment projection

An eligible domain decision projects into:

- the exact profile, action, policy, evidence, state, evaluator, required
  configuration, and executed implementation commitments;
- profile-owned reservation intents;
- one profile-owned exact-command obligation;
- a workflow identity derived from the profile, exact action digest, and
  policy digest; and
- one records-domain reservation algebra identity.

The create profile emits:

1. an additive create-unit intent of one unit under the policy digest; and
2. an additive created-byte intent equal to the canonical customer-value byte
   count under the same policy digest.

The read profile emits one additive read-unit intent of one unit under the
policy digest.

Actual disclosed bytes remain records-domain effect semantics. They are known
only after an authorized protected projection is constructed, so the records
store atomically checks and accounts for the exact disclosed byte count. A
disclosure-byte denial is a definite non-effect and releases the shared
read-unit reservation. The shared package does not learn record fields,
projection bytes, or disclosure policy.

Reservation intents MUST be canonically ordered by intent identity before
constructing bounded outputs. A lifecycle store is selected by policy digest
and configured with the exact additive ceilings committed by that policy.
Different actions under one policy therefore contend on the same durable
capacity, while different transports cannot create another budget namespace.

### 30.3 Required durable order

For both profiles, production execution is:

```text
configuration equality
  -> pure records decision
  -> presentation verification
  -> exact Auths verification
  -> immutable domain decision receipt
  -> shared decision record
  -> atomic shared reservation
  -> exact execution intent
  -> credential authorization
  -> attempt start
  -> provider-call entry
  -> sealed profile command
  -> one atomic records-store effect
  -> durable domain effect evidence
  -> shared commit
  -> observation and delivery result
```

No protected record read, mutation, or records-store credential is available
before the execution authorization seal. The provider adapter accepts only a
profile-specific command containing the exact Auths authorization,
`ExecutionAuthorizationV1`, and `ProviderCallAuthorizationV1`. It rejects a
wrong provider contract, workflow, execution, request digest, revision order,
or action binding before touching records.

The original pure create and read evaluators remain executable qualification
oracles. The original combined production orchestration and raw-action
provider entry points are removed in the same PR.

### 30.4 Crash, replay, and reconciliation

The local records transaction atomically persists either:

- the exact completed create effect;
- the exact completed disclosure and projection; or
- no effect.

The transaction is keyed by exact action digest. A committed lifecycle replay
returns the stored effect without a second insert or disclosure.

If the process stops after provider-call entry, restart MUST query the exact
domain execution ledger:

- one canonical matching completed action reconciles to effect and commits;
- canonical proof that no completed action exists reconciles to non-effect and
  releases capacity; and
- unavailable, corrupt, or contradictory state remains inconclusive and holds
  capacity as outcome-unknown.

Neither HTTPS response loss nor Iroh acknowledgement loss authorizes provider
resubmission. Reconciliation is read-only with respect to protected records.

### 30.5 Receipt and persisted-state cutover

The immutable decision receipt is written before reservation and always
reports `protected_storage_accessed = false`. Later protected access is
reported only by a profile-specific effect or non-effect receipt. Replay is an
execution classification and MUST NOT rewrite an authorized policy decision
as denied.

The direct cutover reserves:

```text
claim_and_replay_schema = "auths.records.shared-lifecycle/1"
records_store_schema    = "auths.records-store/2"
receipt_schema          = "auths.records-receipt/2"
lifecycle_state         = "auths.records.lifecycle-state/1"
domain_ledger_state     = "auths.records-ledger-state/2"
```

Receipt V2 adds the shared workflow and reservation commitments needed to
audit the ordered cutover. It keeps delivery evidence separate from decision,
effect, and observation evidence. The schema change is intentional because
the original receipt could be finalized only after protected access and
conflated replay with denial.

Existing `auths.records-ledger/1` bytes are obsolete disposable prelaunch
state. Opening them MUST fail closed without changing or deleting the file.
Local development, demos, and CI start the V2 records and lifecycle stores
from empty state.

### 30.6 Cutover evidence

The cutover is complete only when:

- create and read both use the shared lifecycle production path;
- exact domain reference decisions still match the frozen fixtures;
- configuration mismatch and proof denial stop before any lifecycle or
  protected-store mutation;
- final create and read units have one concurrent winner;
- cross-transport replay produces one effect or disclosure;
- crash after call entry reconciles from the exact domain ledger without
  resubmission;
- unavailable reconciliation evidence retains outcome-unknown capacity;
- obsolete V1 state is rejected rather than migrated;
- generated fixtures, domain inventory, compliance claims, and architecture
  snapshots identify the V2 cutover; and
- authoritative CI passes on the exact revision.
