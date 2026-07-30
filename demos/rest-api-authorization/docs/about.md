# About the transport-neutral records demo

## Goal

This demo proves that an agent can call a protected `POST` or `GET` API without
being handed a reusable client API key. A short-lived Auths proof authorizes
one exact typed action, or one action chosen within a bounded records policy.
The service verifies the proof and presenter signature locally before it
touches protected storage.

Changing delivery from HTTPS to Iroh does not change the action, proof,
semantic executor audience, policy, or verifier. It changes only delivery
evidence. Replaying an HTTPS execution over Iroh, or the reverse, cannot
produce a second effect because both paths share one durable action and budget
ledger.

The demo does not claim that credentials disappear from all infrastructure.
If a production records store needs a credential, it belongs behind the
native executor and becomes reachable only after authorization and durable
reservation. The public agent never receives it.

## Future Work

A production records product would separate issuer and verifier deployment,
put issuer keys in audited custody, replace the demo session control plane
with an application-specific grant workflow, and use a transactional
database-backed ledger with explicit reservation leases and unknown-outcome
reconciliation.

It would also add:

- WebAuthn, workload, or hardware-backed presenter identity;
- tenant administration, grant revocation, and policy lifecycle controls;
- rolling-window budget storage with database isolation guarantees;
- multi-region receipt replication and signed receipt transparency;
- explicit downstream credential brokerage after durable claim;
- OpenAPI tooling generated from profile-owned typed actions;
- production HTTP carrier standardization after more vertical evidence;
- Iroh endpoint rotation and relay health monitoring;
- structured privacy and retention policy for disclosed data and receipts;
- fuzzing for HTTP/Iroh decoders and duplicate-member handling;
- failure injection around every persistence and acknowledgement boundary; and
- formal bounded-policy and reservation refinement once the cross-domain
  abstraction milestones identify the genuinely shared semantics.

The current implementation intentionally does not extract generic HTTP
middleware or a generic remote-action executor. Those abstractions would be
premature until several independent API domains prove the same boundary.
