# Auths Proof Exchange Networking Profile V1

**Status:** Proposed companion profile  
**Core protocol relationship:** Optional and non-normative for
`auths-proof` verification  
**Profile version:** 1

## 1. Purpose

This document specifies the boundary between the pure `auths-proof` kernel and
applications that exchange proof-bearing actions over a network.

The architectural rule is:

> Networking is a proof-exchange port. Iroh, HTTPS, TLS/TCP, Unix sockets, and
> test channels are adapters.

This is a separate port from `PrincipalControlVerifier`:

- principal adapters prove control of an Auths principal;
- transport adapters deliver challenges, action bodies, proof bundles, and
  application responses;
- the Auths verifier proves delegated authority;
- the application applies transport policy, consumes challenges, and decides
  whether to execute.

No conforming Auths verifier needs a network implementation. A `ProofBundle`
has identical meaning whether it arrived through Iroh, HTTPS, a file, or an
in-memory test.

## 2. Layering

```text
+-------------------------------------------------------------+
| Application                                                 |
| replay state | execution | local policy | audit             |
+-----------------------------+-------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| Proof-exchange protocol                                     |
| challenge | bounded submission | peer observation | response|
+-----------------------------+-------------------------------+
                              |
                +-------------+-------------+
                |             |             |
                v             v             v
             Iroh          HTTPS         in-memory
          EndpointId    TLS identity       tests
                \             |             /
                 +------------+------------+
                              |
                              v
+-------------------------------------------------------------+
| auths-proof                                                 |
| decode -> verify principal control -> attenuate -> verdict  |
+-------------------------------------------------------------+
```

The proof-exchange implementation may depend on async runtimes and networking
libraries. `auths-proof-model`, `auths-proof-codec`,
`auths-proof-adapter-api`, `auths-proof-author`, and
`auths-proof-verifier` must not depend on it.

## 3. Semantic port

The port models an Auths exchange rather than generic sockets:

```rust
pub trait ProofExchange {
    type Error;
    type Channel: ProofChannel<Error = Self::Error>;

    async fn open(
        &self,
        target: &TransportTarget,
    ) -> Result<Self::Channel, Self::Error>;
}

pub trait ProofChannel {
    type Error;

    fn peer_observation(&self) -> &PeerObservation;

    async fn receive_challenge(
        &mut self,
    ) -> Result<ActionChallenge, Self::Error>;

    async fn submit_action(
        &mut self,
        request: AuthorizedActionRequest,
    ) -> Result<ActionResponse, Self::Error>;
}
```

These signatures are design sketches, not part of the stable Rust API. The
normative properties are:

1. The client receives an application-issued challenge before authoring the
   action.
2. The request carries the exact action body and complete `ProofBundle`.
3. Every incoming field is bounded before allocation or cryptographic work.
4. The channel exposes what transport peer, if any, it authenticated.
5. Transport failure is not an Auths verdict.
6. The application executes only after Auths returns `Authorized` and all
   additional application and channel-binding policy passes.

Do not introduce a generic `Network`, `Socket`, `Stream`, or `RpcClient` trait
into the proof kernel.

## 4. Exchange state machine

```text
Client                                      Service
  |                                            |
  |------------ open authenticated channel --->|
  |                                            |
  |<----------- ActionChallenge ---------------|
  |                                            |
  | author exact body and ProofBundle          |
  |                                            |
  |------- AuthorizedActionRequest ----------->|
  |                                            | bound parse
  |                                            | atomically claim challenge
  |                                            | verify Auths proof
  |                                            | apply transport/app policy
  |                                            | execute or refuse
  |<-------------- ActionResponse --------------|
```

The states are:

1. `Connected`
2. `ChallengeIssued`
3. `SubmissionReceived`
4. `ChallengeConsumed`
5. `Verified`
6. `Completed`

The service must reject:

- submission before a challenge;
- a challenge unknown to the service;
- an expired or previously consumed challenge;
- a body or proof above configured limits;
- more than one submission for a single-use exchange;
- an Auths action whose audience, challenge, body digest, or time does not
  match the service's explicit verification context.

Challenge claiming and consumption require state outside `auths-proof`.
Exactly-once execution is not provided by this protocol.

## 5. Messages

The semantic messages are:

```rust
pub struct ActionChallenge {
    pub exchange_version: u16,
    pub challenge: Challenge,
    pub audience: Audience,
    pub expires_at: Timestamp,
    pub max_body_bytes: u32,
    pub max_proof_bytes: u32,
}

pub struct AuthorizedActionRequest {
    pub body: Vec<u8>,
    pub proof: Vec<u8>,
}

pub struct ActionResponse {
    pub request_id: Option<[u8; 32]>,
    pub outcome: ExchangeOutcome,
}
```

`ExchangeOutcome` distinguishes:

- a completed application response;
- application refusal after an Auths verdict;
- malformed or oversized exchange input;
- expired, unknown, or consumed challenge;
- transport-policy rejection.

It must not manufacture `Authorized`, `Denied`, or `Indeterminate` when the
Auths verifier did not run. When a verifier did run, the application may
return a safe projection of its stable decision and reason codes.

The body remains outside the `ProofBundle`; the Auths action commits to its
digest. Applications define body canonicalization. A service must verify and
execute the same bytes.

## 6. Framing

Stream transports use one length-delimited frame per semantic message:

```text
u32 big-endian payload length
payload bytes
```

Requirements:

- read the four-byte length before allocating the payload;
- reject a declared size above the message-specific limit;
- reject truncated frames and trailing bytes;
- configure deadlines for challenge, submission, verification, and response;
- allow only one challenge and submission on the simple V1 stream;
- do not decompress untrusted messages in V1.

The initial Iroh payload encoding should use closed, deterministic CBOR maps
with integer keys. Freeze that schema and add golden vectors when the
companion exchange repository is implemented. HTTP adapters may map the same
semantic messages to an HTTP request/response without preserving stream
framing.

## 7. Peer observations and channel binding

Transport authentication is typed:

```rust
pub enum PeerObservation {
    IrohEndpoint([u8; 32]),
    CertificateFingerprint([u8; 32]),
    UnixPeerCredentials {
        uid: u32,
        gid: u32,
        pid: Option<u32>,
    },
    ServerAuthenticated,
    Unauthenticated,
}
```

The list is illustrative and may grow in the exchange crate without changing
the Auths proof protocol.

An application selects an explicit policy:

```rust
pub enum ChannelBindingPolicy {
    None,
    RequireAuthenticatedPeer,
    RequireSignedSenderBinding,
    RequireSignedRecipientBinding,
}
```

For a signed binding, the application action profile commits to the endpoint
identifier as part of the exact body or a profile-defined signed field. The
application compares that commitment with `PeerObservation`.

Transport identity is an additional condition:

```text
Auths verdict == Authorized
AND
channel-binding policy == satisfied
AND
application execution policy == satisfied
```

It is never valid to infer:

```text
authenticated Iroh/TLS peer => Auths Authorized
```

Nor may equal public-key bytes silently make an Iroh `EndpointId` and an Auths
`PrincipalRef` equivalent.

## 8. Iroh adapter profile

Iroh is the first recommended network adapter for agent, edge, mobile, and
device-to-device applications.

The V1 adapter should:

- use a versioned ALPN, initially `/auths-proof/action/1`;
- wait for the authenticated connection handshake before accepting an
  authorization-bearing message;
- obtain the remote `EndpointId` from the connection and expose it as
  `PeerObservation::IrohEndpoint`;
- run the V1 challenge/submission state machine on a bidirectional QUIC
  stream;
- enforce framing limits before decoding the `ProofBundle`;
- disable authorization-bearing use of 0-RTT because of replay risk;
- surface path, discovery, and relay failure as transport errors;
- produce the same Auths verdict as every other adapter for identical proof
  and verification-context inputs.

Iroh and Auths keys should be separate by default:

- an Iroh endpoint key authenticates an online network endpoint;
- an Auths signing key proves approval of exact Auths signing bytes;
- an Auths trust-anchor key may have a different, often offline, custody
  model.

Applications may deliberately reuse a key only through a documented profile
and threat analysis. Reuse is never required by this networking profile.

Public Iroh relays are suitable for development, not as an assumed production
dependency. Production operators must choose managed or self-hosted relays
and account for availability, traffic analysis, connection metadata, and
upgrade policy.

## 9. Other adapters

### In-memory

The first conformance adapter. It must exercise the complete state machine,
limits, replay behavior, and error separation without sockets.

### HTTPS

Useful for conventional service infrastructure. Server-authenticated HTTPS
does not authenticate the client. Client identity, when required, must come
from mTLS or an explicit application mechanism. Auths proof verification
remains unchanged.

### TLS/TCP

Acceptable where a streaming protocol is needed. Raw unauthenticated TCP is
not the recommended production configuration. The adapter must report
whether it authenticated neither peer, only the server, or both peers.

### Unix socket

Useful for local agents and sidecars. Peer credentials are local operating
system observations, not Auths principals.

### Message buses

Kafka, NATS, and similar systems may carry the same body and proof, but their
challenge and replay model differs from an interactive channel. Add such an
adapter only with an explicit profile for nonce issuance, delivery retries,
and duplicate consumption.

## 10. Error separation

The implementation maintains three namespaces:

```text
TransportError
    discovery, connection, TLS/QUIC, timeout, reset

ExchangeError
    framing, size, sequence, expired/consumed challenge

TrustVerdict
    Authorized, Denied, Indeterminate with Auths reason codes
```

No mapping may turn `TransportError` or `ExchangeError` into an Auths
`TrustVerdict`. Transport or application policy may reject after an
`Authorized` verdict, but it may never upgrade a non-authorized verdict.

## 11. Conformance requirements

Every transport adapter must pass a shared suite covering:

1. valid challenge and authorized action;
2. denied and indeterminate proofs preserved unchanged;
3. malformed and oversized frames;
4. expired, unknown, and replayed challenges;
5. timeout and early disconnect;
6. multiple submissions on a V1 stream;
7. peer observation accuracy;
8. optional sender and recipient channel binding;
9. identical Auths verdicts across in-memory, Iroh, and any other adapter for
   identical verifier inputs;
10. proof bytes transported without mutation.

The Iroh adapter additionally tests direct and relayed paths, connection
migration, wrong Endpoint IDs, relay unavailability, and rejection of
authorization-bearing 0-RTT.

## 12. Strict boundary

The exchange layer does not own:

- Auths authority or attenuation semantics;
- principal-control adapter selection;
- generic service discovery;
- key generation or custody;
- production relay infrastructure;
- application execution;
- audit storage;
- exactly-once delivery;
- budgets, quotas, or rate limits;
- a general RPC framework.

If a feature does not improve bounded exchange of a challenge, exact action
body, `ProofBundle`, peer observation, or application response, it does not
belong in the proof-exchange port.

## 13. References

- [Iroh endpoints and endpoint identifiers](https://docs.iroh.computer/concepts/endpoints)
- [Iroh application protocols and ALPN routing](https://docs.iroh.computer/concepts/protocols)
- [Iroh endpoint hooks and peer observation](https://docs.iroh.computer/connecting/endpoint-hooks)
- [Iroh public relay limitations](https://docs.iroh.computer/iroh-services/relays/public)
- [Iroh security and privacy considerations](https://docs.iroh.computer/deployment/security-privacy)
