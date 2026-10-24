# Gateway HTTP leaf contract

Status: implementation and wire-oracle code written; validation pending.
This records AP-SPEC-069 §6.2's transport boundary. It is not a completed
qualification or a claim about provider-side business effects.

The source owner is `product/runtime/auths-gateway/src/transport.rs`. The
production path is `GatewayHttpTransport::prepare` → `pinned_client` →
`GatewayHttpTransport::write`, through the submission's leased transport.
The oracle is `product/runtime/auths-gateway/src/transport_wire_tests.rs`.
The exact resolved dependency graph must be recorded from `Cargo.lock` at the
final release gate; the currently inspected reqwest source is version 0.13.4.

## Required behavior

1. The recipe and connection credential requirements must agree. Production
   origins are approved HTTPS DNS origins on port 443. Preparation resolves
   before secret access, refuses an empty result or any non-public IPv4
   result, selects a public IPv4 address and pins that address for the client.
   Unselected IPv6 records do not create a fallback route. The compiler's
   origin/hostname validation and the address classifier remain part of the
   input boundary.
2. Every outbound URL must belong to the approved origin, contain no query,
   fragment or user information, and equal its parsed URL serialization.
   Dot segments, backslashes, raw whitespace and other parser rewrites are
   refused before credential exposure and request construction. Escapes that
   the URL parser retains are sent verbatim. What a provider subsequently
   does with an encoded separator is provider behavior, not a proved path
   interpretation.
3. The client requires HTTPS, disables proxies and redirects, and explicitly
   disables reqwest's retry policy. The prior absence of retry configuration
   left the library's default safe protocol-NACK retry behavior enabled.
   Disabling it expresses Auths' stronger no-automatic-write-retry contract;
   it is not evidence that the previous library retried an entered write.
4. TLS uses the approved hostname and normal production certificate roots.
   Certificate and hostname validation precede sending HTTP headers/body.
   Secret bytes may already exist in the in-process request header before a
   handshake completes; this contract does not claim otherwise.
5. The transport sends the exact closed method and body, one declared content
   type, the declared recipe headers, the credential header, `Accept`, `Host`
   and body framing headers. A recipe cannot supply transport-owned headers.
   Credential bytes are nonempty, bounded to 4,096 bytes and printable ASCII
   without whitespace. Their header is marked sensitive. Request-library
   copies are not claimed to be zeroized.
6. The connect timeout is five seconds and the complete transport deadline is
   fifteen seconds. The write response is bounded to 65,536 bytes. Read
   response limits come from the approved recipe and are checked while
   accumulating chunks. Response version headers must each occur exactly
   once with the approved value.
7. Rejection before `execute` is definite non-entry. Any execution error or
   incomplete/oversized write response is conservatively unknown. A complete
   HTTP response, including a redirect/error response, is recorded without
   following it. Neither unknown nor an HTTP error grants write retry.
8. Security-bearing provider JSON is parsed through the same unique-member
   check as recipe source/lock documents. Account and credential probes,
   relative-ceiling basis/binds, response locators, read-back value/echo and
   pre-entry signed facts reject duplicate decoded member names anywhere in
   the document. A duplicate escape spelling also fails; identical names in
   different objects are allowed. A rejected document supplies no fact.
   Stored observation expected-values use the same check. Input byte bounds
   remain with each caller and serde's recursion limit is retained. Numbers
   retain serde_json's typed interpretation; integer-only checks do not coerce
   fractions or exponents, and ceiling/locator integers are bounded to
   2^53 − 1. Object keys compare their decoded strings without Unicode
   normalization. Malformed Unicode and trailing documents are refused by
   the parser. The parser's actual source refinement remains an E3 obligation.
9. Native write dispatch receives the original immutable verified command.
   The driver consumes its single-use permit before checking the captured
   command's deadline again. The HTTP leaf then builds the bounded request
   and invokes the native entry-time gate before its execution witness and
   `execute`, with no intervening await. It also rechecks the exact lease's
   deadline after request construction. The full time gate checks each
   original authority/prepared/current installation endpoint, present clock
   and qualification samples, no clock rollback, and at most 60 billion
   monotonic nanoseconds. A fractional excess refuses. A late deadline
   refusal retains the existing `gateway.attempt.entry-deadline` outcome;
   the durable claim/slots remain consumed. Leased read ports expose only
   read operations; production has no unguarded leased-port write method.
   Clock acquisition, scheduling between synchronous instructions, runtime
   and physical I/O still retain their explicit external contracts.

## Independent wire oracle

The new oracle uses a local rustls HTTP/1 peer and reads raw decrypted bytes
with the standard I/O traits. It does not use Auths' request renderer, a URL
parser, reqwest, or an HTTP server framework to interpret those bytes. The
client uses the same `pinned_client_builder` as production. Only its DNS
admission target and root trust are replaced: a local socket and a fresh
test-only certificate. No custom trust root is exposed by the production
constructor.

Written cases cover:

- the exact method, independently stated path, body bytes and JSON string
  meaning, including quotes, backslashes, control characters and Unicode;
- unique credential, content-type, accept, host, content-length and declared
  headers, with an exact inventory of default header names;
- literal percent escapes, encoded separators, double encoding and encoded
  UTF-8/query/fragment characters;
- refusal of dot-segment, encoded-dot, backslash, whitespace and Unicode URL
  normalization before an HTTP request reaches the peer;
- no second provider request after a 307 redirect or a disconnect after the
  peer has received the request;
- certificate-trust and hostname failures exposing no HTTP request, and the
  HTTPS-only client refusing plaintext before opening a socket;
- compiler rejection of recipe headers that shadow transport-owned fields.
- a final entry-gate refusal after request construction, with no TLS or HTTP
  entry and an unchanged execution witness.

All cases are unrun. They exercise the HTTP/1 policy on the resolved test
stack, not every possible protocol/library/feature combination. Final review
must inspect the actual enabled protocol/features and cover each production
path, including any additional protocol-NACK handling. DNS classification,
OS routing, trust-root administration, TLS implementation correctness,
cancellation, scheduler behavior and secret-memory isolation retain their
declared runtime contracts. These cases do not establish the full native
verifier, recipe compiler, async-driver or concurrent backend refinement.

The preceding claim, aggregate reservation, lost-acknowledgement, collection and
first-capture evidence is mapped in [the admission/history boundary](ADMISSION_HISTORY_BOUNDARY.md).
Its new scripts and backend case remain unverified and do not close this
document's driver or physical-entry obligations.
