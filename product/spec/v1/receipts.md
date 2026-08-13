# Auths Decision, Execution, and Audit Receipts V1

Decision receipts record the proof, canonical action, verifier context,
principal-status snapshot, grant-status snapshot, profile, three-valued
decision, stable reason codes, and decision time. Execution receipts are
separate objects that bind a decision receipt ID, non-reusable execution lease,
verified command digest, outcome, optional result digest, and completion time.

The content identifier of either receipt is derived from its canonical
unsigned record. Stored and exported receipts are verifier-attested envelopes:

```text
protocol major
receipt kind
canonical receipt bytes
verifier principal
verification-method identifier
signature-suite identifier
signature bytes
```

The signature preimage has a receipt-kind-specific domain followed by
length-prefixed verifier, method, suite, and canonical receipt bytes. Runtime
signing is an external effect; the runtime never owns the private receipt key.
An unavailable signer produces no partially attested receipt and prevents
execution where receipts are configured fail-closed.

Offline verification has two distinct stages:

1. strict canonical decoding, content-ID checking, and decision/execution
   linkage;
2. signature verification against verifier-local expected identity, key, and
   registered signature suite.

Audit bundles contain the attested decision, linked attested executions, and
sorted disclosed or digest-only artifacts. A redacted artifact retains its
media type and digest. A disclosed artifact must reproduce that digest.
Duplicate identifiers, mutation, non-canonical bytes, excessive collections,
and executions linked to another decision fail closed.

## Bounded disclosure and inert inspection

Receipts remain commitment-only. Exact commands, provider results, customer
identifiers, and operational details are not embedded in the signed receipt.
An application may separately retain a canonical `ReceiptDisclosure` bound to
one execution receipt ID and profile. The disclosure has strict command and
result size limits and must be protected and stored under an application-owned
tenant boundary. Auths defines protector and store ports; it does not own
encryption keys, databases, retention, or access policy.

Inspection is Rust-owned and effect-free. Before returning any view, the native
implementation verifies both receipt attestations, their content identifiers,
decision/execution linkage, expected signers, the disclosure's receipt and
profile bindings, and the command and result commitments. Maintained profiles
own the safe projection from exact canonical material to human-readable fields.
Bindings only map the native result into language-native immutable values.

The public inspection contract has three views:

- `opaque`: verifies the signed receipt pair and returns identifiers, profile,
  outcome, signers, and commitments. It does not require, load, or reveal a
  disclosure.
- `summary`: additionally verifies the disclosure and returns only the
  profile-owned bounded projection. It never returns exact command or result
  bytes.
- `full`: returns that same projection plus the exact verified canonical
  command and optional result bytes for callers already authorized by the
  application.

Every successful value is inert metadata. It is not a grant, approval,
authorization ticket, executable command, provider credential, or native
effect-capable handle. Missing, malformed, oversized, non-canonical, mutated,
cross-profile, cross-receipt, or incorrectly signed inputs produce stable typed
failures and no partial view. The application must authenticate the viewer and
select `opaque`, `summary`, or `full` before asking Auths to inspect; transport
or successful decryption never grants viewing authority.
