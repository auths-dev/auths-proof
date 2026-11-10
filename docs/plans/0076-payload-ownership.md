# AP076 D1 payload ownership

The translated `auths_gateway_kernel::order` still selects every action and
`GatewayAttempts` still owns durable transitions and acknowledgements.
`submit::Run` now holds either Unverified or Verified authority with a closed
claim phase: Unclaimed, Claimed, Leased, EntryGranted, Response, Unknown, or
Unavailable. Only EntryGranted carries a lease, claim and acknowledged one-use
permit together. Send consumes that phase and moves the claim into Response or
Unknown; response recording cannot run without its captured response. Invalid
internal action/payload combinations fail closed and cannot call transport.
Unavailable retains no entry capability; the durable journal resolves a lost
acknowledgement. Independent recipe options and the counted in-flight guard
remain independent facts, not duplicate transition authority.

MutationState now owns phase-specific refusal, complete response, comparison,
or provider observation payloads. Observed requires a complete response and a
closed Match/Mismatch/EchoMismatch reading. ObservedByProvider requires provider
evidence; an absent original response remains an actual unknown send rather
than a malformed half-response. Recovery links and created-resource identity
remain bound to the native recovery fence and existing validation. Acquisition
and disclosure retain their separate payload-bearing phases and domain meaning.

The single existing canonical wire shape is preserved deliberately. MutationWire
is only a bounded decoding/encoding projection: it is never retained as a
shipping lifecycle state and cannot perform a transition. Decode constructs a
closed phase or rejects inconsistent field presence; encode derives every field
from that phase. This is one codec, with no legacy decoder, migration, alternate
wire reader or dual journal. Canonical byte equality and native transition rules
remain independently checked. A structural field-presence corpus compares exact
serialized bytes and rejects half-responses, missing readings/evidence and
foreign fields. Existing native mutation, fault, recovery, file/TLS PostgreSQL,
late-evidence and translated transition corpora remain required final evidence.
No test execution or formal qualification is claimed by this design record.
