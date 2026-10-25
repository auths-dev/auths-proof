# AP-071 installed Airtable read and exact-write conformance

On 25 October 2026, the development operator ran the checked-in Airtable
GET-release and PATCH recipes against the dedicated disposable base
`appQD3Qf0YFBCW9bV`, table `tblBx2jwe0IsPYRKT`. The run-owned record was
`recY02Wyc4QHZ6x2Y`; its ownership journal was written before creation in
`/private/tmp/ap071-airtable-live-20261025-1747`.

The operator issued one task with a synthetic human key and separate agent
key, bound to the operator PAT account label, the exact record, one read,
64 release bytes, one write and exact confirmation. The agent signed the read
and served a separate authenticated local release channel. The gateway
reported `agent-acknowledged` for operation `airtable-read-one` and charged
one provider call, one release and seven bytes. The agent received the
private `DemoStatus` value, and `task-release-compare` matched its private
source file to the gateway's keyed release commitment. Neither the value nor
an unkeyed hash appears in the redacted result.

After an operator-side fresh GET, the agent signed an exact PATCH proposal to
set that same record to `Approved`. The synthetic human key signed the exact
confirmation. The gateway charged one write for `airtable-write-one` and
returned `observed-by-provider`. A separate operator GET saw the run-owned
record with `DemoStatus=Approved` and a nonempty gateway echo. The private
redacted result is `operator/redacted-result.json` under the run root; it
records the task ID `pifwUZ1LkUdUgXSEQq_Xs4Ii`, operation IDs, budgets,
outcomes and an independent-readback verdict without PAT or field bytes.

The cleanup command reread the owned record, deleted only that record, and
verified that the run-owned name no longer appeared. The journal's `retired`
flag and the result's cleanup field are both true. The base and table were
retained.

Before task expiry, the separate agent signed a fresh read action reusing
`airtable-read-one` against the already consumed task. The gateway returned
`not-entered` with `gateway.release.task-admission`. Status after that probe
still showed one provider call, one acknowledged release, seven bytes and one
write. The authenticated channel received no second content frame. This is
one installed replay denial with zero additional provider requests, not the
full hostile corpus.

A second disposable run (`/private/tmp/ap071-airtable-negative-20261025-1804`)
put an agent-signed read for a different record through the installed gateway
before the permitted read. It returned `not-entered` with
`gateway.release.scope`; status still showed zero provider calls and zero
releases. The permitted read and exact PATCH then succeeded with one provider
call, one acknowledged release, seven bytes and one observed write. The
independent readback passed and the second run-owned record was retired.

This proves one installed second-provider task/read/exact-write mechanism
using the same native gateway path. The Airtable PAT is an operator credential
with no demonstrated human subject, so this run does **not** prove a second
employee's account delegation. The agent used a distinct key and process,
but this development run did not isolate it under a different OS user. It
does not complete the full negative matrix, production custody or the Google
single-plan create/populate acceptance.

An additional disposable run
(`/private/tmp/ap071-airtable-lost-ack-20261025-1825`) used a separate agent
process that saved the seven exact release bytes, then closed its Unix socket
without signing the acknowledgement. The gateway returned
`delivery-unknown`, charged one provider call, one release and seven bytes,
and retained that stage after the agent process exited. A second authenticated
channel attempted the identical signed operation; native task admission
returned `not-entered` with `gateway.release.task-admission`, sent it no
content and left all counters unchanged. The run-owned record was retired.
Its redacted result is `operator/redacted-result.json` under that root. This
proves the lost-ACK accounting and same-operation replay refusal in the
installed Airtable path; it does not prove the agent used the bytes.

A fourth disposable run (`/private/tmp/ap071-airtable-recipient-20261025-1950`)
attempted to sign a read addressed to a principal other than the registered
agent before the permitted read. The separate agent signer refused to produce
a proof or action; the gateway task still showed zero provider calls and zero
releases. This is an agent-side refusal, not a claim that a forged low-level
proof reached the gateway. The subsequent permitted read was acknowledged,
the exact confirmed write had independent provider readback, and the
run-owned record was retired. The redacted result records one provider call,
one release of seven bytes and one write. The gateway's separate synthetic
recipient-mismatch case covers a forged proof at its native admission
boundary.

A fifth disposable run
(`/private/tmp/ap071-airtable-wrong-recipe-20261025-2201`) used gateway binary
SHA-256 `f17084b2796ba7deee148814054f1b3f50beeb8af5ab4e401359fe8ee50460a7`.
The distinct agent signed a read action carrying a changed recipe digest
through its public task package. The installed gateway returned `not-entered`
with `gateway.release.native-proof`; task status was unchanged from its
zero-call, zero-release state. The allowed read then reached Airtable, was
acknowledged by the agent and charged one provider call, one release and
seven bytes. The exact confirmed PATCH was observed by the provider, and an
independent operator GET confirmed the approved value and gateway echo. The
run-owned record `recltn8I6tC22UfSo` was retired; the ownership journal has
`retired=true` and the redacted result reports verified cleanup. This adds an
installed wrong-recipe refusal without claiming the full §6 corpus is done.
