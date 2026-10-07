# Reviewed commissioning references

These are release-only provider references, outside shipping packages. They
neither hold provider credentials nor publish qualification evidence.

`stripe_platform.py` independently derives the platform-account test refund;
`airtable_record.py` derives the dedicated table's one-field update. The
resource carrier is closed, unique, bounded and tied to one protected run.
Only the dedicated owner-authorized Airtable base/table may replace the two
synthetic fixed path members. Every other recipe member and the exact profile
lock must agree with reviewed source, including guards and ceilings.

`expand.py` receives public packet files, resource bindings, the original
candidate binary, tuple and canonical conformance/differential evidence. It
hashes the candidate without executing it. It invokes only a reviewer binary
that the signing job builds from its own checkout, with an empty environment,
through `qualification-candidate` and `review-submission`. No program from a
downloaded artifact runs with a signing key.

Native proof review supplies the exact actors, canonical action commitments
and decoded arguments. The provider reference supplies the expected request.
Their request mappings must agree byte-for-byte before an action enters the
unsigned binding. All actions must have one exact actor, the installed trust
must match, and the lease ceiling is a source-owned 64 acquisitions. The
native issuer separately rechecks both offline artifacts and their mandatory
scenarios before signing. An expansion is neither a live report nor a permit.

```text
python qualification/reference/expand.py \
  --reviewer <binary-built-in-this-signing-job> \
  --candidate <original-candidate-binary> \
  --tuple <tuple.json> --recipe <recipe.json> --profile-lock <profile.lock.json> \
  --resources <resources.json> --packets <public-packets.json> \
  --conformance <conformance.json> --differential <differential.json> \
  --source-commit <exact-commit> \
  --protected-run recipe-qualification/<run-id>/<attempt> \
  --out-dir <new-output-directory>
```

The public packet carrier is `auths.qualification-public-packets/3`, with
`protected_run`, `evaluated_at`, `not_after`, `trusted_contexts` (1–4 sorted
unique adjacent filenames), and 1–64 `packets`. Packet validity is at most five minutes; the
signing expansion reviews native proofs at their recorded offline evaluation
time, within the last two hours. This grants no production clock override.
Each packet contains `label`, `proof`, `action`, `trusted_context` (adjacent filenames), and its
expected `arguments`. Unknown fields, path traversal, changed source, wrong
production targets, resource widening, actor changes or an oracle mismatch
prevent output. Filenames never select code. Private author keys are absent.
The signing expansion reconstructs the entire original source-owned packet
pool, including both phase operations and both fresh-challenge replays. Missing,
additional, reordered or rebound packets cannot receive a permit. A one-packet
refresh is a private execution handoff, never a new signing input.

The protected family setup, complete corpus and live workflow still need to
use these references. No family is qualified by landing this code.

The native commissioning permit is now schema 2. Its closed
`trusted_contexts_sha256` list contains 1–4 sorted unique exact canonical context
hashes. Every installation still authenticates its actual context separately;
all listed contexts share one immutable run/family lease budget. An unlisted
context, duplicate or reordered list, changed set, or schema 1 permit refuses.
The public packet author supplies two native challenges under one exact actor
and grant. Each phase's first resource has a `-fresh` replay packet with the same
logical operation and arguments, under the second context. Refresh never changes
that packet's assigned challenge, action or context. At most 31 Airtable or 29
Stripe resources fit the finite 64-packet ceiling. Stripe also has two exact
guard probes per phase: 1001 cents against a 2000-cent payment, and EUR against
that USD payment. Their native proofs authorize request construction; the real
relative-ceiling read must refuse them after one custody lease and before any
write. A permit never replaces that guard. The grant has bounded USD/EUR sum
partitions so the currency probe can reach the provider-read guard; every
payment remains scoped to the exact reviewed test ledger. Source plan schema 3
refuses obsolete plans. The source-owned
protected corpus and native durable replay evidence still need integration.

`measure.py` validates and subtracts native execution snapshots: matching fresh
scope, no saturation/decrease, no duplicate host in an aggregate. Restarted
engines must be measured separately. Budget consumption is never substituted
for actual custody calls.

`native_observation.py` projects actual native results and measured counter
deltas into corpus facts. A recorded HTTP response or unlinked value match
cannot become a confirmed effect. Linked evidence requires a new independent
provider read with the reviewed exact state/echo and identical raw response
digest. Its bounded journey ledger counts each measured entered write once;
read-only recovery can confirm that earlier write, and subsequent observations
cannot count it again. Changed tuples/actions, scope drift, duplicate entries,
unmeasured effects and additional result fields refuse. The helper does not
assert isolation, installed-consumer provenance or a passing wall; the family
harness must measure those separately and the native runner decides the case.

`fresh_evidence.py` is the separate response oracle for the reviewed Stripe
refund and Airtable update. It validates the approved resource, exact intended
value, test-mode success (Stripe) and the action-derived echo, then hashes the
raw independently fetched response. It accepts no candidate response digest
or locator. Its subject binds the full reviewed request, resource ledger,
action and expected state. The corpus runner compares this fresh witness with
the candidate's own digest. Synthetic unit responses test refusals and exact
bytes; they are not qualification evidence.

### Disposable provider resource lifecycle

`stripe_resources.py` prepares platform-account test payments with `pm_card_visa`
and the run marker `metadata.auths_qualification`. It requires separate test
setup and restricted runtime keys, supplied as closed JSON on private stdin
(`setup`, `runtime`). Each planned intent is journaled before POST and has a
run/index-specific idempotency key. A lost response can be recovered for one
hour with that same key. Cleanup verifies platform, test mode, exact payment,
run marker and charge, refunds only the remaining test balance and confirms
full retirement with a fresh read. Recovering a pending setup during cleanup
may create and immediately retire its one pre-journaled test fixture. It never
uses Connect or a `Stripe-Account` header.

`airtable_resources.py` accepts a personal access token on private stdin
(`token`) and uses only the reviewed dedicated base/table. Before any creation,
it journals the complete run/index-specific `Name` predicate. Exact filtered
fresh reads recover lost creation responses and determine the public ledger;
duplicate names cannot produce a qualification input. Cleanup discovers all
records under that predicate, rechecks ownership immediately before each
delete and confirms their absence. Other records, the table and the base remain.

Both commands take `prepare --protected-run <scope/run/attempt> --count <1..32>
--journal <path> --out <path>` or `cleanup --journal <path>`. The output parent
must already be owner-private mode 0700. Public ledgers never contain tokens,
provider response bodies or payment client secrets. Journals are bounded,
written atomically and retained after partial failure for cleanup. Existing
outputs cannot be replaced. TLS requests refuse redirects and ambient proxies;
provider error bodies never enter diagnostics.

`resource_summary.py` reconstructs the native record's sorted resource names
from the complete closed ledger. Stripe names the test platform and each test
payment; Airtable names the approved base, table and each owned record. The
projection checks run ownership, duplicate IDs, test mode and the native
96-byte name limit. Assembly uses this projection instead of accepting an
arbitrary string list or sorting the ledger object.

Unit cases use synthetic providers, including lost responses, changed ownership,
foreign resources, duplicate records and unsafe files. Actual setup/cleanup
rehearsals are recorded separately and confer no protected qualification.

Stripe's [Refund object](https://docs.stripe.com/api/refunds/object) has no
`livemode` attribute. Test mode is established by the test key/account balance
and the exact freshly checked PaymentIntent and Charge; the refund must bind
that same payment. An unexpected explicit live-mode marker is refused. Unit
responses follow the provider's actual Refund shape.

### Installed author and delayed signing

`packet_plan.py` derives public arguments for separate commissioning/live
operations on each closed resource. It preserves the exact reviewed lock and
the approved recipe substitutions, obtains the native verifier pin and Stripe
bounded extension, and scopes the Stripe grant to these payment identifiers.
No provider credential or caller-supplied argument enters the installed author.

`author_packets.py` must run outside the checkout from an installed wheel, with
only `PATH`, `PYTHONNOUSERSITE` and optional locale variables. It refuses any
additional environment variable before importing the SDK. A fresh native key
authors the single actor, grant, challenge and trust; no private key is exported.
The grant/session lasts at most two hours. Every action keeps the ordinary SDK
maximum of 300 seconds; a protected signing wait must not extend that limit.

With `--serve`, the same isolated process holds its key in memory and accepts
bounded newline-delimited commands on private stdin. A refresh names only an
existing label and the next integer generation (1–1024); it cannot supply new
arguments, authority, actor, challenge or a destination path. It writes into a
new private `refresh-NNNN` directory. The refreshed proof uses current time,
while the canonical action, action commitment, exact grant, request and
installation context remain unchanged. Native context normalization preserves
the installation's request evaluation input; the gateway always rebinds its
own trusted current time. EOF, `close`, expiry, rollback or malformed commands
terminate the process. Keys and tokens are never transferred through artifacts.

`check_packets.py` exercises the real installed author and shipping gateway with
explicitly synthetic resource carriers and no network/provider credential. It
checks both independent request mappings, original five-minute expiry, and an
actual refreshed native proof with the same actor/action/request/trust. CI
retains only its closed report. This is operator/release-tool evidence, not
protected live qualification.

`author_socket.py serve` is the Linux runner connection for that same installed
author. It runs under a dedicated non-root UID, in an owner-private directory,
with the same empty-environment requirement. Its fixed `author.sock` has mode
0600, authenticates kernel peer credentials and accepts only the root operator
controller. `inspect`, `refresh` and `close` reconnect across runner steps;
generation state and the native key stay in the one process. A duplicate launch
cannot replace an existing socket. Refresh accepts only an original label and
copies public proof/action/context bytes into a new private controller directory,
after checking exact original arguments, action bytes, trust and normal validity.
An expired session, changed handoff or malformed command cannot export a packet.

Keep the author's directory outside the publication tree; sockets and private
inputs are never artifacts. `check_socket.py` exercises the actual installed SDK
and shipping gateway under separate Linux UIDs, using synthetic resources and
no provider access. Its report explicitly confers no protected qualification.

`run/artifact_wait.py` is the public mailbox reader for the protected sequence.
It accepts only this repository's main-branch manual qualification workflow,
exact source SHA, run and attempt, and five source-owned artifact roles. It
checks the authenticated run metadata and GitHub archive SHA-256, refuses
duplicates, expired artifacts, another attempt/repository, links, executable
files, traversal and oversized archives, and extracts only bounded public
protocol files with private permissions. Partial extraction is removed.
Missing artifacts are checked every ten minutes within a fixed two-hour
deadline. Only the GitHub Actions token enters the GitHub client; provider and
signer keys are absent from that child's environment. The native issuer/gateway
must still verify every permit/record: a transported artifact grants no authority.
The protected workflow has not yet connected this mailbox to admitted corpora.
