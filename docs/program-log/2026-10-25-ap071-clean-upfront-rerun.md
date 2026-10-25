# AP-071 clean bounded-upfront edit rerun

The first Jules-signed upfront run spent one write and received Google HTTP 200,
but its independent readback could not prove the exact approved after-state.
The marker replacement appeared once with unexpected surrounding text. This
rerun uses a new disposable Project A Doc and retains the failed result as a
separate observation.

## Precommitted state

demo_co created `Demo Co AP-071 Project A Clean Edit Rerun` under the existing
Project A folder. Its private, immutable generation 0013 export pins Google
Doc `1No9AogHOiVqVgtZ1Qa5TTxpY81YZffzfhIIK8NkqS_A`, one tab, Jules's
`canEdit` capability, a 39-byte raw text export comprising BOM and one marker,
and SHA-256 `ee05eaa34ced2313dd067adcc4a8b74c17662203cf558ffe9f7b3387526edcbc`.
It also pins the canonical Project A/B, Jules probe, both prior Auths child
Docs, and the old working Doc as unchanged. The generation 0013 artifact is
pinned by SHA-256 `ef3f82b6fbdc12a5464fae5e1ee9f2b0f5522a187fc3d26cb8f9cc766fed4381`.

Before a new Jules signature, demo_co exported generation 0014 with both
complete expected raw after-state hashes. Option A is 93 raw bytes and SHA-256
`a44c4cb6fcfa3af4b7a82357faa36f1e57f9664b305226b4badc1e6fbdf196ed`;
option B is 93 raw bytes and SHA-256
`921c63c11a96a7a30afd3f51c1be8a19f9d802e27c6cbbb37394fde43034cb7a`.
The generation 0014 artifact is pinned by SHA-256
`d0aa6e8b2eb01231ad4201ecefefd33490a3cd92361c89e0be33fad6f19723b1`.
The Auths consumer reconstructs and checks the complete raw baseline and both
expected after-states; it refuses a changed digest, schema, identity, folder,
marker, byte count, or option text.

Auths issued a fresh one-hour operator authority and installed a new
subject-checked, short-lived Jules `drive.file` credential in a private gateway
state. A live read-only Jules preflight before task signing matched the pinned
39-byte baseline, one marker, `canEdit` capability, one tab, and exact Jules
revision. The broker suite passed 136 tests including the consumer's tamper
case. These are setup checks; no new human delegation or Google write has yet
occurred in this rerun.

The branch-built broker wheel SHA-256 is
`46f3b5b003512aef07e860258500a9853cd68db30ff8d1db44b6f15293f13a28`.
The branch-built agent wheel SHA-256 is
`766ed92164813381f46122382da0551876b4e421317c8c33a42c39e169f37f6c`.
An isolated `--no-deps --no-index` install loaded `employee_read_demo` from the
wheel target, confirmed both pinned rerun schemas and the consumer module were
packaged, and accepted the private generation 0013/0014 snapshots without the
repository source path. It also loaded `employee_read_agent` from its separate
wheel. The installed workbench parsed the complete live launcher and built its
rerun configuration with the listener replaced by a no-op. This checks package
contents and startup contract compatibility; it is not the live installed
Google run.

After the live finance denial, a read-only task activity control fix was
packaged into an updated broker wheel with SHA-256
`311ec7176db308cf040dbd5951be79603576fdacaf461677af67b98500c1fcaa`.
That wheel and the unchanged agent wheel were installed in a separate target.
The updated broker started the Jules workbench from that installed target;
the Chrome Incognito page showed the precommitted marker, complete option A
and B replacements, same target Doc and revision, the distinct agent, zero
reads and one allowed write. This is a refreshed review card only. No new
Jules signature or Google write occurred at that point.

## Outcome

Jules signed task `G-uUZcqy3F45L5NLBweYvjoY` in the installed Chrome
Incognito workbench for the registered, separate agent, the one disposable
Project A Doc, both complete precommitted choices, and a single bounded-upfront
write. The task grants no read. The separate agent signed option A as operation
`ZwgkCTXm6P95chCVO3YsgUMY`; Auths staged its proof and action without
provider entry. The workbench's submit path performed a fresh Jules Google
preflight, then submitted that signed action once. The gateway returned
`response-recorded` with Google HTTP 200. Its durable task status shows
`writes=1/1`, `provider_calls=0/0`, `releases=0/0`, and that one operation ID.
The screenshot of the gateway result and activity is retained privately as
`gateway-response-live.png` under the rerun work directory.

demo_co then ran its independent read-only inspection and produced immutable
generation 0015 `google-edit-rerun-observation.json`, SHA-256
`59e5ee1bf9efaef6592ad2d448ea370e7b7d89a85c6acd9f5df073dfaa617900`.
It observed the same owned Doc in the exact Project A parent, tab `t.0`, and
a nonempty admin revision. The **complete** raw export is 93 bytes with SHA-256
`a44c4cb6fcfa3af4b7a82357faa36f1e57f9664b305226b4badc1e6fbdf196ed`,
equal to precommitted option A and unequal to option B. The original marker
count is zero. The direct child count stayed five; the canonical Project A/B
Docs, Jules probe, both prior Auths child Docs, and old working Doc were
unchanged against their producer pins. The observation's attribution is
`provider_state_only`; its admin revision is not treated as Jules's revision.

Auths copied the immutable generation to private custody, validated its
schema and pinned digest, and joined it to the signed task, agent-signed option
A operation, gateway attempt `response-recorded` HTTP 200, and durable
`writes=1/1` task ledger. The gateway attempt timestamp precedes the producer
observation. This supports the exact bounded-upfront edit outcome, with the
earlier failed run retained as a separate failed observation. The off-choice,
second-write, and exact-confirmation-only policy refusals remain separate
acceptance cases; this positive result does not prove those denials.

The final branch-built broker wheel is SHA-256
`fe3ddf343057636e6d66ca9736b4b22f7be5f52bd6bd62052a8357abb49aed0e`.
An isolated install of that wheel and the unchanged agent wheel loaded both
packages from its install target, not the repository source path. Its strict
consumer accepted the private generation 0013 baseline, generation 0014
choices, and generation 0015 observation against the pinned artifact hashes,
signed task start time, exact document ID, option A's 93-byte complete raw
export, and unchanged-neighbor verdicts. The broker's full 136-test suite
passed with local loopback sockets enabled; `git diff --check` passed.
