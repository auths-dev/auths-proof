# AP-071 bounded-upfront Google edit: first live attempt

On 25 October 2026, Jules signed a 30-minute task for the separately
registered agent. The task listed two complete native action argument choices
for the disposable Project A Working Doc, allowed one edit and no reads, and
required no second exact confirmation. The agent signed option A. The gateway
admitted it and recorded one Google Docs `batchUpdate` HTTP 200. Its durable
task status showed writes **1/1**, provider calls **0/0** and releases **0/0**.
The task ID was `gvxJlZEwJ4KgGr3MUIX8rupp` and the claimed write operation
was `jSHbCVBfH4EAg8XdkR5LSKML`. No retry was made.

**The exact after-state claim failed independent inspection.** demo_co read
the working Doc with its admin credential. The approved option A sentence
appeared once, but the normalized Doc had 68 bytes before and 78 bytes after
that sentence. The normalized observed content was 236 bytes, while the
approved sentence was 90 bytes. The immediate pre-write generation retained
only a content hash, so the producer cannot prove that those extra bytes are
exactly the old surrounding text. They do not match the original seed
template's outer fragments. demo_co explicitly marked the relation to the
immediate baseline unknown. Canonical Project A and B Docs, the Jules probe
Doc and the two preserved Auths child Docs matched their pinned prior state.

The producer's private redacted failure observation is
`generation-0011/google-write-edit-verdict.json`, SHA-256
`c44a0b9030b846848d4a81a78e3c518d171e24b6177f0e56a5eb1341faecaab6`,
schema `demo-co/google-write-edit-verdict/v1`, status `failed_exact_content`.
Auths verified the file digest and status. The provider 200 and spent write
slot prove entry and accounting, **not** an accepted bounded-upfront effect.

The Google edit recipe replaces one literal marker and deliberately preserves
surrounding Doc text. The workbench wording now states that scope explicitly.
For a clean rerun, demo_co should provision a fresh disposable Doc whose
complete immediate baseline is reconstructable and immutable, then export
the expected marker replacement rule. Auths should issue a fresh task for
that new target and have demo_co compare the exact after-state independently.
