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

## Outcome

Pending the new signed task, separate agent choice, one gateway submission,
and demo_co's independent read-only after-state inspection. The only accepted
effect result is a complete raw export match to the precommitted selected
option with unchanged neighbor checks. A gateway HTTP 200 alone is
`response-recorded`.
