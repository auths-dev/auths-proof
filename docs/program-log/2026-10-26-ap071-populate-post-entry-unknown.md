# AP-071 entered population with a lost response, 26 October 2026

This installed development run tested the case that the earlier population
denial could not cover: Google processes the agent's one approved edit, but
Auths does not receive its successful response. Jules signed one 30-minute
task `g1tig0SWL0OfD_6smee3ljaZ` for the separately registered agent. The
task allowed one pinned Project A source read up to 16 KiB and two writes to
create and populate one Doc in disposable run folder
`1kgl7i0gJZXhALEtBJL8OKGDw5d6UWL0O`. Jules separately signed the exact
two-effect plan before either provider write. The agent received and
acknowledged the 51-byte source, then signed its source-backed draft.

The fixed development gateway SHA-256 was
`68c33f28e561e45c10ffcd35f69d79b330f0a66020b088e11053c2a4bcf9f57f`.
Its new one-use population response-loss arm was bound to the task,
population operation and closed request commitment. The arm is available
only with the development `loopback-provider` feature. It can fire only after
the real transport returns a complete successful 2xx response for an edit to
the task-bound child. It was consumed once and renamed `.json.consumed`.
The normal production build has no such branch.

demo_co independently supplied setup generation 0044 (SHA-256
`22ed079e15c2c965aa8b0c2bec637e466b92c1b94911a516afc46bed985a3a10`)
and a fresh, complete empty-folder baseline generation 0046 (SHA-256
`fa4e65041c085b8bfbbdc44560b39dc071f3c2d77d5d2c4641a3f2c1354c62b5`,
observed 02:34:46 UTC). The earlier generation 0045 had expired and was not
used to authorize create. Auths submitted one Drive create, operation
`7lOSNOci-ZDRnufaY2bPriI1`, which returned `observed` and bound child
`1foIFs7VB5xQIsEUMHYQYjscgDVBZvFXxKV59zpqC-Zw`. demo_co's independent
blank-child generation 0047 (SHA-256
`3c7e0b7d04b3f9eadfb1b0a697deb532f4cc3e5a9a62793f91172dae324041bd`)
found exactly that sole child, the unique marker and one tab. Its raw export
was exactly the three-byte BOM, SHA-256
`f1945cd6c19e56b3c1c78943ef5ec18116907a4ca1efc40a57d48ab1db7adfc5`.

After a fresh Jules child/revision preflight, the separate agent signed the
population action. Auths submitted operation `populate-n_z28TQEcgYIRZll`
once. The successful Google response met the exact development arm and was
discarded before Auths could record it; the gateway outcome was `unknown`.
The task ledger charged both write operation IDs. The local redacted support
bundle showed exactly two write attempts: one `observed`, one `unknown`.
No population retry or pre-entry recovery was made. A live replay submission
was rejected by automatic approval review because it could repeat an already
entered write; this run makes no claim that a second live request was tested.
The task was revoked after inspection.

demo_co's independent read-only generation 0048 (SHA-256
`0d70fdef725a9ee62dd523502ae6fe26d2752d5dd31bfc9743f083bdf58faea8`)
found the same sole child and a changed Docs revision. The complete Google
raw export was the exact approved 148 bytes, SHA-256
`a1fb0c3010e622cee1ac5f85bda4c9865194f2e84bba36196267e2886c2fd54d`.
It found no run marker in the content and no change to the bounded-upfront
Doc, frozen seven Docs or canonical Project A/B state. The producer attests
provider state only; it does not attest Auths entry or authorize retry.

Auths vendored and pinned the new producer observation schema, validated the
four producer generations and joined them to the signed plan, one-use arm,
redacted gateway support bundle and revoked task ledger. The private strict
join at `/private/tmp/ap071-postentry-20261026/strict-post-entry-join.json`
returned `accepted`, `population_outcome: unknown`,
`provider_state: exact_populated`, and `retry_authorized: false`; its SHA-256
is `aaa9333f381cd0406551288f5bef3ef997f845e271d7c69271168241509a5a4b`.
This result establishes the fail-closed handling of this entered population
with lost response. It does not turn an unknown response into a gateway
success receipt. Full AP-SPEC-071 acceptance still requires its remaining
hostile and production qualification gates.
