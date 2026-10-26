# AP-071 bounded-upfront Google refusals, 26 October 2026

This run used one disposable marker-only Doc in demo_co's Project A scratch
root. The producer created and pinned the fixture; Auths did not provision or
reset it. No canonical Project A or Project B file was edited.

## Installed pins and task

- demo_co baseline generation 0041 SHA-256
  `daa6e57826e2f23863e01903a5dc73a7c0d997e11c34950437febaeba6d439a0`;
  choices generation 0042 SHA-256
  `763fcb826a7db418b6c5752efaedc63814199436c38902735825bfee27522597`.
  Their vendored schemas are pinned by SHA-256 in the Auths consumer.
- The fixture is Doc `1Kus0s2X23vGembjUxWWDqQCVALVQdvgFNR8A5-mCzGM`,
  a child of scratch root `13WCvt0UcXhuLq0KgoxkYtrltmTGT499F`. The
  pinned initial raw export was 37 bytes; its content digest remains in
  private verifier custody.
- Auths installed Jules's subject-checked `drive.file` credential in
  development connection `conn_IbUzmZ3xo6c8b3SEI82OBA`, generation 1. The
  fixed gateway binary SHA-256 was
  `8c663e4021f3f0469bebf708b1afecde11b5208d82d95f43a959215253415b1d`.
  The bearer remained in operator and gateway custody.
- In Chrome Incognito, Jules signed task `Tp4vzXC8GLiRQ-ukYhzLgvKJ`
  for registered agent
  `key:sha256:ngUKlHElrvbAobws4WACYio2L-BiqqMomEfMMeCK0dk`. The task
  allowed no reads or creates and **one** marker replacement in that Doc,
  selecting one of the two complete displayed texts within 30 minutes.
  Company policy explicitly allowed bounded-upfront mode. There was no
  second exact-write signature for the selected choice.

## Three separate agent actions under that one grant

1. The agent signed an unlisted option C (`RVbUCi-IsIZHbOFR836UYJRz`).
   `task-submit` returned `not-entered` with
   `gateway.task.upfront-arguments-not-approved`. The task journal stayed at
   zero writes and zero provider calls.
2. The agent signed listed option A (`cMqWZ2OnRMJckHmquLdYxVYi`). The
   owner-side live preflight matched Jules's pinned marker, parent, tab and
   revision. The gateway recorded one Google Docs HTTP 200 response and
   charged its sole write. This response alone is a transport result.
3. The agent signed listed option B (`wMBPYlSZ4qLVY1odEF84oFsm`) as a
   distinct second operation. A sandboxed CLI invocation could not prepare
   the outbound transport, so it supplied no budget evidence. Re-running the
   same unclaimed operation with network access returned `not-entered` and
   `gateway.task.write-budget`. The journal still recorded exactly one write
   operation. No second Google request entered. The task was then revoked;
   its final status is revoked, one write, zero read calls/releases/bytes.

## Independent provider observation

demo_co read Google directly after option A and exported generation 0043,
`google-bounded-negative-observation.json`, SHA-256
`ea86c4b9045778ab8f4259eacaf2c509b257f45e95b7032df60ce2ef9c328a5b`.
Its schema SHA-256 is
`ff8c25aea56cef6aca7dc91881d9d055990dae7eb70654c9a7e64af3731aa8f3`.
Auths copied the private observation into its isolated run and validated
the schema, digest, generation chain, producer identity, task timing,
document/parent/tab/marker pins and complete expected bytes. The admin and
Jules exports both privately match precommitted option A: 93 raw bytes. The
content digest remains in verifier custody.
The original marker is absent, the Jules revision changed, the scratch
root still has five children, and the frozen seven and canonical Project A/B
fixtures remain unchanged. demo_co attests provider state, not gateway
causality; the signed task, agent action, gateway result and timing provide
the separate Auths side of the join.

The exact-confirmation-only override was checked without making another
agent grant. A separate private operator policy set `write_approval_mode` to
`exact` and removed the choices (SHA-256
`27327dcab039cba6f044165995c4e602a5decc223c4fd199257cf1611c7b52d4`).
Its task installation pinned that digest and set `allow_bounded_writes` to
false (installation SHA-256
`ae62c35b9d5323894f03d94bf05a2e1b90ea168382b1829880fe884ccd9c1ffb`).
Using the same live operator authority and identities, task-card construction
refused the proposed A/B upfront allowance with `bounded upfront choices
disagree with installed task`. No grant or provider request was created in
this policy variant. The focused policy test also passes. The override was
exercised at owner-side task construction, not as a second configured gateway
deployment.

This run covers the bounded-upfront off-choice, second-write and company-policy
refusals with one real Google edit under the human grant. The wider §8–9
hostile matrix and production qualification remain open. This run used
development-only credential custody.
