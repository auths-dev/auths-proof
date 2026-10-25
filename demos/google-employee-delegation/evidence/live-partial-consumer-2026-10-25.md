# Existing-consent Google consumer smoke — 25 October 2026

**Qualification:** partial provider-adapter smoke, not AP-SPEC-070 delegation
acceptance. This run used Jules's existing `demo_co` employee grant. It did not
start a Google sign-in or consent flow, copy a credential into Auths's normal
vault, create an Auths employee-signed task, or invoke a separate agent process.

- Auths code revision: `49b20589c24d01735ad21fbb917eb2983ce15164` (clean
  worktree, unsigned commit).
- Producer's private `demo-co/google-partial-probe/v1` report SHA-256:
  `4d9132c5457e1a7a7ea75624cf28febea0312c50925edab95f1f1700ed2318da`.
  It records the independent provider controls: Jules allowed on projects A/B,
  Jules denied on finance, and Drew denied after suspension. It explicitly has
  `full_google_ready=false` and is not the versioned full Google export.
- Auths redacted [consumer result](live-partial-consumer-2026-10-25.json)
  SHA-256: `30638cbe82294d4e39f55db54343a121ff275ad823a8e104890222f1c12df075`.

`auths-google-read-partial-smoke` pinned the producer report digest and OAuth
client record, verified Jules's subject and hosted domain through Google
UserInfo, then used the closed Auths Drive reader. Project A required two
fixed GETs; 1,249 content bytes were returned to the local diagnostic and
their SHA-256 matched the producer's independent control. Project B was
employee-readable in the producer report but excluded from the diagnostic
task; Auths refused it before credential resolution or any provider request.
The result contains no token, document body, Google subject, or Drive ID.

The first live attempts exposed three compatibility defects that the exact
revision above fixes: the Mac Python runtime lacked a default CA bundle,
shared-drive metadata needed `supportsAllDrives=true`, and Google's refresh
response used gzip while the broker had read undecoded raw bytes. The full
broker suite passed locally (64 tests) after those changes. This run used the
local source package and installed native SDK wheel; source-free Mac install,
full independent export, real signed agent journey, and the §13 live matrix
remain open.
