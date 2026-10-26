# AP-071 provider custody process cutover — 26 October 2026

The shared gateway executable now loads an operator-pinned, provider-neutral
custody process descriptor. Its executable and private provider pin document
are checked against SHA-256 before installation and each materialization. The
sidecar receives only a previously reserved task operation and an opaque
credential source. It returns a bounded short-lived bearer; the gateway checks
the returned subject, authority digest and deadline before sending a reviewed
recipe request. The gateway's old Google module and v1 materializer bundle are
removed from the runtime path.

The Google source was moved to the demo-owned
`auths-google-employee-custody` executable. Its existing four grant, scope,
source and subject tests pass. A generic gateway test used an independent
fixture custody executable and then refused its modified code digest. This
proves the process protocol and pin check, not a second provider credential.

A private two-connection Jules pin bundle was converted to the new v2 process
installation in `/private/tmp/ap071-custody-cutover-20261026` without copying
grant bytes. Each Google sidecar passed a live OAuth refresh and UserInfo probe.
The current gateway binary accepted the v2 bundle in disposable state
`/private/tmp/ap071-process-cutover-gateway-20261026` and its own readiness
probe reported `materializer-probe-ready`, `count: 2`. No Drive or Docs effect
was attempted, and no new agent task was signed in this check.

A second provider-owned process now uses the same interface without another
gateway branch. The source-free Airtable bundle included its pinned
`airtable_custody.py`, private PAT pin documents and the unchanged generic
gateway. Bundle manifest SHA-256:
`1993a36f2a33d1ce1d358fe50ba34fc6db5e806eefd025d55b16950d08f28c7b`.
The installed runner placed only an opaque source reference in both gateway
connections; the separate sidecar read the operator PAT after task admission.
Two disposable-record live runs completed one seven-byte agent-acknowledged
read and one exact confirmed write each, with independent `approved-with-echo`
readback and one read/one write in the gateway ledger. Both run-owned records
were retired. Redacted results are under
`/private/tmp/ap071-airtable-custody-diagnostic-live-20261026` and
`/private/tmp/ap071-airtable-custody-repeat-20261026`.

The first attempt with this bundle stopped before provider entry during the
excluded-read negative stage; its ledger retained zero calls/releases/writes
and its disposable record was retired. The runner reported only a generic
`RuntimeError`, so the precise reason is unresolved. The two succeeding
independent runs provide positive interface evidence but do not erase that
intermittent failure. A fresh Google task under the new gateway and sidecar,
and production custody qualification remain open. A separate
[installed macOS agent isolation run](2026-10-26-ap071-macos-installed-agent-isolation.md)
subsequently exercised the same generic gateway and Airtable sidecar with
every agent command under an OS Seatbelt profile.
