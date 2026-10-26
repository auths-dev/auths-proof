# AP-071 read boundary and installed status refusal, 26 October 2026

This continuation started at `1957d661` on `codex/ap-spec-071`, seven commits
ahead of the recorded upstream. It read the spec, acceptance audit and original
review before changing code. The untracked `docs/review/` directory was not
changed. No Google provider operation or workbench shell request was made.

## Browser prerequisite

The new session tried to bind the existing Chrome workbench at
`http://127.0.0.1:8765/`. The browser tool returned `Tab not found in browser 1`.
Its tab inventory was empty; the subsequent surface inventory also showed no
tabs in Chrome or the in-app browser. This session therefore could not control
the requested tab. It did **not** reproduce the earlier saved-permission denial
and cannot establish its cause. No replacement tab, alternate hostname,
native-app fallback or HTTP request was used to bypass the missing access.
The revoked rotation-test task was not reused.

## Review finding 3: authority after asynchronous connection reload

The existing read fix checked task activity before each asynchronous
connection reload. A task revoked while the unchanged connection was being
loaded could therefore still reach a new credential lease or provider entry.
`release_execute.rs` now checks the task after that reload and qualification
check, immediately before custody and again immediately before transport.
It retains the check after credential leasing and the conservative spent
reservation on refusal. This narrows those specific interleavings; it does not
claim atomic multi-host cancellation of already entered requests.

Three new deterministic regressions cover revocation during the pre-lease
reload, revocation during the pre-provider reload, and exact task expiry
during a still-valid static credential lease. A private clock seam is used
only by the test invocation; installed entry points always supply the gateway
wall clock. The expiry case does not revoke the task. Each case asserts no
provider transport entry, no agent content, one retained call reservation and
`release-refused`. The pre-lease case additionally asserts zero new credential
lease calls.

The requested boundary evidence was constructed locally with:

```text
cargo test -p auths-gateway --features loopback-provider --lib release_execute::tests -- --nocapture
```

All **10** tests passed, including the existing materialization, static-lease
revocation, positive release, provider-denial and delivery-fault cases. The
gateway executable was then built to package the installed case below. This
is focused local evidence, not an authoritative repository CI result. GitHub
CI was deliberately not inspected while spec acceptance remains incomplete.

## Real Airtable response-status refusal

The source-free 33-wheel bundle at
`/private/tmp/ap071-airtable-status-v2-bundle-20261026` has manifest SHA-256
`765d80b6b826c697701154f256623db95864d16842254d366374d7d44f9df9c2`.
Its gateway SHA-256 is
`27f41ed3cf22fd56db748c3104ed7992bfa582b9b1343879f20e75b1922154d3`.
The bundle contains the read-boundary fix above, the reviewed Airtable GET and
PATCH recipes, pinned custody executable, runner and native/broker/agent
wheels. Installation was offline, and execution used no checkout imports.

Task `g4VHKAoMBEmhWkbQIPYPaNw8` and its separate agent's read were signed
before the operator retired the run-owned disposable record through the
existing ownership journal. The unchanged signed read then entered the
gateway's normal HTTPS recipe. The result was `provider-unavailable` with
**HTTP 403**, one charged provider call, zero releases, zero released bytes,
zero writes and no write attempts. The isolated agent received no content.
An independent ownership-scoped discovery after the refusal found no record,
and the resource journal records retirement. The macOS isolation probe also
passed credential/state/operator-file denial, outbound-network denial and
writes limited to agent storage.

The owner-private redacted result is
`/private/tmp/ap071-airtable-status-v2-live-20261026/operator/redacted-result.json`,
SHA-256 `57482ab49b1c14827bc91a754b5494384b15a8e0eb9b12fff39e0e71e76fcf88`.
The runner now persists the gateway result before later fixture assertions;
that intermediate observation has SHA-256
`bd20791943e3772b146c18870a6d4361cbb19b626422a7a9f841d90969b6d69d`.
The [installed-case manifest](2026-10-26-ap071-installed-case-manifest.json)
adds this seventeenth accepted case. The prior sixteen receipts, their cleanup
fields and all pinned members of their eleven bundles were rechecked locally
with no mismatch before this run.

This proves refusal of a real non-200 response under the existing read
contract. The provider record was retired, not subjected to an employee ACL
change. It is **not** evidence for Google access withdrawal, changed OAuth
subject, media-type substitutions, redirects or changed origins. The operator
PAT still establishes no second employee-bound identity.

## Initial run retained as incomplete evidence

The initial runner incorrectly required HTTP 404 for the retired record.
Task `N022L-g3D7xyNj0j1BLM3mSy` at
`/private/tmp/ap071-airtable-status-live-20261026` consumed one read call,
released no content and retained `provider-unavailable`, but failed before
saving the gateway's returned status. A separate later operator GET returned
403. That later status cannot reconstruct the original gateway result, so the
initial run is **not accepted** as a status case and was not retried.

Its bundle manifest is
`856f9f1bcb5ca5e797b7ad2030e6926a179f9ac29b5b925badafe92f71d871ed`.
Its post-run `operator/redacted-incomplete-result.json` has SHA-256
`1b23afefe786f68eceffbed4120777787be479380a59385c01d652b7c0e11012`.
The run's own record was confirmed retired; no cleanup remains. The corrected
runner used a fresh task and record for the accepted run above, admits only
the explicitly expected 403/404 denial statuses in this case, and retains the
actual status before assertions.

## Remaining acceptance

PR #211 remains **not ready to merge**. The
[review disposition](../reviews/0071-follow-up.md) separates source fixes,
installed evidence and unresolved gates. demo_co independently checked its
existing evidence and confirmed that neither the live stale-revision race
nor post-signing Jules access withdrawal has an existing complete producer
contract/report. It made no provider calls or changes for that audit. A fresh
browser approval path and coordinated producer work are still necessary for
those Google cases; the existing populated Docs remain preserved evidence.
