# AP075 findings and assurance gaps

Assessed shipping source: `ac5fcabe9c6300e46789b4e847bb1991f9f9d66f`.
The assessment tooling is a separate change. No shipping Rust, protocol or
binding behavior was modified. References below refer to this target unless
explicitly marked as assessment tooling.

## Demonstrated product vulnerabilities

None demonstrated by this investigation. This is a bounded negative result,
not a finding that vulnerabilities are absent. In particular, supplemental
implementation tests and finite process/race histories do not establish every
schedule or the production deployment premises.

## Release-blocking assurance gaps, ranked by consequence

These are evidence gaps, not critical/high vulnerability findings.

### AG01 — The assessment does not satisfy the fresh-context requirement

Affected requirement: AP075 §3.1; G01/G09. The coordinating assessor also worked
on AP073. Its new attacks are observations, but its source review and retesting
retain author bias. A fresh-context reviewer has not participated; a human
security audit has not occurred. Signing off an independent assessment on the
basis of this work would overstate the evidence.

Required action: give another assessor the pinned source, installed artifacts,
specification and reproducible observations. Require it to derive its own
attack plan and challenge the three composed invariants. Keep author involvement
visible. This does not require a new authorization abstraction or more proof
coverage. Delegating that review requires the owner's pending authorization.

### AG02 — Lab containment cannot qualify production provisioning or storage

Affected claims: SC05/SC12; G04/G06/G09. The restricted UID could not read the
tested private files/process memory or reach the admin/provider endpoints. But
`demos/stripe-gateway/operate.py:332` provisions a simulation with controller-held
development keys, and `/run` is disposable container state. A deployment that
mounts an operator token into the agent, gives it Docker access, uses a writable
clock-marker parent, restores stale state without an independent checkpoint, or
allows an alternate provider credential does not inherit these observations.

The central time gate at
`product/runtime/auths-gateway/src/qualification.rs:135` checks marker type,
permissions and age. It trusts the configured host/time/provisioning boundary;
the test does not establish a production time service or root custody ceremony.
The production runbook's backup/quarantine procedure remains an operator premise.

Required action: independently assess one actual supported deployment, its
effective mounts/identities/egress, protected trust and custody provisioning,
clock producer, checkpoint custody and backup/restore exercise before making
production claims. Preserve the existing central clock, entry and journal
owners. No live account or production access was authorized here.

### AG03 — A response-lost refund may remain operationally unresolved

Affected claims: SC09/SC10; G06. Concrete history: the counting provider applies
one refund and drops the response. Inspection after restart remains Unknown and
issues no further provider request. The response-provided refund locator was
never retained. An authorized observation of a different known source succeeds;
that is not reconciliation of the unresolved refund.

See `RECOVERY-unknown-restart-and-independent-read` in the retained boundary
evidence and `recovery-exercise.json`. The journal/entry boundary
(`product/runtime/auths-gateway/src/store.rs:2991`,
`product/runtime/auths-gateway/src/submit.rs:891`) correctly does not turn this
uncertainty into a new permit. Blindly submitting another refund can create a
second real effect even though the original authorization was used only once.

Required action: keep the charge and escalate using separately authorized
provider/account evidence. Before calling recovery usable for a customer,
exercise that escalation with an unfamiliar operator and measure its effort.
Do not add a universal provider-search language or silently declare a missing
match to mean non-execution. Machine timings here measure four scripted steps,
not human resolution time or production incident frequency.

### AG04 — Full interface/variant independence remains narrower than the matrix

Affected requirements: AP075 §§7–8; G02/G03/G05/G08. All 32 families have
concrete related evidence, but a family mapping is not proof of each listed
variant. The new independent provider-reaching campaign uses file state and
Python/raw IPC. TLS PostgreSQL, many late-ACK/rollback histories, presentation
and multi-hop variants rely on freshly executed existing native/installed
tests. Go/TypeScript semantic agreement covers the portable corpus, not the
gateway's stateful semantics or a fresh WASM hostile-input campaign. No human
review-comprehension trial occurred.

Required action: the fresh assessor should identify and independently expand
the highest-risk uncovered variants, especially validly signed lineage/origin
substitution, TLS-store composition and recovery/projection ambiguity. Retain
the exact execution census. Do not convert 454 passing selectors into an
independent proof of the complete boundary. The bounded local review is useful
evidence; it is insufficient for the broader independent-release claim.

## Assessment-tool defects and setup failures

| ID | Concrete failure | Resolution and retained evidence |
| --- | --- | --- |
| AT01 | A networkless container cannot resolve `api.stripe.com` for the native doctor's transport-construction check; the existing reference fails before execution. | Add an explicit public-address DNS construction stub while retaining `--network none` and per-UID egress denial. Corrected installed reference: 23 cases. This supplies no real Stripe/DNS/TLS evidence. |
| AT02 | PostgreSQL configured as host IP `127.0.0.1` while expected TLS identity is `localhost` is refused by `product/stores/auths-stores/src/lifecycle.rs:1002`. | Correct the lab connection host to the expected DNS identity. Do not weaken identity checking. All 85 selected TLS PostgreSQL scenarios then execute successfully. |
| AT03 | macOS `/var` symlink ancestry causes the intact acquisition-control fixture to be rejected. | Canonicalize the assessment-owned temporary root before constructing variants; preserve rejection of links inside extraction. Nine controls pass, including the intact positive. No corrupt package was accepted. |

These setup failures were preserved before corrections in private local logs,
as described in `remediation-and-retest.md`. None is represented as an Auths
authorization exploit or counted as a passing initial run.
