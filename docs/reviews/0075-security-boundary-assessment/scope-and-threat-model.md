# AP075 assessment scope and threat model

Status: local investigation retained; independent assessment and release closure
remain incomplete. See `final-report.md` for the exact gate verdict.

The target is main `ac5fcabe9c6300e46789b4e847bb1991f9f9d66f`, source tree
`fe161d6d38957af071bb11a0a59224f3923e13e4`. The primary path is the existing
platform Stripe refund demonstration, with real native authorization and exact
effect approval, installed Python/TypeScript consumers and a synthetic provider.
This does not qualify Stripe Connect or production Stripe behavior.

## Assessor declaration

The coordinating agent helped implement AP073 and therefore has implementation
history and potential confirmation bias. It cannot truthfully claim a fresh
assessment context or independent human review. Authorization for a fresh-context
reviewer has been requested; that work is not claimed until actually performed.
Same-agent fixes/retests will be identified in their records. Model/host tool
information is recorded only where actually exposed; unavailable provenance is
not inferred.

## Adversary and trust

The attacker controls application requests, its own signing key and authorized
input data, scheduling/replay, malformed frames and any files legitimately owned
by its restricted UID. It may coordinate authorized siblings and probe exposed
app/reviewer interfaces. It does not begin with operator/approver keys, custody
credentials, private gateway state, root administration or Docker access.

The laboratory controller may hold disposable keys and manipulate faults. Its
privileges are not attacker capabilities. Native authorization cannot be replaced
by fabricated sealed values or test allow verdicts. Provider transcripts and
applied effects are independent observations; native counters remain secondary
observations produced by the target.

Trust premises include native cryptography, the Linux kernel/container runtime,
protected operator provisioning, durable-store behavior, the selected time source
and the declared provider contract. Advertised deployment accidentally granting
the attacker access to those premises is in scope. A malicious trusted host,
compromised root ceremony, arbitrary independent provider writers and a dishonest
production provider are not claimed to be contained by this topology.

## Execution boundaries

Default experiments use assessment-owned local containers, synthetic credentials
and private content, source-free installed packages, disposable state and bounded
traffic. Existing unrelated containers, volumes, credentials and worktrees are
not part of the lab. Real provider accounts and production custody are not used.

File and configured TLS PostgreSQL are required for applicable state/fence
comparisons. Separate process identities, capability/namespace observations and
actual egress probes must establish containment; a development readiness failure
remains an expected limitation, not production qualification. No actual human
trial, customer demand or willingness to adopt can be inferred from scripted work.

Release claims stay unverified until mapped cases and retained evidence support
them. Missing prerequisites and indirect existing CI evidence cannot silently
become passing independent results.

## Executed topology distinction

The independent installed Stripe campaign and installed AP073 journey execute
Linux/amd64 source-free packages inside Docker Desktop's Linux VM. The 454-case
supplemental native registry is a Darwin/arm64 test binary on the macOS host;
its 85 PostgreSQL tests connect over actual TLS to the assessment-owned Linux
PostgreSQL container. It is not a second 454-case Linux execution. The source
tests are recompiled from the unchanged shipping source with
`loopback-provider,testkit-harness`; no test allow oracle replaces installed-path
authorization. Hosted CI supplies its own separate Linux evidence.

The package binaries are GitHub-produced Linux artifacts; the native test binary,
runner and raw log hashes have separate identities. Report assembly never treats
those distinct builds as identical artifacts. The exact assessor model/runtime
build identifier is not exposed; no version is inferred from a model-family name.
