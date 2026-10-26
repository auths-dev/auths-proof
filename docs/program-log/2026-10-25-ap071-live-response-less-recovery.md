# AP-071 live response-less create recovery, 25 October 2026

This run exercised Jules's existing Google grant, a distinct registered agent,
one authenticated 51-byte Project A source release, and a Jules-signed exact
plan for one create and one population write. It used development installation
`QU6Mhax33H2fPldLdNKrvWes`, write connection
`conn_N7qsNKNG3p7bAfUu6z9qIg`, and read connection
`conn_xGgLT15_Vq2cwJ5X_2KMnQ`, both bound to Jules's Google subject
`113654555744401103740`. Both source-backed credential materializers passed
their live subject probes before the task. The agent principal was
`key:sha256:ngUKlHElrvbAobws4WACYio2L-BiqqMomEfMMeCK0dk`; the browser
employee principal was distinct.

The agent received and acknowledged the pinned source as one 51-byte gateway
release. Jules signed an exact plan naming the Project A folder
`1ZtmuBMypwxDZ_onYgV3tspl-_Mzv_8SA`, title
`Auths AP-071 Project A handoff`, marker
`ap071_22aadc7077caa3d6413c204910252e1b`, one create operation
`m8O2ezqkwFH_Y5OthNWswFJO`, and the complete 145-byte population text. The
plan was recorded before provider entry.

demo_co's private generation-0018 v3 baseline was observed at
`2026-10-25T23:39:06.658417Z` and pinned by SHA-256
`d048c673be94bd545a2d00807c558096ef3ca4273049e4cedf3fffc7f6557db8`.
It showed exactly five Project A children and unchanged canonical Project A/B
documents. Auths stored this baseline before the sole create submission. A
development-only, exact-operation fault arm consumed a complete successful
Google create response before Auths could record its locator. The gateway
reported `unknown`, with no response status, digest, or child ID in the
attempt; the task journal charged one write. **Create was never retried.**

Jules's marker search found one candidate. Independently, demo_co generation
0019 observed the same new blank Doc, ID
`1ddfm1ReM8LJ3VrPsENXtucfxvY6KEdV1RSLF5SvWYVA`, created at
`2026-10-25T23:41:09.724Z`, with the exact sole parent, title, marker, blank
Docs layout, six-child inventory, and five unchanged neighbors. The private
observation SHA-256 is
`b29b82881c1cdb292fcad66c41e19fa229267b173d7d8364cccc5bd93f102c8b`.
An operator-signed attestation joined the gateway's original unknown attempt,
Jules's one-candidate search, and that independent observation. Jules signed
the recovered-child action in her Incognito workbench. The gateway then made
one fresh Google metadata GET and durably bound only that candidate. The
signed recovery itself made no create or edit.

The first recovery attempt found a real gateway bug: it reverified the
short-lived original agent proof at recovery time, after its expiry. The
gateway now checks that proof at the original attempt's durable evaluation
time, while requiring the task, plan, operator attestation and new human
recovery action to remain valid at recovery time. The initial workbench
metadata step could not resolve Google from its restricted process; the
same signed gateway recovery was completed in the network-enabled operator
process. Neither failure bound a child or sent a second create.

The create ran under gateway binary SHA-256
`aa6a4ceef758c9fc332eda3ca566cb443b76ccd90b5f493208521696408db40b`.
Recovery and population ran after that bug fix under SHA-256
`b69d5de56d21bc1ed147c446cc708d3ecc2f615b6fbcb58db8353cabe511ea84`.
This run is live integration evidence, **not a same-build installed-artifact
qualification**. A clean fixed-build rerun is required for that claim.

Jules's live preflight checked the recovered child's blank tab and revision,
then the separate agent signed the plan's population action. The gateway
recorded one Google Docs `batchUpdate` response for operation
`populate-vIDVh62ripODhs-q`. The final task status charged exactly two writes
against its two-write budget, one read call, one 51-byte acknowledged release,
and no extra operation IDs.

After binding, a read-only recovery-input query refused with
`gateway.task.recovery-plan-mismatch`. The task did not expose a second
recovered-child binding path, and no further provider write was attempted.

demo_co's private generation-0020 final observation, SHA-256
`edf586cf331d760787b171d8758984120a6976cdf50b25464bb6407fce1112a8`,
passed the pinned v3 consumer. The new Doc has the exact approved 145-byte text
plus Google's three-byte UTF-8 BOM: raw export 148 bytes, with its content
digest retained in private verifier custody.
It remains the sole new Project A child with the unique marker. All five
pre-existing children and canonical Project A/B documents were unchanged;
Jules's Project B write was denied. The provider observation proves final
Google state; the signed Auths task, attempt and recovery journals establish
the delegation and operation attribution.

This demonstrates the **single-match live recovery path**. A fixed-build
rerun, the zero-match, multiple-match and incomplete-search lost-response
cases, remaining hostile matrix, production custody and qualification still
require their own evidence before full AP-SPEC-071 acceptance.
