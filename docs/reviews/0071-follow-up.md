# AP-SPEC-071 review disposition, 26 October 2026

This is an implementation-side follow-up to [0071-review.md](0071-review.md),
not a replacement for that review or an independent approval. It starts from
`1957d661` and includes the read-boundary and installed-status changes recorded
in the [continuation log](../program-log/2026-10-26-ap071-read-boundary-and-status.md).
**PR #211 is not ready to merge.** No GitHub CI was inspected in this
continuation, as requested; no exact-final-revision CI result is claimed.

| Original finding | Current disposition | Limit of the evidence |
| --- | --- | --- |
| 1. Unsigned task observation | `GatewayEngine::observe` rejects task-bound recipes before all observation variants, including stored outcome/pre-entry results. The existing application-socket regression provisions an observer, tries an excluded Airtable record and repeats after revocation. | Source and previously recorded loopback evidence; this continuation did not replay live provider operations. |
| 2. Managed-agent OS isolation | Existing source-free macOS and Linux runs exercise the actual AP-071 channel and deny direct provider egress and credential/operator/state access. The new Airtable status case also passed the installed macOS isolation probe. | Scoped development deployment evidence. Production and multi-host isolation remain separate qualification work. |
| 3. Read revocation/expiry checks | The earlier fix reloaded task state around leasing/materialization. This continuation also places the checks **after** asynchronous connection reloads, and adds pre-lease reload, pre-provider reload and static-lease expiry regressions. All ten focused read-execution tests passed. | No atomic cancellation or production revocation-propagation claim. Installed Google binaries from older runs do not acquire this later source fix retroactively. |
| 4. Recorded create reconciliation time | `reconcile_created_child_at` verifies original agent/confirmation facts at the durable attempt's `evaluated_at`, while current task and connection checks still govern recovery. Existing recorded-plan and exact-confirmed expiry/restart regressions cover the source path. | The installed Google recorded-response crash/restart case still needs evidence on the final artifact. These existing tests were inspected, not rerun in this continuation. |
| 5. Google code in common executable | Google custody moved to the separately pinned demo-owned executable; the common binary uses the closed process-materializer contract. Installed Google and Airtable sources have used that interface. Remaining Google references in the common binary are test fixtures. | Production process custody/qualification remains open. |
| 6. Google fields in common population | The common preflight and recipe contract uses zero to four named provider values. Google supplies tab/revision; the independent Todoist population oracle supplies none. The source comparison and hostile cases exist; the revised Google recipe has its own installed positive run. | Synthetic Todoist reference evidence is not a live Todoist deployment or an installed cross-task/child/plan/preflight swap case. |
| 7. Installed reproducibility and hostile matrix | The source-free bundles pin native executable, wheels, recipes and runner. Seventeen accepted Airtable cases now have manifest/receipt/cleanup pins, including a genuine HTTP 403 refusal, OS isolation and specific process-crash boundaries. | Partial. Google create/populate swaps, Google crash/concurrency, live subject change, stale revision and access withdrawal remain unproved; Airtable media type, origin and redirect cases remain outside the accepted installed corpus. |

The successful Google Jules read/create/populate and independent exact-content
readback are preserved. The latest rotation test was already revoked and is
not an available task for further effects. The new session could not bind the
existing workbench tab: browser inventory contained no tabs. It did not
reproduce the prior permission-denial text, change permissions or attempt an
alternate access route.

Before full §8–9 acceptance, retain decisive evidence for the remaining cases
rather than treating source tests as installed provider results:

- The Google exact-edit content/revision race, changed live OAuth subject and
  provider access withdrawn after an otherwise valid task is signed. demo_co
  confirmed that historical finance/Project B denials and successful edits do
  not establish those last two provider behaviors.
- Current installed create/populate task, plan, child, parent and preflight
  substitutions, recorded-response crash recovery and concurrent last-write
  behavior, with independent no-unintended-effect observations.
- The stronger planned-population revocation condition with a retained
  attempted-entry time proving the preflight was still fresh. The prior run
  isolates revocation as the refusal cause but lacks that timestamp.
- The remaining installed cross-provider identity/account and response
  media-type/origin/redirect matrix. A fabricated response cannot be labeled
  as a real Airtable response. The new retired-record case proves only its
  recorded non-200 status behavior.
- Full-suite canonical Project A source context and exact-artifact provenance
  for each required case; the installed positive Google run selected the
  separate 51-byte probe source. Preserve that narrower evidence label.
- Authoritative CI on the settled final revision after the spec work is done.
  Production custody, deployment and multi-host qualification are separate
  claims and must not inherit the dedicated demo's evidence.

The other agent's untracked `docs/review/` work was neither edited nor staged.
