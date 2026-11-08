# AP075 assessment report

**Verdict: assessment incomplete for the independent release claim.** The
repository-local investigation, attack tooling and retained evidence are useful
and reproducible. They do not satisfy the required fresh assessment context or
establish production security. Recommended designation: **prelaunch engineering
candidate; retain current production and independent-review limitations**.

Target: main `ac5fcabe9c6300e46789b4e847bb1991f9f9d66f`. Assessment changes do
not alter shipping Rust, protocol, binding or provider semantics. The same agent
participated in AP073 and authored this assessment/tooling. No independent human
audit, customer trial, real Stripe call or production custody ceremony occurred.

## Observed results

| Evidence | Actual scope and result |
| --- | --- |
| New installed-path campaign | 33 cases pass with restricted Linux UID 62004, native verifier/approval/entry, independent provider transcript/effects and file state. |
| Existing installed Stripe reference | 23 cases pass after correcting the lab DNS prerequisite. Scripted reviewer consent; no human-presence claim. |
| Existing compiled native registry | 452 exact selectors pass; 85 use configured TLS PostgreSQL. Twenty dedicated child-worker entrypoints and one unconfigured report consumer are excluded from property counts; parent scenarios invoke their workers. |
| Installed multi-hop journey | Eight scenarios pass with distinct UIDs, five or six process-held keys, zero private-key export to the orchestrator, zero replay writes/redeliveries and retained successor capacity origin. |
| Independent Go and TypeScript | Each semantically checks 323 portable corpus vectors without mismatched fields. Not a stateful gateway or end-to-end theorem. |
| Acquisition controls | Intact positive accepted; eight corruption/path/source variants rejected; mutants not executed. |
| Conventional baseline | Six common scenarios pass. This experiment does not establish that Auths uniquely solves those basic cases. |

Twenty-four duplicate requests across two gateway processes produce one provider
write. Sixteen distinct-operation contenders produce one write and consume at
most the 1000-unit shared limit. After an applied refund's response is lost,
restart and inspection retain Unknown with no extra provider I/O. Recovery of a
different known source does not resolve the unknown refund.

The scope is finite and uses development custody plus loopback doubles. Existing
tests remain supplemental implementation evidence. Read `findings.md` before
using a passing row to support a release claim.

## Gate verdict

| Gate | Verdict | Basis |
| --- | --- | --- |
| G01 Scope/provenance | Unverified in full | Target, payload pins and source-backed path retained; required fresh assessor absent. |
| G02 Coverage | Unverified in full | All 32 families mapped to concrete related evidence; broader independently derived variants and positive controls remain narrower than the complete matrix. |
| G03 Authority/approval | Supported within tested scope | No bypass demonstrated. New transport attacks plus native quorum/lineage/entry cases do not establish arbitrary chains or every presentation. |
| G04 Containment | Supported within lab only | Effective restricted-UID file/memory/admin/egress observations pass. Production provisioning remains unassessed. |
| G05 Concurrency/revocation | Supported within tested scope | Independent file races and native file/TLS scenarios pass; finite schedules and participating-writer/storage assumptions remain. |
| G06 Recovery/operations | Unverified in full | Lost-response exercise and native crash/ACK/restore cases pass; unresolved refund escalation, human usability and production restore/custody remain unmeasured. |
| G07 Findings closure | No demonstrated critical/high defect | No product exploit established; assurance gaps AG01–AG04 prevent broader closure. This is not a vulnerability-absence claim. |
| G08 Qualification | Pending final hosted verification | Exact-head checks must be inspected after the final assessment commit; prior head has lab readiness and upstream download failures plus unrelated live-demo failure. |
| G09 Evidence/claims | Supported for disclosed local report | Retained census/provenance/limitations and current prelaunch claims agree. Independent/production qualification remains unavailable. |

“Supported within tested scope” is deliberately not a full gate pass. No internal
release-candidate or production designation follows from this table. Hosted CI
results for the final PR head belong in the PR handoff; a commit cannot contain
its own future CI result.

## Release claims and next decision

Preserve README's statements that no independent security review or qualified
production provider route exists. Offline audit checks the entries provided under
independent trust; it cannot establish that an operator exported every action.
Revocation committed before a later grant blocks that grant; already-granted
provider entry may finish. No exactly-once external effect or physical-power-loss
durability guarantee was established.

The bounded comparison supports a product decision: test whether transferable
authority, shared ancestor limits and portable evidence unlock one consequential
customer action. A conventional transactional gateway already handles the six
basic cases in this experiment. Do not build another provider or richer identity
calculus to avoid learning whether the additional machinery is wanted.

Prioritized remaining work is AG01's fresh assessment, AG02's independently
reviewed deployment when authorized, AG03's real operator escalation exercise,
and AG04's targeted independent variant expansion. Customer questions are in
`customer-validation-handoff.md`. Demand, willingness to adopt and human effort
are unvalidated. These gaps must not be relabeled as passes to finish a roadmap.
