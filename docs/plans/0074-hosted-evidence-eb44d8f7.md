# AP074 hosted evidence: eb44d8f7

Status at publication: the eb44 native, installed and clean formal producers below are verified. Its implementation gate retains the obsolete-corpus failure; the repaired consumer head must pass its own complete gates and both real Lean reuse checks. This is producer evidence, not final acceptance.

Source `eb44d8f7082db6ed9ab46c1bf5319e8e736d7b28`; GitHub PR merge producer `8335af6a6f9170a12f4b63feae0f755e87290308`; both tree `195e1ae19c0491af1c7e8fdd6d0c63b87655fe89`. Merge parents are protected base `e2d10a74fa0be5e6bfe2b9f698632c835cd7b11b` and source eb44. Native closure `61173a0020911d7fb40fe9870a81b9b19a3641b1f5c406c0eeb9b9db3a3b88aa`; formal source closure `fe66a1c24450b555e7e28d775c5796b68bc0d896445181343c6f8178d3f43751`; freeze 432.

All twelve applicable workflows outside CI passed. Conditional custody-live41924978034 is skipped and provides no live-provider evidence. Main CI41924977969 is terminal with its known corpus failure. The complete cohort has 96 checks: 85 success, 3 failure and 8 conditional skips. Fast Lean126908887765 passed at22:49:58UTC after the fresh build beginning22:34:06UTC. Kani126913912984 passed at 23:01:31UTC with all49harnesses; translation126913912807 passed at 23:10:35UTC after two byte-identical reproductions. Authoritative clean Lean126929527493 ran23:10:39–23:38:21UTC and passed; its clean rebuild step started23:14:08UTC. No manual reruns/cancellations or new publication occurred after eb44.

## Workflow inventory

| Workflow | Run | Current result |
| --- | --- | --- |
| Airtable gateway demo | [41924977955](https://github.com/auths-dev/auths-proof/actions/runs/41924977955) | success |
| CI | [41924977969](https://github.com/auths-dev/auths-proof/actions/runs/41924977969) | failure: corpus root and dependent rollups |
| Gateway custody live | [41924978034](https://github.com/auths-dev/auths-proof/actions/runs/41924978034) | skipped |
| Gateway isolation | [41924977909](https://github.com/auths-dev/auths-proof/actions/runs/41924977909) | success |
| Gateway operator package | [41924977942](https://github.com/auths-dev/auths-proof/actions/runs/41924977942) | success |
| Git signing branch-protection action | [41924978062](https://github.com/auths-dev/auths-proof/actions/runs/41924978062) | success |
| Git signing protocol | [41924978149](https://github.com/auths-dev/auths-proof/actions/runs/41924978149) | success |
| Google read demo installed images | [41924978033](https://github.com/auths-dev/auths-proof/actions/runs/41924978033) | success |
| PostgreSQL lifecycle qualification | [41924978051](https://github.com/auths-dev/auths-proof/actions/runs/41924978051) | success |
| Python SDK package | [41924977978](https://github.com/auths-dev/auths-proof/actions/runs/41924977978) | success |
| Recipe qualification | [41924978037](https://github.com/auths-dev/auths-proof/actions/runs/41924978037) | success |
| SDK outcome recipes | [41924978031](https://github.com/auths-dev/auths-proof/actions/runs/41924978031) | success |
| Stripe gateway demo | [41924978136](https://github.com/auths-dev/auths-proof/actions/runs/41924978136) | success |
| TypeScript SDK package | [41924978104](https://github.com/auths-dev/auths-proof/actions/runs/41924978104) | success |

## Conditional skips and scope

All eight skipped jobs require `github.event_name == workflow_dispatch` and `github.ref == refs/heads/main` in their checked-in workflows. This cohort is a PR event on `codex/effect-recovery-foundation`, so neither condition is met. These are explicit inapplicable live/operator release paths for this PR event; their skipped status supplies no passing, provider, retained-operator or signed-release evidence. The installed simulations and required native/platform gates are separately executed above.

| Skipped job | Workflow and excluded operation |
| --- | --- |
| [verify as a gateway would (126912127149)](https://github.com/auths-dev/auths-proof/actions/runs/41924978037/job/126912127149) | recipe-qualification: verify a manually signed live qualification release |
| [sign the complete cleaned qualification release (126912126680)](https://github.com/auths-dev/auths-proof/actions/runs/41924978037/job/126912126680) | recipe-qualification: sign the cleaned live release |
| [independently review finite commissioning (${{ matrix.family }}) (126912125017)](https://github.com/auths-dev/auths-proof/actions/runs/41924978037/job/126912125017) | recipe-qualification: independent finite commissioning review |
| [independently sign first qualification (${{ matrix.family }}) (126912124758)](https://github.com/auths-dev/auths-proof/actions/runs/41924978037/job/126912124758) | recipe-qualification: independent first-qualification signing |
| [retained production operator (${{ matrix.family }}) (126912124717)](https://github.com/auths-dev/auths-proof/actions/runs/41924978037/job/126912124717) | recipe-qualification: retained production operator |
| [gateway journey against Stripe test mode (126906932637)](https://github.com/auths-dev/auths-proof/actions/runs/41924978034/job/126906932637) | gateway-custody-live: actual Stripe test-mode provider journey |
| [store-contract (126906880394)](https://github.com/auths-dev/auths-proof/actions/runs/41924978034/job/126906880394) | gateway-custody-live: manually dispatched production credential-store contract |
| [gateway journey on the production credential store (126906879308)](https://github.com/auths-dev/auths-proof/actions/runs/41924978034/job/126906879308) | gateway-custody-live: production credential-store journey |

## Actual native and installed evidence

[PostgreSQL lifecycle job126906875975](https://github.com/auths-dev/auths-proof/actions/runs/41924978051/job/126906875975) passed. Its actual complete retained log matches all 63 required selectors exactly once with one passed/zero failed/zero ignored:48 ordinary,11 final-hardening,2 cost and2 generated-history. Both newly required native review and64-event boundary selectors executed. The additional production connection-process test and 30-store hostile/conformance suite passed separately. Physical-with-WAL restore to a named restore point reports before-target retained and after-target excluded; replay-continuity claim is explicitly false. Connection-generation and exact-record floors protect only their stated state: an unchanged connection floor does not establish safe automatic managed resume after point-in-time rollback of attempt/counter rows. The physical-WAL rehearsal proves before/after storage behavior, not whole-journal replay/accounting continuity.

The independent mutation report compares28 requests and26 responses across maintained Airtable/Stripe recipes. All seven source hashes match this checkout. The information report compares22 pairs after actual execution of the eight named file/PostgreSQL histories; its five source hashes and native-log hash match. Its source_commit is the verified merge producer, whereas installed/cost/history reports explicitly retain source and/or checkout separately. None is relabeled as a different producer revision.

Generated histories retain four seeds and eight concurrent rounds per seed per adapter (32 positive rounds and four negative pairs). Independent expected effect entries agree with actual HTTP and write-transport counts. Distinct OS workers and retained historical-byte preservation hold in every round; each seed has four distinct effects plus the baseline HTTP entry, with fresh-operation/old-approval refusal leaving the source unchanged. These are deterministic generated fixtures, not exhaustive concurrency exploration.

The actual Linux distinct-UID report covers33 application cases,12 admin commands,53 CLI routes and5 private CLI refusals. Initial 45/replay 49 private files remain inaccessible. It reports no new custody/provider entries, direct provider refusals, recipient identity/key checks before content, trusted recipient positive control, no plaintext/encoding/raw-digest sentinel leakage,0600 private export, one verified audit entry and overwrite refusal.

Airtable source-free installed simulation passes 36 cases with 13 verified private audit entries, zero inconsistent/unverified. All owner-browser positive assertions hold: consent withholding/decline/substitution, exact native renderer, private owner credentials, one write and separate read, Python+TypeScript acquisition, separate disclosure consent/native recipient ACK, private content, no replay delivery, same actor across operations and unknown-response/fresh-process controls. Stripe passes 23 cases with 6 verified audit entries, zero inconsistent/unverified. Both explicitly decline production/live-provider/human-attention qualification.

## Verified artifact archives

All ZIP SHA-256 values below match GitHub's authenticated artifact metadata; run metadata binds the exact source head. Only bounded named reports/logs were read. Private nested audit packets were not copied into this report.

| Artifact | GitHub ID | ZIP SHA-256 |
| --- | --- | --- |
| Linux distinct-UID | 13369196614 | `b58fb2bf2087540b0cded52e54ac07a3ea1c6d658a0a66bb26e6643ab6426f67` |
| Mutation differential | 13368214676 | `2f12aad26dcbebd9dd3122159aea9f67869dd536dbd5fd4e53d65f0df81a93cd` |
| Final hardening | 13370235387 | `1901e57fe4081450b9398a28622fdc5634784d00d5fa4948e8c7607e1b8e520f` |
| Generated histories | 13369825985 | `4c44f92f269c0988d8cb9e7afe9f32da23d0130ae7be2ea20ccacbbef7061963` |
| Native cost | 13369072499 | `668af902c3b2ebeecff308eb2933d60f1c679af2bfb2b49e658958c6065affcd` |
| Information differential | 13368772949 | `18e9449e053625c7c019d1c5b08379774e3435297e98986e7fe87cbe05211e8b` |
| Airtable installed | 13368319829 | `b8d0d631a952d3647b8ee338db6b5df0e603941b182e925604f9d09ad310acbd` |
| Stripe installed | 13369173481 | `60aeed41d3b8054e83d2f69111fdfce3beee70f26d55db570258ddc64ab77bfa` |
| Fast Lean log | 13370357973 | `d20e5620c8de7d5d36513e8869b27e029330749ff670a79942f2771e3dbe2b0f` |
| Kani phase | 13370384762 | `5f9b7dea6ddf6313592d36da7dff15700fb6ca792f4d3408130ae77c197bb963` |
| Translation phase | 13371652840 | `68184973fcad190b9fc0c289a8960665f38b7bda87b7ae6ef0317a0f5488b5fa` |
| Translation qualification | 13370803802 | `bcb31f244dbfa513eedd33ea06dd0be1c10176c4ce64214a2aadb4b54760e537` |
| Clean authoritative Lean phase | 13373617020 | `f2a256d1be842c86af7cf057b0e46e989e2029f5a4504ca18b2ecf093fd6818c` |
| Final formal evidence | 13373479017 | `7ac7d07e3b21228650318811c6d54bf09dbc6febbd4e4e793f806b567f52fb8a` |

## Native cost measurements

Eight test-profile samples per path/backend; timings are min/median/max milliseconds, not production SLOs. Adapter and fenced callback totals sum compilation plus execution calls per sample. Snapshot and RSS columns are maxima.

| Backend/path | Verify ms | Compile incl verify ms | Approval ms | Fenced callback ms | Adapter ms | Max snapshot bytes | Max RSS KiB |
| --- | --- | --- | --- | --- | --- | --- | --- |
| file/mutation | 0.888/0.946/0.979 | 3.040/3.116/3.142 | 0.238/0.239/0.325 | 11.359/11.660/16.188 | 14.362/14.800/20.507 | 4538 | 34092 |
| file/recovery | 0.870/0.884/0.912 | 8.627/8.885/8.975 | 0.222/0.224/0.251 | 37.588/38.156/40.827 | 42.149/42.811/54.645 | 12032 | 34136 |
| file/acquisition | 0.937/0.958/1.518 | 4.627/4.699/7.423 | 0.232/0.245/0.260 | 18.533/18.745/18.960 | 22.289/22.587/22.934 | 7330 | 35516 |
| file/disclosure | 0.889/0.920/0.945 | 4.114/4.189/4.255 | 0.239/0.242/0.263 | 37.878/38.435/38.691 | 41.773/42.379/52.188 | 16717 | 35580 |
| postgres/mutation | 0.916/0.955/1.179 | 4.250/4.337/5.506 | 0.237/0.241/0.270 | 11.451/11.750/13.926 | 24.247/25.036/34.465 | 4538 | 38940 |
| postgres/recovery | 0.874/0.922/0.960 | 10.415/10.585/11.005 | 0.223/0.227/0.239 | 38.249/38.478/40.621 | 63.532/64.258/66.230 | 12032 | 39000 |
| postgres/acquisition | 0.902/0.940/1.665 | 5.699/5.804/6.515 | 0.231/0.233/0.261 | 18.692/18.941/19.462 | 34.708/40.561/50.609 | 7330 | 41756 |
| postgres/disclosure | 0.903/0.928/0.959 | 5.222/5.313/5.754 | 0.238/0.240/0.253 | 38.566/39.142/45.296 | 54.699/55.373/64.891 | 16692 | 41816 |

file mutation_recovery: 8 measured inventories; native decode+inventory ms 16.346/51.331/88.234; max attempts 17, limit 4096; max RSS 34136 KiB.

file acquisition_disclosure: 8 measured inventories; native decode+inventory ms 17.950/79.608/142.396; max attempts 16, limit 4096; max RSS 35580 KiB.

postgres mutation_recovery: 8 measured inventories; native decode+inventory ms 17.703/63.310/99.874; max attempts 17, limit 4096; max RSS 39000 KiB.

postgres acquisition_disclosure: 8 measured inventories; native decode+inventory ms 20.013/86.463/155.022; max attempts 16, limit 4096; max RSS 41816 KiB.


Raw artifacts bind source eb44, merge8335, native closure61173 and the current test profile. They report actual native verification, compile, approval, adapter/callback timings, buffer lengths and Linux RSS; these eight-sample fixtures are not production SLOs or adversarial throughput guarantees.

## Assurance citation audit

The parent independently compared977→eb44 assurance manifest text. Masking only the 59 existing `kind=source-closure` citations to `formal/qualification/aeneas/source-closure.json` makes the remaining text byte-identical. All 59 current hashes equal raw source-closure file SHA-256 `685fdbfd0d91ae329300d15dbd2d3469b101a358137c8e37dbed35e3559d4601`. No theorem, axiom, claim, review or semantic binding changed. This agrees with the local complete typed-manifest negative controls; metadata refresh does not constitute proof qualification.

## Verified clean Lean producer

[Authoritative Lean job 126929527493](https://github.com/auths-dev/auths-proof/actions/runs/41924977969/job/126929527493) completed successfully at 23:38:21UTC. Its actual log records the compiled audit of329 statements with transitive axioms reviewed, Aeneas qualification with four reviewed external links and zero compiled external axioms, and four passing Rust refinement tests. The clean rebuild executed; no cached phase was accepted.

Artifact 13373617020 has exactly one member, `lean.json`. Authenticated archive SHA-256 is `f2a256d1be842c86af7cf057b0e46e989e2029f5a4504ca18b2ecf093fd6818c`. Its immutable source is eb44, run 41924977969, attempt 1; `execution=executed-clean`, `reproduction_count=0`, and no `reused_from`. Complete proof inputs are `c523f465540e306ac9eaaf49ef460365b467be4bccaafd2160552ce23dc83432`, exactly matching the repaired native computation. Planned Lean closure is `9a9be86efddb2a9db4ee16ed2c25233dce5d56437c7e4395c93f347908472ddc`; toolchain closure is `baff1cabbf9c83ffca0f4bdb1b8dda685a5ac59638e95d6d12e57f5d5bda9633`; evidence closure is `1c446639f484deacf0dc54fbd94da4ec6aceaa69e8e50432ae05696f123c0dbd`. The native reuse validator must independently validate these fields and current source/refinement checks at the consumer; this successful producer is not itself a warm hit.

## Remaining qualification

Main CI authoritative workspace has the corpus failure documented below. Final formal evidence 126942117729 passed at 23:46:11UTC; artifact 13373479017 attests execution=aggregated for the exact source/run/attempt and matching closures. Clean authoritative Lean and its compiled 329-claim audit passed. Qualified rollup126945531900 failed because AUTHORITATIVE=failure from the corpus root; its other listed formal, compliance, dependency, secrets and live-adapter dependencies are success. The three failures are implementation126913912856 and its derivative authoritative126917977445/qualified126945531900 rollups, not three independent roots. Fast Lean, both translation reproductions and all 49 Kani harnesses have passed. The authenticated translation phase reports execution=executed/reproduction_count=2; its qualification record retains zero compiled external axioms and four reviewed external models with all seven case modules. With the successful cold producer preserved, the required corpus repair/final evidence update must demonstrate both Lean phases reuse matching verified evidence while current-head Rust/source checks still execute. No warm hit is claimed yet. AP074 is incomplete pending final acceptance; AP070 stays independent and AP073 untouched.

## Actual authoritative corpus root and repair

Authoritative implementation126913912856/rollup126917977445 failed after the gateway library passed 302 tests, zero failed and 63 ignored in 38.35s. Both failures are in `auths-gateway-fuzz --test corpus`: the committed `observed-by-provider-after-response` seed predates public outcome/3, and `observe-pre-entry` still uses observe/3 instead of/4. Dynamic xtask campaign seeds already use current native fixtures/schemas. The repair binds committed positive/refused outcomes to the existing native canonical signer, keeps old bytes as explicit obsolete refusal controls, and binds current observation frames to the existing native frame constructor. No decoder or assertion is relaxed. No xtask/formal/controller/Cargo input changes are needed; the healthy eb44 proof producer is preserved. Focused complete repair verification passed: both authoritative native seed constructors and unchanged checks, all six fuzz corpus tests, native source-closure update/rebuilt check, formatting and semantic metadata construction. The canonical signed outcome corpus now has 14 current positives,8 current refusals and2 preserved obsolete seeds; current observation frames coexist with the preserved obsolete/3 refusal. No release identity or formal source/assurance file changed. Corrected-head hosted qualification remains pending.

Repair results: `/tmp/ap074-ci-eb44-repair/results.json`. No broad workspace, Lean or Kani suite was rerun locally. The successful hosted clean proof record is eligible for independently validated reuse because the repair changes only native gateway test/corpus/source-inventory files.

The repaired native gateway closure is `4c368d74e5a748ac79752bf9f2da2cbb3447c9ec67755147c80c03a0856a3d81`. The actual native `auths_ci_plan::formal_proof_inputs_digest` function was evaluated read-only against published main eb44 and the repaired isolated tree: both return `c523f465540e306ac9eaaf49ef460365b467be4bccaafd2160552ce23dc83432`. This establishes unchanged complete proof inputs for the seed repair; it is not a synthesized or qualified phase result. The future hosted warm path must independently repeat that validation and all current-head checks.

The two 63 counts name different inventories: 32 library-ignored cases are in the 63 explicit native selectors; another 30 ignored cases passed in the PostgreSQL conformance/hostile suite. The remaining ignored `scenario_tests::conformance_child_process` is deliberately spawned by both file/PostgreSQL conformance parents, twice for submit and twice for batch. Those parents require successful child exits and exact `RACE` witnesses. Their passing hosted results establish the child executions through this harness; there is no separately invented standalone helper run.

## Consumer verification boundary

The corrected consumer head must pass its own required implementation, installed SDK/demo, native adapter, formal aggregation and two validated Lean reuse gates. Those consumer results are pending at publication of this report. The final live verification record is the exact published head shown in [PR213 checks](https://github.com/auths-dev/auths-proof/pull/213/checks), with its immutable run/job/artifact identities recorded in the PR validation notes and retained authenticated final-head report. Passing producer evidence above is not relabeled as consumer execution. Recording that consumer outcome does not require a recursive documentation-only push.
