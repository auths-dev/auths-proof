# Airtable CI-only fix — published and verified

Observed terminal success on 2026-10-29 at 19:49 UTC. **Main AP074 work remains paused.**

Published exact commit **`d9618a568c4db8fae0b8bc4cb80b77de81c8e7d1`** to `origin/codex/effect-recovery-foundation` for [PR213](https://github.com/auths-dev/auths-proof/pull/213). Before pushing, verified remote and PR head were `cb1ee6d15a8f728b2f6f9ce01021de69b67ac966`, that this was an ancestor of the repair, and that the entire outgoing delta was exactly one reviewed commit changing only `demos/airtable-gateway/tests/owner_browser.py` (11 insertions/two deletions). Non-force push succeeded; remote SHA reverified afterward. No unrelated A19 commits were published. Main worktree, uncommitted retention/comparator work, AP070 and AP073 were untouched.

The [original failure](https://github.com/auths-dev/auths-proof/actions/runs/40911731259/job/123585414288) expected an internal recovery tool identifier in the complete native literal review. The native renderer instead identifies a recovery acquisition using the versioned `auths.gateway-recovery-read/1` contract. The repair checks that rendered contract, acquisition/GET, exact source effect and operation, correct bound read operation, matching native/semantic recovery and a separate reader actor. Existing literal byte equality, authentication, consent/no-entry, substitution, provider-count and replay assertions remain intact. No application/native behavior or security deadline changed.

Existing complete local hosted-package Docker/browser reproduction was rechecked rather than repeated. Publication now has fresh authoritative hosted verification:

- **[Airtable run40942189355](https://github.com/auths-dev/auths-proof/actions/runs/40942189355), attempt1: completed SUCCESS**, source head exactly `d9618a568c4db8fae0b8bc4cb80b77de81c8e7d1`.
- [Package job123688155935](https://github.com/auths-dev/auths-proof/actions/runs/40942189355/job/123688155935): passed.
- [Installed-demo job123691155527](https://github.com/auths-dev/auths-proof/actions/runs/40942189355/job/123691155527): passed, including all 36 existing cases and the repaired complete installed owner-browser journey.
- Evidence artifact **12928066979**, SHA256 **`f61da4e93df77739da78960f20d4baa994583b5126ddb1a2d820328e80c1d147`**, downloaded and checksum verified. Its `owner-journey.json` explicitly identifies exact source `d9618a56` and records unchanged native renderer, withheld pre-consent approvals, decline/no entry, substituted review refusal, private owner credential isolation, one write, independent read and browser/fresh-process replay without extra execution.
- Package artifact **12927612249**, SHA256 **`b240c4a5e3e0a1b37549fc8f971b6112ae9abea84b246688e7c967a39ba15f95`**, attributed to the same head.

This completes the requested CI-only fix. No additional changes or reruns were needed. Other automatically triggered workflows were preserved; no claim is made here that the entire new-head PR matrix is terminal or green. Owner actions are browser-simulated against a local provider; the artifact explicitly excludes human attention, production custody, live provider qualification, hostile OS and a full content/disclosure journey.

Saved records:

- `/tmp/ap074-ci-d961-evidence.json`: job records, artifact attribution and installed-job log.
- `/tmp/ap074-ci-d961-owner-journey.json`: verified hosted owner-journey manifest.
- `/tmp/ap074-ci-d961-airtable-evidence.zip`: checksum-verified hosted evidence archive.

Child checkout is clean. Main's previously cherry-picked duplicate `f6ef54a1` and unpublished work remain preserved; any future ancestry reconciliation belongs to a later authorized resumption, not this paused goal.
