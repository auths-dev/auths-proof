# AP074 holistic CI repair — ab980d10

Published source: `ab980d1028927ef7bb08159ac489153d767993d5`, PR #213.
Child repair: `31f71657190af6f5ad8348cdaa6db4dbd2742328`, one coherent seven-file commit, not pushed by child. Main integrates separately. Main/AP073/AP070 source and shared metadata/index were not modified by this investigation.

## Root matrix and repairs

| Root | Actual evidence | Repair |
| --- | --- | --- |
| Fresh owner container lacks counting ledger before its first provider request | [Airtable installed job123776995604](https://github.com/auths-dev/auths-proof/actions/runs/40967090762/job/123776995604): owner_browser.py calls provider_counts(), strict docker cat fails because provider.jsonl does not exist | Create the owned fixture ledger exclusively at startup with mode0600; refuse an existing path, never truncate retained counts. Counter readers remain strict. Add a regression proving initial empty evidence, mode, append and restart refusal; invoke it in the package workflow. |
| Managed recipe declares UTF-8/text/plain but actual Airtable-shaped response is application/json | Full installed owner reproduction reaches Python acquisition and native history rejects it with gateway.content.response-media-type | Use the existing native json-string projection at /fields/PrivateNote; regenerate the native review and document the narrower projection. Keep native media-type rejection and all bounds. Recipient assertion requires exact sentinel bytes rather than interpreting the entire record as content. |
| Second acquisition has the same rendered outcome label as the first | Reproduction reaches both native acquisitions but reads the first rendered Python result before the TypeScript response completes | Wait for the submit control to re-enable; require exact current operation_id and language. Keep outcome, counters, withheld-content and full native literal-review assertions. |
| Disclosure review assertion expects a nonexistent native.protocol field | Reproduction reaches separately approved disclosure review and raises KeyError | Require actual binding.protocol.kind=disclosure, native versioned disclosure schema, exact source operation and native/semantic disclosure equality. Native renderer output remains byte-for-byte unchanged. |

## Exact installed reproduction

Original package artifact `12939290801`, run `40967090762`, has ZIP SHA-256
`a2032da2971a0edcdcf118271b8a5eb6c9bb73cce45e068940583bbc8a6ad8e4`.
The ZIP, nested tar checksum, source_commit=ab980d10 and all41 manifest file hashes were verified before overlaying repairs. Package directory:
`/tmp/ap074-ci-ab980-airtable-package/airtable-gateway-demo`.

The Docker reproduction uses that package's original Linux x86_64 shipping and simulation gateways, wheel, npm/WASM artifacts and compiled TypeScript client. Only repaired demo payloads and browser assertions are overlaid. Host browser is Playwright1.62.0 with its installed Chromium; test driver changes only owned container name/output paths beyond the committed assertion repairs. This is local patched-payload evidence, not hosted success for the new commit.

Actual native review generation uses the original hosted shipping binary:

```text
auths-gateway review --recipe managed-recipe.json --profile-lock profile.lock.json
```

New managed recipe digest: `88f9e64b3f82ff6d369a31082d9e2b00890b0d676bb1c0c8e3610e961b1769eb`.

Results:

- `python3 demos/airtable-gateway/tests/test_provider_ledger.py`:1passed.
- Source-free Docker `--selftest`:36cases passed, production_qualification=false. Log `/tmp/ap074-ci-ab980-selftest.log`.
- Standard installed desktop/mobile browser:passed, log `/tmp/ap074-ci-ab980-browser.log`.
- Full installed owner browser:passed, log `/tmp/ap074-ci-ab980-owner-browser-disclosure.log` and artifact `/tmp/ap074-ci-ab980-owner-evidence/owner-journey.json`.
- The owner artifact asserts native literal renderer equality, withheld approval before consent, decline/substitution refusals, private operator files, separate owner origin, installed Python and TypeScript acquisition, separate disclosure consent, retained native ACK, exact0600 recipient bytes, no public HTTP content, no replay redelivery/refetch, same agent actor, exact write, independent recovery, unknown response loss and fresh-process replay without new entry.
- Both owned browser containers were stopped and removed. The disposable selftest container was automatically removed. Parent and unrelated PostgreSQL containers were untouched.

No native outcome, security deadline, media-type check, counter assertion, signature or consent requirement was weakened. No live-provider or human-attention qualification claim follows. No redundant broad local suites, secret scan, workflow reruns or cancellations were performed.

## Current hosted evidence

PG/source-contract jobs checked out PR merge `de85f0ffc03f6bc29244a2c69c8d74c071da453b`. Merge and published source have identical tree `3a4b23482a6a5fd7efc87692233405409fa44002`, fetched and compared.

[PG123774214713](https://github.com/auths-dev/auths-proof/actions/runs/40967090703/job/123774214713) passed all26 explicit native selectors exactly once, each1passed/0failed/0ignored, including both new epoch cases. Then installed-SDK information comparison22pairs and physical/WAL restore passed; restore retains replay_continuity_claim=false. [Python source123774214528](https://github.com/auths-dev/auths-proof/actions/runs/40967090693/job/123774214528) passed native mutation generator plus28request/26response comparisons.

Downloaded artifact ZIPs and checksums verified:

- Information/native-log12938568979: `c1be7c1114d6bbe8ec39214d05f849aea981bfa97e0a97e45c6cd32197fc9f55`.
- Mutation12937534434: `0aeef604c259ff01e79c131ddbe7ceddd8bad7da4443e7575d8f624902c71781`.

Per-selector evidence: `/tmp/ap074-ci-ab980-native-executions.json`.
Reports: `/tmp/ap074-ci-ab980-information-report.json`, `/tmp/ap074-ci-ab980-mutation-report.json`.

At repair handoff the only observed hosted failure is the Airtable owner journey. Main authoritative implementation, Kani and authoritative Lean are still running; final qualification is not yet established. Continued holistic observation will produce a terminal cohort report. Parent owns metadata regeneration and coordinated publication.
