# Real-vendor OpenAPI rejection corpus (manual, pre-mapper)

This is AP-SPEC-057 Epic 4 step 1 evidence. `cases.json` records the selected
operations, document digests, every first-level rejection found by applying
AP-SPEC-056 §§3.1–3.3 without overrides, and the explicit narrowing choices
needed for a candidate derived operation. The source documents were read on
2026-09-21. No derivation mapper, `recipe check`, provider call, or effect
observation was run. The proposed override sets are **not** accepted recipes.

The full vendor bundles are not copied into this repository: GitHub's pinned
description is 13 MB, OpenAI's is 4.2 MB, and Todoist's is 1.2 MB. Source URL,
revision where available, exact byte length, and SHA-256 are recorded so a
later AP-SPEC-056 test can fetch and verify them as local files. A changed
Todoist URL is a new corpus input, not a silent update. The selected operation
and body-schema paths in `cases.json` make the analysis reproducible without
turning these source documents into runtime authority.

The three narrowed requests are intentionally small: create a GitHub issue
with `owner`, `repo`, and string `title`; create a Todoist task with `content`;
create an OpenAI vector store with `name`. Every omitted optional vendor field
is an explicit capability reduction. Provider-specific effect and read-back
meaning remain outside derivation and outside this corpus.

Open issues for the future mapper are recorded as findings, not silently
resolved: AP-SPEC-056's CLI does not define the root-object path spelling for
`--closed`; its character-count `minLength` to byte-count `min_bytes` mapping
does not preserve every non-ASCII minimum; and this hand review has not
measured each resolved operation's 256 KiB slice or run a recipe compiler.
