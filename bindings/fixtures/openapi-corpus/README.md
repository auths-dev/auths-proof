# Real-vendor OpenAPI rejection corpus (manual, pre-mapper)

This is the measured rejection wall that AP-SPEC-057 Epic 4 step 1 asks for
and that AP-SPEC-056 Epic 1 must start from. `cases.json` records three real
vendor operations, the SHA-256 and byte length of each pinned source document,
every rejection found by applying AP-SPEC-056 §§3.1–3.3 by hand without
overrides, and the override set that narrows each operation to a candidate
derivation. The mapping was done on 2026-09-21 and re-checked against the same
source bytes and against `main` on 2026-09-23.

What was checked, and what was not:

| Item | Status |
| --- | --- |
| Source digests and byte lengths | re-fetched and matched on 2026-09-23 |
| Rejection lists against each operation and its referenced schemas | checked by hand, then re-read from the parsed documents |
| Operation slice size and `$ref` count | measured (method in `cases.json`); all three are far below the 256 KiB and 256-resolution limits |
| Tool names against the packaged profile grammar | checked; only GitHub's `issues/create` fails |
| Candidates against the recipe compiler's origin and binding-field rules | read from the compiler source; gaps recorded as findings |
| A derivation mapper, `profile generate`, or `gateway recipe check` | checked on 2026-09-23: the native mapper reproduces each rejection wall's pointers, the candidate override sets derive, and every derived recipe compiles; exact outputs are in `../openapi-derivation/` |
| Provider behavior or effects | **not checked** |

The upstream documents are not committed. GitHub's pinned description is
13 MB, OpenAI's is 4.2 MB, and Todoist's is 1.2 MB. The manifest records the
source URL, the revision where one exists, the exact byte length, and the
SHA-256, so a mapper test can fetch the bytes once and verify them locally.
Mapper parity requires those exact bytes. Todoist publishes at an unversioned
URL: if its bytes change, that is a new corpus case, not an update to this
one.

The three candidates are deliberately small: a GitHub issue with `owner`,
`repo`, and a string `title`; a Todoist task with `content`; an OpenAI vector
store with `name`. Each omitted optional field is an explicit narrowing of
what the vendor operation can do. The proposed overrides are not accepted
recipes. Provider effects and read-back meaning are not part of derivation and
are not part of this corpus.

The mapper findings listed under `findings` in `cases.json` are resolved. The
root body object is spelled `.` in override paths, so the candidate sets use
`--closed .`. `minLength` maps to `min_bytes` and is recorded as unenforced
when it exceeds 1. `anyOf [T, null]` is recognized as nullable. Server base
paths become fixed leading segments. Derivation writes the gateway binding
fields. AP-SPEC-056 records each reading, and the derivation corpus in
`../openapi-derivation/` holds the resulting outputs.

`bindings/python/tests/test_openapi_corpus.py` checks the manifest's shape and
internal consistency. When `AUTHS_OPENAPI_CORPUS_DIR` names a directory that
holds the source documents as `github.json`, `todoist.json`, and
`openai.json`, the test also checks their bytes against the pinned digests.
