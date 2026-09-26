# OpenAPI derivation corpus

Expected output of `auths derive` for a fixed set of documents,
operations, and flags. One native mapper
(`product/tools/auths-openapi-derive`) produces every byte; the Python and
TypeScript CLIs call it through the Python extension and the WASM package, and
their tests replay this corpus through those bindings.

`cases.json` lists each case: the document, the derive arguments (without the
CLI's own `--openapi` and `--directory`), and whether the case derives or is
rejected. `expected/<case>/` holds:

| File | Derived cases | Rejected cases |
| --- | --- | --- |
| `profile.toml`, `recipe.json`, `derivation.json` | exact bytes the CLI writes | absent |
| `profile.lock.json` | the packaged profile generator's lock for that `profile.toml` | absent |
| `review.json` | the gateway recipe compiler's review, including the recipe digest | absent |
| `rejections.json` | absent | every code, JSON pointer, and resolving override, in order |
| `report.txt` | the report printed after writing | the rejection report; nothing is written |

Documents:

- `documents/minimal.json`: a hand-written API exercising API-key and bearer
  security, security and server selection, base paths, form and JSON bodies,
  nested objects, literals, unions, and bounds.
- `documents/hostile.json` and `documents/hostile-*`: one operation or one
  document per construct that derivation must reject.
- `documents/airtable-record-update.json`: the Airtable demo table update. Airtable
  publishes no OpenAPI document, so this one is hand-written for the demo base.
- `documents/todoist-rest-create-task.json`: an excerpt of the pinned Todoist
  operation that CI can derive without the upstream bytes.
- GitHub, Todoist, and OpenAI vendor documents are not committed. They are
  pinned by digest in `../openapi-corpus/cases.json`; their cases run when
  `AUTHS_OPENAPI_CORPUS_DIR` holds `github.json`, `todoist.json`, and
  `openai.json`, and are skipped otherwise.

Regenerate after a reviewed mapper change, then review the diff:

```text
AUTHS_OPENAPI_DERIVATION_UPDATE=1 cargo test -p auths-openapi-derive --test corpus
AUTHS_OPENAPI_DERIVATION_UPDATE=1 python -m pytest bindings/python/tests/test_openapi_derivation.py
AUTHS_OPENAPI_DERIVATION_UPDATE=1 cargo test -p auths-openapi-derive --test corpus
cargo test -p auths-openapi-derive --test corpus
```

The first command rewrites the derived files and rejection lists, the second
rewrites `profile.lock.json` with the packaged generator, the third compiles
every derived recipe against those locks and records `review.json`, and the
last checks the result without writing.

What this corpus shows: the derived contract and recipe for each case, that
every derived recipe compiles under the gateway recipe compiler, and the exact
rejection for each unsupported construct. It does not show that a document
describes its provider accurately or that any derived request has the effect
the document describes.
