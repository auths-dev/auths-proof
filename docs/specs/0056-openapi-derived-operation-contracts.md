# AP-SPEC-056: OpenAPI-derived exact operation contracts and recipes

- **Status:** Epics 1 and 2 implemented on branch `epic-6-openapi-derivation`
  with repository-local tests; no hosted CI result is cited yet. Epic 3
  (observation derivation, a MAY) is not started; §8.3 says why. One native
  mapper, `product/tools/auths-openapi-derive`, produces every derived byte
  and both packaged CLIs call it. The derivation corpus is in
  `bindings/fixtures/openapi-derivation/`. §8 records every reading and
  deviation. This is generation-time tooling only; it changes no runtime or
  authorization behavior
- **Depends on:** [AP-SPEC-053](0053-declarative-credential-isolated-gateway.md)
  (recipe AST and `recipe check`), [AP-SPEC-054 §5](0054-self-hosted-adapter-developer-experience.md)
  (restricted schema, lock, vectors), and
  [AP-SPEC-055](0055-closed-enumeration-fields.md) (enum node)
- **Resolves:** the "OpenAPI extensions and typed action generation" item
  deferred in [AP-SPEC-024 §29](0024-transport-neutral-rest-api-authorization.md)
- **Scope:** one packaged command that reads a local OpenAPI document and one
  `operationId` on the developer's machine and writes a reviewable
  `profile.toml`, `recipe.toml`, and provenance record; everything downstream
  is unchanged
- **Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** specify
  implementation requirements

## 1. Decision and claim

Auths will derive an exact operation contract and its declared request recipe
from a single OpenAPI operation, at generation time, into ordinary source
files in the consumer's repository. The developer reviews those files, the
operator approves the compiled recipe digest exactly as in AP-SPEC-053, and
the gateway never sees the OpenAPI document. This removes the hand-authoring
step for each new provider operation without adding a runtime input, a
second trust path, or a provider semantics claim.

The claim boundary does not move. A derived contract commits to the same
canonical action bytes as a hand-written one. A derived recipe is compiled,
digested, and approved by the same path. The OpenAPI document is an
**untrusted, bounded, generation-time input**; nothing in it becomes
authority, and the derivation tool MUST fail closed on any construct the
restricted schema or recipe language cannot express. "Support any API" is
not an exit criterion; "derive the operations that fit, and say precisely
why the others do not" is.

AP-SPEC-024 §4 still holds: no OpenAPI document is accepted from a caller at
runtime. Derivation runs where `auths-profile init` runs, produces files the
developer commits, and is finished before any proof is authored.

## 2. UX

```text
$ auths-profile derive \
    --openapi ./vendor/todoist-v2.yaml \
    --operation createTask \
    --service todoist --name create-task \
    --server https://api.todoist.com \
    --max-bytes content=256 --max-bytes description=1024 \
    --max-items labels=8 --omit due_string --require project_id

  document:   sha256:3f9a…  (todoist-v2.yaml, 412 KiB, OpenAPI 3.0.3)
  operation:  POST /rest/v2/tasks  (createTask)
  security:   bearer (http/bearer "token"); acquisition is application-owned
  arguments:  6 fields, depth 2, worst-case 1.9 KiB canonical JSON
  recipe:     POST https://api.todoist.com/rest/v2/tasks  body: application/json
  omitted:    due_string (--omit), id (readOnly), url (readOnly)
  overrides:  content.max_bytes=256 description.max_bytes=1024 labels.max_items=8
              project_id.required=true
  wrote:      profile.toml recipe.toml derivation.json
  next:       auths-profile generate && auths gateway recipe check recipe.toml
  claim:      derived shape only; provider effect unqualified

$ auths-profile derive --openapi ./vendor/todoist-v2.yaml --operation updateTask ...
  REJECTED  contract
    parameters[in=query] "reveal_completed": query parameters are not in the
    recipe language (AP-SPEC-053 §3.2)
    requestBody.properties.priority: integer without minimum/maximum;
    pass --range priority=1:4 or --omit priority
  nothing written
```

The complete override set is `--max-bytes`, `--range`, `--max-items`,
`--require`, `--omit`, `--closed`, `--pick`, `--literal`, `--server`,
`--security`, `--security-scheme`, and `--tool`. Every rejection names the
JSON pointer, the rule, and the override that would resolve it, if one exists.
Overrides are explicit flags and are recorded in
`derivation.json`; the tool never guesses a bound, a server, or a security
scheme. Re-running `derive` against a changed document or with different
overrides produces a diff and requires a `[profile].version` bump before
`generate`, exactly as a hand edit would.

The TypeScript CLI exposes the same command with the same flags, diagnostic
codes, and byte-identical output for the same inputs.

## 3. Architecture

```text
 OpenAPI document (local, bounded)  +  operationId  +  explicit overrides
                          |
                          v
            bounded parse -> resolve local $ref -> select operation
                          |
          +---------------+-----------------+
          v                                 v
   argument mapper                    request mapper
   (OpenAPI schema -> 054/055 nodes)  (path/body/security -> 053 recipe AST)
          |                                 |
          v                                 v
      profile.toml                      recipe.toml
          \                                 /
           +---------- derivation.json ----+
                          |
                          v
         existing: profile generate / check / diff
         existing: gateway recipe check / install / approve
```

Derivation is a pure function of (document bytes, `operationId`, overrides,
generator format). It has no network access, reads no credential, and writes
only the three files above into an empty or already-derived directory.

Prefer one deterministic mapper in the native module with thin Python and
TypeScript bindings. Where a packaged CLI cannot load the native module, the
language implementation MUST pass the full derivation corpus in §6 before
release; two mappers that disagree on any corpus entry are a release blocker,
not a documentation note.

### 3.1 Input bounds

| Input | Rule |
| --- | --- |
| Document | local regular file, not a symlink, ≤ 32 MiB (vendor bundles such as GitHub's exceed 10 MiB); JSON or YAML parsed by a safe loader with no anchors/aliases expansion beyond 64 nodes, no custom tags, depth ≤ 32 |
| Operation slice | the selected operation object plus every component it transitively references MUST fit in 256 KiB after `$ref` resolution; the rest of the document is never retained |
| Version | `openapi` field `3.0.x` or `3.1.x`; Swagger 2.0 rejected |
| `$ref` | local (`#/...`) only; remote and file references rejected; ≤ 256 resolutions per derivation; cycles rejected |
| `operationId` | exactly one match; missing or duplicate rejected; MUST satisfy the tool-name regex or `--tool` supplies a compliant name |
| `servers` | exactly one `https` URL with no server variables, or `--server` matching one listed entry byte-for-byte; `http`, variables, and unlisted values rejected |
| `security` | resolves to exactly one requirement whose scheme is `http`/`bearer` or `apiKey` with `in: header`; alternatives (OR) require `--security <name>` selecting one supported requirement; `oauth2` is accepted as bearer at request time only and MUST be reported as "acquisition is application-owned". `apiKey` with `in: query` or `in: cookie`, and `http`/`basic`, are rejected with `contract.derive.credential-scheme-out-of-scope`, with no override. A document that declares no security requirement (GitHub's public document is one) requires `--security-scheme bearer` or `--security-scheme apikey:<Header-Name>`, recorded in `derivation.json`; this flag cannot override an explicitly declared incompatible scheme. The derived recipe records the scheme type and, for `apiKey`, the header name as a requirement; the operator's AP-SPEC-053 connection binding names the injection header, and `recipe check` fails if they disagree. AP-SPEC-056 MUST NOT widen AP-SPEC-053's static-credential-in-one-header scope. |

### 3.2 Argument mapping

The request body schema (for `application/json`) and `in: path` parameters
become the root object of `profile.toml`. Order is the document's property
order for readability; it has no effect on canonical bytes.

| OpenAPI construct | Result |
| --- | --- |
| `type: string` with `maxLength` | `string`; `max_bytes = min(maxLength, 4096)` — OpenAPI counts characters and the contract counts UTF-8 bytes, so the byte bound equals the character bound (every string within `maxLength` ASCII characters fits; multibyte strings near the limit are rejected); `--max-bytes path=N` MAY widen up to `min(4 × maxLength, 4096)`; `min_bytes = minLength ?? 0` |
| `type: string` without `maxLength` | rejected unless `--max-bytes path=N` |
| `type: string` with `enum` of strings | `enum` (AP-SPEC-055); > 32 variants or non-conforming variant rejected |
| `type: string` with `format: byte`, `binary`, `date-time`, etc. | `string`; formats are not validated; `byte`/`binary` bodies are rejected in this format |
| `type: integer` with `minimum` and `maximum` inside the safe range | `integer` |
| `type: integer` otherwise | rejected unless `--range path=min:max` |
| `type: number` | rejected; no floats in the command API |
| `type: boolean` | `boolean` |
| `nullable: true` (3.0) or `type: [T, "null"]` (3.1) | `nullable` around the mapped node |
| property not in `required` | rejected unless `--require path` (treated as required) or `--omit path` (excluded from arguments and recipe); the recipe body is fixed-shape, so "absent" has no encoding |
| `type: object` with `properties` and `additionalProperties: false` | `object` |
| `type: object` with `additionalProperties: true` or a schema | rejected; free-form maps are not in the schema |
| `type: object` with `additionalProperties` absent | rejected unless `--closed path` declares the object closed; most vendor documents omit the keyword, so this override is expected and is recorded |
| `type: array` with `items` and `maxItems` | `array`; `min_items = minItems ?? 0` |
| `type: array` without `maxItems` | rejected unless `--max-items path=N` |
| `oneOf` or `anyOf` whose alternatives are all scalars (`string`, `integer`, `boolean`) | rejected unless `--pick path=<type>` selects exactly one alternative; the selection is recorded (GitHub's `issues/create` `title` is `string \| integer`) |
| any other `oneOf`, `anyOf`, `allOf`, `not`, `discriminator` | rejected; no override |
| `readOnly: true` | omitted from arguments and recipe; listed under `omitted` |
| `default`, `example`, `description`, `deprecated` | ignored for the contract; `description` MAY be copied into a comment |
| depth > 4, > 32 named fields, or worst-case canonical JSON > 4 KiB | rejected with the offending pointer |

`in: query`, `in: header`, and `in: cookie` parameters are rejected: the
AP-SPEC-053 recipe language has no typed query or dynamic header form. A
later revision of 0053 MAY add a typed query segment; this spec does not.

### 3.3 Request mapping

| OpenAPI construct | Recipe result |
| --- | --- |
| path template `/a/{id}/b` | fixed segments `a`, `b`; typed percent-encoded segment bound to argument `id` |
| method | one of `POST`, `PUT`, `PATCH`, `DELETE`; `GET` and every other method are rejected for the write recipe, matching AP-SPEC-053's first scope of one write; `GET` is accepted only by Epic 3's `--observe-operation` |
| `requestBody` `application/json` | fixed-shape JSON body whose keys are the mapped properties and whose values are typed field references; no literals unless `--literal key=value` |
| `requestBody` `application/x-www-form-urlencoded` with scalar properties only | form body of typed field references |
| any other media type, multiple media types, or a `required: false` body | rejected |
| security scheme | a credential requirement (`bearer`, or `apikey` with one header name) that the operator's connection binding must satisfy; the gateway injects the secret into that one operator-bound header; the recipe never contains a value or a caller-chosen injection header |
| `servers` | the single operator-pinned origin |
| responses | unused; observation is not derived in this format |

The recipe MUST compile under `auths gateway recipe check` without edits. If
the compiler's limits (fields, depth, bytes, timeout, redirects) are tighter
than this spec, the compiler's limits win and derivation reports them.

### 3.4 Provenance

`derivation.json` records the schema `auths.openapi-derivation/1`, the
document sha256 and byte length, `openapi` version, `operationId`, method and
path, server, security scheme name and type, every override, every omitted
pointer with its reason, the generator format, and the sha256 of the written
`profile.toml` and `recipe.toml`. `profile check` verifies those two digests
when `derivation.json` is present. A hand edit to a derived file is allowed;
it changes the digest, `check` reports "derived file edited by hand", and
the developer either re-derives or removes `derivation.json` to declare the
files hand-owned. There is no silent re-derivation.

## 4. APIs

Derivation adds no public runtime type. The generated `profile.toml` and
`recipe.toml` are consumed by the existing AP-SPEC-054 generator and the
AP-SPEC-053 compiler. The only new public surface is the CLI command and its
diagnostic codes, which use the `contract` stage from AP-SPEC-054 §8 with a
`derive` sub-code and a JSON pointer:

```text
contract.derive.unbounded-string      #/components/schemas/Task/properties/content
contract.derive.unsupported-construct #/paths/~1tasks/post/requestBody/.../oneOf
contract.derive.query-parameter       #/paths/~1tasks/get/parameters/0
contract.derive.ambiguous-server      #/servers
contract.derive.ambiguous-security    #/security
contract.derive.optional-property     #/components/schemas/Task/properties/priority
```

Each code has one human sentence and, where an override exists, its exact
flag. Both CLIs emit the same codes.

## 5. Epics and acceptance

### Epic 1 — Mapper and corpus

1. Write the derivation corpus first: at least three OpenAPI documents
   (GitHub's published `api.github.com.json` with `issues/create`, one
   hand-written minimal, one hostile), each with several `operationId`s and
   override sets, and for each case the expected `profile.toml`,
   `recipe.toml`, and `derivation.json` bytes or the expected rejection code
   and pointer. The GitHub case MUST record both the unmodified rejection
   list and the override set that makes it derive; that list is the measured
   rejection wall and is published with the corpus.
2. Implement the bounded parser, local `$ref` resolver, argument mapper, and
   request mapper in the native module or, if unavoidable, in each language
   under the corpus gate.
3. Reject every construct in §3.2 and §3.3 marked rejected, with the
   pointer and override in the diagnostic.

**Acceptance:** every corpus case produces byte-identical output in every
implementation; every rejected case names the pointer and the resolving
override; no derivation reads the network or a credential.

### Epic 2 — Packaged command and round trip

1. Add `auths-profile derive` to the Python and TypeScript CLIs with the
   flags in §2 and the codes in §4.
2. Wire `derivation.json` verification into `profile check` and the
   "edited by hand" diagnostic into `profile diff`.
3. Derive the Airtable field update and Todoist task creation from
   vendor or hand-written documents, run `profile generate` and
   `gateway recipe check`, and compare the resulting action identity and
   recipe digest with the hand-authored versions from AP-SPEC-053 Epic 1.

**Acceptance:** a clean packed Python and npm consumer each derive, generate,
and compile one operation without editing Auths; a changed document or
override cannot pass `check` under the same version; the derived Airtable
and Todoist recipes compile and, where the hand-authored recipe expressed the
same request, produce the same digest.

### Epic 3 — Observation derivation (MAY)

1. Accept `--observe-operation <operationId>` naming a `GET` whose path
   parameters are all covered by the write's arguments, and
   `--observe-compare response.pointer=argument` pairs.
2. Emit the AP-SPEC-053 read-only observation block with a bounded response
   projection and exact comparison.

**Acceptance:** the derived observation compiles and, on the Todoist fixture,
matches the hand-written read-back. This epic does not block Epics 1–2.

## 6. Non-goals

- Reading an OpenAPI document at runtime, from a caller, or from a URL.
- Importing an API surface: every derivation names one `operationId`.
- Inferring bounds, servers, security schemes, required-ness, or defaults
  that the document does not state; every gap is an explicit override.
- Query, header, or cookie parameters; multipart, binary, or streaming
  bodies; `oneOf`/`anyOf`/`allOf`; free-form objects; floats; Swagger 2.0.
- OAuth token acquisition, refresh, or scope negotiation.
- Any claim that a derived recipe matches provider semantics, that the
  document is accurate, or that the operation is idempotent.
- Generating adapters for the self-hosted (051–054) path from OpenAPI; that
  path keeps hand-written adapters by design.

## 7. Verification and release boundary

Development is corpus-first: the §5 Epic 1 corpus exists before the parser
or mappers. Hosted CI is the verification gate under the repository policy;
this specification does not run checks or assert their outcome. The command
ships only when both packaged CLIs pass the whole corpus on one reviewed
revision and AP-SPEC-053's `recipe check` accepts every derived recipe in it.
Derivation changes nothing in the claim ledger: the contract and recipe it
writes are reviewed source, the gateway's guarantees are AP-SPEC-053's, and
provider effect remains unqualified.

## 8. Readings fixed during implementation

### 8.1 Readings

| Question | Reading |
| --- | --- |
| Where the mapper lives | One Rust crate in the product layer, `product/tools/auths-openapi-derive`. Python calls it as `auths._native.derive_openapi_operation_v1`; TypeScript calls the WASM export `deriveOpenapiOperationV1` from `tools/profile-cli.mjs`. Both return the same JSON result, so outputs match by construction. The mapper also parses the derive flags, so flag grammar cannot differ by language. Each CLI owns only `--openapi`, `--directory`, and `--json`, plus file reading and writing. |
| Recipe file name | `recipe.json`, not `recipe.toml`. The compiler, the fixtures, and `auths gateway recipe check` all read the `auths.gateway-recipe-source/1` JSON source. The §2 example's `recipe.toml` is read as the recipe file. |
| YAML | Not read. A document whose first non-space byte is not `{` fails with `contract.derive.document-format` and the advice to convert with a safe loader. No YAML dependency was added. JSON is parsed into a bounded tree: at most 32 MiB and 32 levels of nesting, with duplicate keys rejected at every depth. |
| Gateway binding fields | Derivation writes the three fields the compiler requires ahead of the derived fields. `operator_namespace` is a one-variant enum taken from the new required flag `--operator-namespace`. The tool never guesses a namespace. `operation_id` is a 1–128-byte string, the compiler's full bound. `recipe_digest` is exactly 64 bytes. A document property or parameter with one of these names fails with `contract.derive.name-collision`. The other identity flags are `--operation`, `--service`, and `--name` (required) and `--version` (default 1). |
| Server base paths | A server URL becomes the origin (`https://host`) plus fixed leading path segments. `https://api.openai.com/v1` becomes the origin and `v1`. One trailing slash is dropped, so `https://api.todoist.com/` becomes the bare origin. `contract.derive.unsafe-server` rejects the rest, with no override: `http`, server variables, ports, user information, a query or fragment, an IP-literal or uppercase host, `localhost`, `.local`, `.internal`, empty inner segments, and segments outside the compiler's fixed-segment characters. Operation servers override path-item servers, which override root servers. `--server` must match a listed URL byte for byte. |
| Root spelling for `--closed` | The root request-body object is spelled `.`. Every other override path is a dotted property path (`fields.DemoStatus`), and parameters are named directly. `body` is an ordinary property path. GitHub's `issues/create` has a `body` property, which is exactly the ambiguity the finding named. The published corpus now uses `--closed .`. |
| `minLength` counts characters | `min_bytes = minLength`, as in §3.2. When `minLength` exceeds 1, the contract admits a multibyte value with fewer characters than the minimum, and the provider must reject it. `derivation.json` lists this under `unenforced`, and the report prints it. `pattern` and non-binary `format` are recorded the same way. The contract never claims to enforce them. |
| Nullable spellings | `oneOf`/`anyOf` alternatives, 3.1 `type` arrays, and 3.0 `nullable: true` are normalized into one list of alternatives, so `anyOf [T, {type: null}]` is recognized as a nullable `T`. The gateway compiler has no nullable field. A required nullable property therefore fails with `contract.derive.compiler-limit`, and `--pick path=T` resolves it: the derived request always sends a `T`. An optional one still takes `--omit` or `--require` first. |
| Compiler limits win | The compiler accepts only root-level string, enum, integer, and boolean fields. Nested closed objects are flattened into root arguments, named by joining the property path with `_`: `fields.DemoStatus` becomes `fields_DemoStatus`. The recipe body keeps the nesting. Arrays, nullable fields, objects in form bodies, and integer or boolean path parameters fail with `contract.derive.compiler-limit`. `--max-items` is parsed and consumed, but no current recipe can carry an array. Also enforced: at most 32 fields including the three binding fields, 64 template nodes, 16 form fields, and 16 path segments. An operation without a request body is rejected, because the compiler needs a non-empty body. |
| Path parameters | A string path parameter gets `min_bytes` of at least 1, because the gateway refuses an empty segment at request time. `--literal name=<value>` fixes a path parameter as a checked fixed segment, including an integer. Mixed segments such as `{id}.json` and a trailing slash have no recipe form. |
| Form bodies | Scalar properties only. Integer and boolean fields are rendered as compiler-serialized JSON form values. |
| Query, header, and cookie parameters | `--omit name` means an optional one is never sent, and it is recorded as omitted. A required one is rejected with no override. Header and cookie parameters use `contract.derive.unsupported-parameter`. |
| Overrides | Every override must apply to a construct, or it fails with `contract.derive.unused-override`. That code is reported only when nothing else is rejected. `--omit` on a required property is `contract.derive.invalid-override`. `--max-bytes` may narrow or widen up to `min(4 × maxLength, 4096)`. `--range` may only narrow a bound the document states. `--literal` takes `true`, `false`, a safe integer, or a JSON string of at most 1024 bytes, and the value must satisfy the schema it replaces. `--pick` selects exactly one scalar alternative. |
| Security | `oauth2` maps to bearer, reported as "acquisition is application-owned". `openIdConnect`, `mutualTLS`, `http` schemes other than bearer, `apiKey` in a query or cookie or in a reserved header such as `Authorization`, and a requirement combining schemes are rejected with `contract.derive.credential-scheme-out-of-scope`. A missing, empty, or `[{}]` requirement list counts as declaring none. It fails with `contract.derive.missing-security` and needs `--security-scheme`. `--security` selects a single-scheme requirement by scheme name. |
| Tool name | `--tool`, or the `operationId` when it satisfies the tool grammar. Otherwise `contract.derive.tool-name` suggests a sanitized name, such as `--tool issues_create`. |
| Document constructs | Only local `#/` references are followed, and a reference containing `%` is rejected. A referenced path item is rejected, because it hides operations from selection. A keyword other than `description` or `summary` beside `$ref` is rejected. Keywords outside the annotation and mapped sets are rejected with their pointer. The slice measurement reproduces the published corpus figures exactly: 45, 2, and 15 resolutions, and 70 346, 9 455, and 8 960 bytes. |
| What derivation does not emit | `echo`, `observation`, and `preconditions` blocks. A derived recipe is a single write. |
| Provenance | `derivation.json` records the fields in §3.4 and `generator_format: 2`. It also lists the derived arguments with their pointers and the `unenforced` constraints. Overrides are recorded in one normalized order, so flag order cannot change the bytes. The document's file name appears only in the printed report. |
| Re-derivation and `check` | `derive` writes only into an empty directory or one that already holds `derivation.json`. It refuses `profile.toml` or `recipe.json` without `derivation.json` (`contract.derive.directory-not-derived`). It refuses a changed derivation unless `--version` exceeds the recorded version (`contract.derive.version-required`). An unchanged re-derivation is a no-op. `profile check` reports `<file>: derived file edited by hand` when a digest differs; its JSON code is `profile.contract.derived-edited`. `profile diff` prints the same line for each edited file and returns `derived_edits`. Deleting `derivation.json` makes the files hand-owned. |
| CLI-only codes | `contract.derive.document-unreadable` covers a symlink, a non-regular file, and the size bound. `contract.derive.directory-not-derived` and `contract.derive.version-required` are the directory and version rules above. The mapper's codes are `invalid-request`, `document-invalid`, `document-format`, `unsupported-version`, `operation-not-found`, `duplicate-operation`, `unsupported-method`, `tool-name`, `remote-ref`, `ref-cycle`, `ref-limit`, `slice-limit`, `ambiguous-server`, `unsafe-server`, `ambiguous-security`, `missing-security`, `credential-scheme-out-of-scope`, `query-parameter`, `unsupported-parameter`, `unsupported-body`, `unbounded-string`, `unbounded-integer`, `unsupported-construct`, `scalar-union`, `optional-property`, `open-object`, `compiler-limit`, `enum-variant`, `invalid-name`, `name-collision`, `field-limit`, `invalid-override`, and `unused-override`, each under `contract.derive.`. |

### 8.2 Corpus and comparison results

The corpus has 74 cases. Derived cases have exact bytes for `profile.toml`,
`recipe.json`, `derivation.json`, the generator's `profile.lock.json`, and
the report. Rejected cases have exact codes, pointers, and resolving
overrides. Every derived recipe compiles under the gateway compiler, passes
the operator credential-header binding, and records its digest in
`review.json`.

- **GitHub `issues/create`.** Unmodified, the pinned document yields the
  published 14-pointer rejection wall exactly. The published candidate
  override set derives, with the root spelled `.`. A second case fixes
  `owner` and `repo` as literals and keeps `body`, which is the request the
  hand-authored fixture expresses. Its digest differs from the fixture's
  only because the profiles differ: the document states no title minimum,
  so the derived title is 0–128 bytes, not 1–128, and the derived logical
  ID allows 128 bytes, not 64. With the fixture's profile digest
  substituted, the derived recipe compiles to exactly the fixture's digest.
- **Todoist task creation.** The vendor document and a committed excerpt
  derive identical `profile.toml` and `recipe.json`. Service, tool, and
  operator namespace equal the hand-authored fixture. The request does not:
  the derivation is `POST /api/v1/tasks` with a JSON `content` body, while
  the fixture uses the sync endpoint with a form-encoded `item_add` command
  that carries the logical ID as its `uuid`. The digests differ for that
  reason, as the published corpus predicted. Derivation has no flag that
  maps a body property to a binding field.
- **Airtable field update.** Airtable publishes no OpenAPI document, so the
  corpus uses a hand-written one for the demo base and table. Origin,
  method, path, credential, service, tool, and namespace equal the
  hand-authored fixture. The digest differs for two reasons. The body field
  keeps its structural name `fields_DemoStatus`, where the fixture uses
  `replacement`, and there is no rename flag. The fixture also declares a
  read-back observation and an echo field, which derivation does not
  produce.
- **OpenAI `createVectorStore`.** The published wall and candidate override
  set reproduce, and the `v1` base path becomes a fixed segment.

### 8.3 Not done

- **Epic 3.** Not started. The compiler's observation needs a
  response-byte cap, and this spec names no flag for one, so the tool would
  have to guess a bound. The Todoist fixture that the acceptance names has
  no read-back to match. The Airtable fixture has one, but its argument
  names differ from a derivation.
- **Vendor cases in hosted CI.** The three vendor documents are pinned by
  digest and not committed. Their corpus cases, and the checks that compare
  them with the published wall, run only when `AUTHS_OPENAPI_CORPUS_DIR`
  holds the documents. Hosted CI does not fetch them, so CI verifies the
  committed documents only. That covers the Todoist excerpt, the Airtable
  document, the minimal document, and the hostile documents.
- **Packaged consumers.** The installed-wheel consumer
  (`bindings/python/external/openapi_derive_consumer.py`) and the packed npm
  test derive, generate, and check one operation from committed fixtures.
  Neither runs the Rust recipe compiler, which is not part of either
  package. That compilation is proved by the Rust corpus test on the same
  bytes.
