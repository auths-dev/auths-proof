# AP-SPEC-056: OpenAPI-derived exact operation contracts and recipes

- **Status:** Draft; implementation has not started. AP-SPEC-053's recipe
  prerequisite has landed, and the manual real-vendor rejection wall
  (GitHub, Todoist, OpenAI) is published in
  `bindings/fixtures/openapi-corpus/` with open mapper findings. The Epic 1
  derivation corpus with expected outputs, the mappers, and packaged
  `derive` commands remain open; this specifies generation-time tooling, not
  a runtime or authorization change
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
