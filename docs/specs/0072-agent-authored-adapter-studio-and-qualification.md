# AP-SPEC-072: Agent-authored adapter proposals and qualification

- **Status:** Draft; no implementation or qualification is claimed by this spec.
- **Date:** 25 October 2026.
- **Scope:** Let an agent rapidly propose a new provider adapter from bounded provider documentation, OpenAPI, or a database schema, then make its limits, authority, execution path, and evidence reviewable before activation. This is an authoring and qualification interface, not permission for generated code to run inside the gateway.
- **Depends on:** [AP-SPEC-054](0054-self-hosted-adapter-developer-experience.md), [AP-SPEC-056](0056-openapi-derived-operation-contracts.md), [AP-SPEC-063](0063-generalized-gateway.md), [AP-SPEC-066](0066-production-gateway-polish-and-recipe-qualification.md), [AP-SPEC-071](0071-human-agent-read-write-delegation-demo.md), [ADR 0012](../adr/0012-declarative-credential-isolated-gateway-boundary.md), [ADR 0013](../adr/0013-recipe-capabilities-and-sum-budget.md), and the [domain boundary plan](../target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md).
- **Normative terms:** MUST and MUST NOT are requirements. Suggested command and record names are proposed interfaces, not claims about shipping code.

## 1. Product claim and trust boundary

A person should be able to say, “Let this agent use my connected account to read these records and make this kind of update for the next 30 minutes,” even when the provider is new to Auths. An agent can help describe the provider and draft the adapter. **Drafting does not install an adapter, connect an account, qualify provider behavior, or grant the agent access.** The person sees a meaningful task and concrete limits, not a raw HTTP recipe or SQL statement.

The standard interface produces a closed, inspectable adapter proposal. Auths checks its shape, bounds, provenance, and conformance. A reviewer separately accepts provider semantics; an operator pins and enables an exact immutable recipe and credential connection; a release process may qualify a specific recipe tuple after protected evidence. A human task grant then narrows that installed capability to one agent, account, resource set, time window, and read/write budget. Provider permissions remain an independent ceiling. None of these steps can be inferred from success at another step.

There are two authoring paths with different claims:

| Path | Credential and effect owner | Result |
| --- | --- | --- |
| Application-owned SDK adapter ([054](0054-self-hosted-adapter-developer-experience.md)) | The application | Fast integration with native proof verification and a local conformance kit; provider execution is application-owned and unqualified by Auths. |
| Auths-managed adapter proposal (this spec) | Installed Auths gateway or a separately admitted execution family | Credential-isolated, data-only execution after exact operator installation; a qualified claim requires the [066](0066-production-gateway-polish-and-recipe-qualification.md) evidence wall. |

The studio MUST label these paths distinctly. Importing an SDK adapter or passing local tests MUST NOT silently promote it to a managed or qualified adapter.

## 2. Authoring journey

1. A developer or agent supplies bounded, version-pinned source material: a local OpenAPI document, selected operation IDs, provider documentation snapshots, or a database schema snapshot. The proposal records source bytes, retrieval location, date, digest, selected slices, and every human override. External text is untrusted data, including instructions embedded in descriptions or examples. The authoring agent cannot execute instructions from that text or obtain an Auths/provider credential through this workflow.
2. The studio derives candidate **read, update, and create** operations only from admitted capability families. For each it shows the exact request or statement template, typed arguments, maximum response/release size, resource and field bounds, connection subject, preconditions, expected effect, observation, retry/recovery assumptions, and excluded behavior. It marks every unsupported or unproven provider assumption; it never fills a missing limit with an unbounded default.
3. A human reviewer edits and accepts the semantic contract and a test-only reference oracle. The output is a proposal bundle, not executable runtime code. It includes a profile lock, immutable recipe source and compiled digest, provenance manifest, corpus, operator review text, risk/claim summary, and a diff from any installed version. AP-SPEC-056's deterministic mapper remains the OpenAPI path where its grammar applies; this spec does not introduce a second mapper that interprets the same document differently.
4. The author runs local compile, lint, differential, hostile, and simulated recovery checks. The UI reports `draft`, `structurally valid`, and `locally conformant` separately. These labels confer no provider access and no qualified claim.
5. An authorized operator reviews the exact compiled digest, origin or database target, connection subject, credential mode and generation, resource and field allowlists, budgets, recovery rule, and evidence. Installation begins disabled. The operator binds a least-privilege credential through the existing custody plane, runs account/permission probes where the recipe requires them, and explicitly enables the connection. A source change requires a new compiled digest and review; no mutable “latest” recipe can be followed at runtime.
6. If a managed production claim is requested, the family supplies the ADR, independent oracle, hostile and live corpus, protected run, signed expiring attestation, and runtime tuple gate required by AP-SPEC-066. Only the release verifier derives `qualified`; neither the agent, studio, registry, nor operator sets that state. Unqualified development installations remain labeled as such.
7. The person connects a provider account and signs an AP-SPEC-071 task using the installed capabilities. The task card names the actual provider account, agent identity, resources, allowed actions, expiry, byte/call/write budgets, and write approval mode. The agent receives neither the provider token nor the human signing key. Exact confirmation remains the default for consequential writes; a reviewed bounded-upfront mode remains available where policy permits it.

The interface SHOULD generate understandable examples such as “read only project `P` fields `title,status`, at most 10 records,” and “update only `status` on those records, once.” It MUST also show what it cannot infer: whether the provider enforces the claimed account scope, whether a write is idempotent, whether a search is complete, and whether an ambiguous response means an effect occurred.

### 2.1 Proposed interface and handoff

The following is the intended user-facing interface, not an assertion that these commands ship today. The studio is a thin workflow client around released Auths derivation, compilation, verification and operator commands. It does not implement its own recipe compiler.

```text
adapter propose --source ./pinned-openapi.yaml --operation getItem \
  --operation updateItem --family https --output ./item-proposal
  -> draft bundle; unsupported or missing bounds are listed, never guessed

adapter check ./item-proposal --offline
  -> canonical source/lock/recipe digests, compiler verdict,
     hostile-corpus results, provider assumptions still unverified

adapter review ./item-proposal --redacted
  -> account and credential requirements, exact outbound requests,
     readable resource/field/release/effect limits, recovery rule,
     changes since the previously installed digest

gateway connection install --proposal ./item-proposal --disabled ...
  -> existing authenticated operator plane; exact reviewed digest only
```

For OpenAPI operations already expressible by AP-SPEC-056, `propose` MUST call that deterministic derivation and preserve its source closure, overrides and rejection codes. Provider prose may suggest assumptions and tests, but cannot silently change a derived request. A database schema can yield a draft SQL proposal, never a managed install before §3.2's gate. The proposal directory contains a bounded manifest, exact source snapshot or digest-pinned reference, generated profile and lock, recipe source and compiler output, review text, test-only oracle, hostile corpus, and an explicit assumption checklist. A reviewer can reproduce the compiler result using the manifest without the studio service or the authoring agent.

The authoring agent's proposal capability is intentionally narrow: read selected source snapshots, edit files in one isolated proposal workspace, and invoke offline released validation tools. It has no operator socket, provider credential, human signing key, release signer, or qualification trust-root key. Fetching documentation is an explicit ingestion step into a size-limited snapshot; the compiler then runs offline. If an agent asks for a provider probe, the studio queues a reviewed test request for the independent test or operator plane, with a disposable connection and finite budget. The agent does not receive a general HTTP client with a production token. Prompt injection, tool descriptions and documentation examples cannot supply command-line flags, install approvals, or provider request parameters without becoming visible proposal data and passing the same review.

The handoff is machine-checkable: the studio submits only the canonical proposal digest and immutable bundle to the operator plane; the operator plane re-derives every digest and displays its own review output. A human approval binds those bytes and the selected connection, not a studio session URL or mutable catalog name. No background job automatically advances `draft` to `installed-disabled`, `enabled`, or `qualified`. If a reviewer changes a bound, field or assumption, the bundle is recompiled and the previous approval is void.

## 3. Closed capability families

### 3.1 HTTPS read, update, and create

The initial managed family is the existing data-only HTTPS gateway. Its compiler and runtime, not generated code, construct requests from verified canonical fields. A candidate MUST pin an HTTPS origin and permitted host/port, method, path template, typed query and headers where admitted, fixed or bounded body, credential injection mode, expected statuses and media types, response limits, and any read projection. Runtime callers cannot provide a URL, arbitrary header, selector, script, or request body outside the compiled grammar.

The gateway MUST enforce TLS verification, the approved origin, resolved-address/egress policy, redirect refusal, response/decompression limits, deadline, and no credential forwarding to another origin. Local, link-local, metadata, private-network and Unix-socket destinations are denied unless a distinct reviewed private-egress class explicitly admits an exact endpoint. The studio's network access to fetch docs is separate from the credential-bearing runtime path. Static provider documentation cannot authorize runtime egress.

Read recipes reuse AP-SPEC-071's release accounting: call allowance before request; approved projection only; durable release charge before first byte to the authenticated agent channel; delivery-unknown if acknowledgement is lost; no automatic redelivery of the same operation. Public evidence uses a keyed content commitment, never a plain digest for small private values. A write recipe fixes the permitted changed fields and resource relationship, pre-entry guards, exact effect plan, and bounded observation. A create additionally fixes the parent/scope, title or key shape, logical operation marker, response locator if available, and a recovery search that can distinguish exactly one owned candidate. Zero, multiple, incomplete, stale, or contradictory matches remain unknown; the gateway MUST NOT retry a possibly entered create merely because no ID was returned.

An adapter candidate may use only already admitted recipe AST capabilities. A new HTTP mechanism or provider interpretation needs the boundary plan's vertical reference, case file, hostile corpus, and ADR before implementation; the authoring agent cannot extend the interpreter by emitting Rust, Python, JavaScript, WASM, or a callback. The existing gateway has no provider-name dispatch.

### 3.2 Separate SQL family

SQL is useful for human-to-agent delegation but is **not** an HTTPS recipe with a different URL. The current generalized gateway does not have a production SQL execution path. A separate ADR, vertical reference and qualification program MUST admit a SQL execution family before the studio can install a managed SQL proposal. Until then, SQL output is `draft-only` or remains application-owned under AP-SPEC-054; no managed production effect or Auths-qualified claim is shown.

The proposed SQL grammar begins with one database/role/schema target pinned by the operator, prepared statements only, typed bound parameters, a closed table/view and column allowlist, required tenant/account predicate, bounded result rows/bytes, and a transaction boundary. Reads cannot invoke write-capable functions, dynamic SQL, extensions or cross-database links. Writes allow only explicitly reviewed `INSERT`, `UPDATE`, or `DELETE` forms with bounded affected-row count, typed predicates, field allowlist, optimistic version or equivalent precondition, and a declared observation. DDL, arbitrary stored procedures, multiple statements, session setting changes, unrestricted joins, and owner/admin roles are out of scope for the first family. Database row-level security and role grants are additional ceilings, not substitutes for the task grant. A timeout or connection loss after commit begins is an unknown effect unless a unique operation marker or trustworthy read-back proves the outcome; no automatic replay is allowed.

The SQL ADR must define credential custody, connection pool isolation, transaction/commit point, cancellation, tenant escape tests, unknown-commit reconciliation, independent live database evidence, and how the family remains separate from HTTPS gateway semantics. A provider-specific SQL dialect or cloud database API does not become a generic capability by sharing the word “SQL.”

## 4. Proposal, installation, and task binding

The proposal bundle MUST have a closed canonical schema, format version, size/depth/count limits, source closure and digest, operation/profile lock, compiled recipe digest, capability family/version, reference-oracle digest, corpus manifest digest, and explicit assumptions. Parsing rejects unknown critical fields, duplicate keys, noncanonical encodings, inconsistent digests, and unresolved remote references. Provider documentation and examples are evidence about a contract, never authority to run an effect.

Installation binds `(recipe digest, profile-lock digest, capability family, connection ID/generation, credential reference/generation, provider account subject commitment, endpoint or database target, operator policy)`. The operator review renders this tuple and the actual request/statement and release/effect limits. Rotation or subject drift fails closed before a new lease; a fresh install or reviewed rotation binds the new generation. A recipe version is immutable. A registry entry may name a version but cannot replace its bytes or cause automatic activation. An installation is disabled on revocation, qualification expiry or drift, and on a stale local trust view where production policy requires qualification.

An AP-SPEC-071 task grant refers to selected installed operation digests and the specific human connection, then narrows resources, fields, recipients, time, counts, released bytes, and write mode. The agent's signed action refers to the task and exact operation. Admission takes the intersection of provider ACL/scope, installed recipe, operator policy, human grant, and agent action. Missing or conflicting limits deny. A bundle across calendar, email, Drive and SQL is a collection of these per-connection child authorities under one human task and activity view; no single “same as me” wildcard bypasses per-provider binding, and revoking the task stops new entry across all children. Already released bytes and entered external effects cannot be recalled.

Approvals are distinct: accepting the adapter's semantics; installing and enabling a recipe with a credential; the human's task grant; and, for exact-confirmation writes, the human's confirmation of the final proposed change. A single UI may guide them, but the stored records, signers, review contents and resulting authority remain separate.

## 5. Qualification, evidence, and lifecycle

The studio emits an independent, test-only oracle and corpus; it MUST NOT derive expected results by asking the candidate gateway. The corpus covers admitted/denied typed actions, request bytes, resource escapes, field substitution, credential/account mismatch, provider-denied reads, release accounting, exact and upfront writes, read-back, replay, races, restart, revocation, response loss, incomplete search, and ambiguous effects. The candidate and oracle must agree on accepted and rejected cases before any protected live run. A protected live run uses a disposable least-privilege account and independently observes effects and cleanup. Every required AP-SPEC-066 evidence member is present or explicitly `not-applicable` for a reason fixed by the family ADR; a failed run issues no attestation.

Qualification is scoped to AP-SPEC-066's exact tuple: recipe family, compiled digest, profile lock, provider contract, gateway semantic closure, target, store and credential-store kinds. It expires, can be revoked, and becomes stale on a tuple or provider-contract change. The registry stores and serves content-addressed proposals, evidence manifests, signed release indexes and revocations; the gateway trusts only its pinned verification root and locally verified current index. A registry outage never upgrades an unqualified proposal. The studio and runtime show `draft`, `locally conformant`, `installed-disabled`, `enabled-unqualified-development`, `qualified`, `stale`, and `revoked` as distinct states and do not collapse them into “connected.” Production with required qualification admits only the exact current qualified tuple.

Receipts distinguish task admission, credential lease, provider entry, response, fresh observation, content release and acknowledgement, unknown outcome, and cleanup. They carry operation/task/recipe/connection commitments, bounded counts, stable codes, and redacted effect links. They do not claim a provider operation succeeded merely because HTTP returned 2xx or a database command returned; the recipe's independent observation rule decides what can be claimed. Logs, traces, registry records, support bundles and public receipts contain no tokens, raw private content, SQL row values, or unkeyed low-entropy content hashes.

Revoking an adapter version prevents new leases for every installation of that digest; revoking one connection or task has narrower scope. Existing unknown attempts remain reserved and available for read-only reconciliation under their original pinned contract; revocation does not grant a retry. New version adoption is an explicit reviewed install and task reauthorization where scope changes. The operator can roll back availability to an earlier **currently qualified, independently installed** immutable version, but cannot reinterpret an attempt made under a newer recipe using old bytes. This lifecycle behavior is recovery and audit, not a legacy schema compatibility path.

## 6. Repository ownership

The [repository contract](../../AGENTS.md) keeps maintained protocol, gateway, SDK and qualification code in the auths-proof monorepo so one change updates contracts, fixtures, implementations and CI atomically. This spec does not split those packages out.

| Auths-proof monorepo | Separate adapter studio/catalog repository, if one is created |
| --- | --- |
| Canonical proposal schemas, bounded deterministic compiler and validator, recipe AST/interpreter, task-grant binding, credential custody, admission, release/effect accounting, stable codes, qualification verifier, signing trust, core fixtures and conformance kit. | UI and workflow for an authoring agent, provider-doc ingestion, human review screens, proposal drafts, catalog search, community examples and publication process. It calls released Auths tools and consumes pinned schemas/fixtures; it is not a second verifier or runtime. |
| Test-only vertical references, independent oracles, hostile/live corpus definitions, family ADRs, protected qualification workflows, release evidence and trusted index generation. | Content-addressed mirror/catalog of reviewed bundles and evidence links. It cannot issue a qualification signature or mutate a trusted release index by itself. |

The studio may run in a separate repository because its presentation and provider-document inventory can change independently. It MUST pin released Auths package versions and artifact digests, never a mutable sibling checkout. If the separate repository would duplicate canonical schemas, signing, qualification, or execution semantics, that functionality belongs back in auths-proof. A public/community catalog is distribution and discovery, not a trust root.

## 7. Acceptance plan

1. **Zero-context authoring.** Give an agent only the released tools, one unfamiliar bounded OpenAPI operation and a provider documentation snapshot. It produces a reviewable proposal with a source closure, profile lock, compiled recipe digest, test-only oracle, corpus and review text. Two independent compiler runs over the same approved normalized proposal produce byte-identical contract outputs; different agents may draft different proposals from the same documentation. Malicious instructions embedded in documentation do not change the compiler result or trigger tool/credential access. Missing bounds and unsupported constructs produce precise rejections.
2. **Two HTTPS domains.** Independently author one read plus exact-confirmed update for a disposable record provider and one read plus create for a distinct document provider. Neither requires a new gateway provider module. Install both disabled; inspect the digest, subject, generation, egress and field bounds; enable explicitly. With a separate registered agent and human account, run a bounded read release and observed write for each. Compare requests and fresh effects against independent references, and prove the agent process cannot retrieve either provider token.
3. **Cross-provider task.** A person signs one 30-minute task with at least two installed provider children, distinct per-account/resource limits and one agent identity. The agent reads from both, proposes one exact write, obtains human confirmation and performs it. A separate bounded-upfront choice is accepted only within its precommitted alternatives. Activity shows each connection and child receipt. Expiry or task revocation stops new reads and writes across both without undoing already observed effects.
4. **Hostile and ambiguous corpus.** Test wrong agent/human/subject/generation, changed recipe or target, unauthorized fields, path/tenant escape, SSRF/redirection, oversized/decompression-bomb responses, projection leakage, lost read acknowledgement, task replay, concurrent final allowance, restart, lost write response, zero/one/multiple/incomplete create recovery matches, stale version, revoked qualification and stale release index. Count provider entries and released bytes. All denied pre-entry cases have zero provider entry; ambiguous entered effects retain a spent claim and never trigger blind replay.
5. **Qualification wall.** A protected release run for a named recipe family passes the full AP-SPEC-066 evidence wall on an exact installed target and produces a signed, expiring attestation. Alter any tuple member or revoke the signer/qualification; production refuses before credential lease. Local conformance alone remains visibly unqualified. A second independently authored provider family exercises the same mechanism without copying the first family's oracle.
6. **SQL gate.** Before an SQL ADR is accepted, a SQL proposal cannot install as managed production. After admission, use a disposable database with two tenants and least-privilege role: bounded prepared read, one version-checked update, exact read-back, and denied cross-tenant/DDL/dynamic-SQL cases. Inject lost commit acknowledgement and show one reserved unknown operation with no second mutation. The SQL test cannot be counted as passed by an HTTPS mock.
7. **Installed consumer.** Package the studio and Auths tools independently. A new operator follows the published flow without repository source imports or preseeded provider secrets; exact artifact digests, account identities, effects, evidence, cleanup and residual assumptions are recorded. CI verifies the proposal corpus and no unauthorized entry; protected provider runs supply the qualified claim. Publish honest setup time and failure diagnostics.

## 8. Non-goals and release gates

- No arbitrary generated code, plugin, shell command, WASM, SQL string, or provider SDK loaded into the credential-owning runtime.
- No automatic provider account connection, OAuth consent, operator install, qualification signature, or human delegation from an agent's proposal.
- No “all my permissions everywhere” wildcard. Broad user intent can be translated into explicit per-provider child grants only after the person reviews their combined ceiling; new adapters do not automatically inherit existing human privileges.
- No assumption that OpenAPI, database introspection, a green simulator, 2xx, or a valid signature proves provider semantics or successful effect.
- No SQL managed production path until its separate ADR, reference and evidence wall exist. No claim that a generic HTTPS recipe safely covers non-HTTP systems.
- No promise of immediate support for every API. Unsupported semantics are an explicit refusal and a candidate for a reviewed new capability.

Implementation order is: freeze proposal schema and review output; reuse AP-SPEC-056 for deterministic HTTPS derivation and AP-SPEC-071 for task binding; ship the studio against disabled development installations; exercise two independent HTTP references and hostile corpus; close protected qualification and installed-consumer gates; only then admit a separately designed SQL family. Each stage publishes its exact claim and unmet gates. A studio demo is not the completion of production qualification.
