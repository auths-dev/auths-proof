# AP-SPEC-052: Self-hosted profile launch hardening

- **Status:** Epics 1–4 engineering evidence merged; independent owner review
  and AP-SPEC-057's separate historical hosted field-lab gate remain unclaimed
- **Depends on:** [AP-SPEC-051](0051-self-hosted-developer-profiles.md)
- **Scope:** make the exact, application-owned MCP path repeatable from packaged
  Python and TypeScript SDKs, usable with independently provisioned authority,
  conservative at the provider boundary, and demonstrable by an outsider.

## 1. Decision and claim

The Airtable and Todoist field-lab runs show that a developer-owned adapter can
make a real provider change after Auths authorizes an exact command. They do
not qualify those adapters, establish production trust, isolate credentials
from the application, or prove exactly-once provider effects. This spec closes
four launch-readiness epics without changing that claim boundary.

An Auths self-hosted decision means: the supplied proof authorizes the exact
canonical action under the supplied trusted context, and the projected command
comes from those verified bytes. A local attempt record means only that the
configured store claimed that action in its documented deployment scope.
Provider acceptance and observation are assertions of the application adapter.

The self-hosted SDK does not accept a runtime-supplied URL, method, header
set, body, or executable callback, and it never holds the provider credential.
The application retains its own credential and provider-specific request,
result, and observation semantics, so code that holds the credential can
bypass the local gate. Stronger enforcement is not obtained by widening this
SDK into a generic HTTP executor. It is obtained by moving the credential into
a separately deployed process that interprets only a declared,
operator-approved, digest-bound request recipe compiled from the same exact
contract, or by a reviewed qualified vertical. The declared-recipe path is
specified in [AP-SPEC-053](0053-declarative-credential-isolated-gateway.md);
neither path is a launch gate for this spec.

## 2. UX

A new developer starts in an empty application repository with an installed
`auths` Python wheel or `@auths-dev/sdk` npm package. Neither repository is
required as a sibling checkout.

```text
auths-profile init --language python|typescript --name create-task
  -> versioned exact-tool contract and generated command type
  -> provider adapter skeleton with no credentials or trust material
  -> denial/replay/unknown tests and canonical vectors

auths-profile check <profile.toml>
  -> schema, size, identity, generated-file and vector verdicts
  -> explicit "self-hosted, provider behavior unqualified" claim

auths-profile doctor <profile.toml> [--production]
  -> production: signer, grant and independent trust sources required
  -> local: testkit artifacts allowed only with an explicit development mode
  -> missing input and next action stated without revealing a secret
```

The prepared command preview displays service, tool, contract version,
canonical action commitment, and bounded argument summary before custody is
asked to sign. The user must never infer authorization from the presence of a
provider token or from an SDK-created development key.

Errors name the failed stage: contract, trust, verifier, claim, provider,
observation, or recovery. `denied`, `indeterminate`, `attempting`, `unknown`,
`confirmed`, and `rejected` remain distinct. `not_observed` is not interpreted
as proof that no provider write occurred.

## 3. Architecture

```text
versioned application contract -> generated bounded command + exact tool
                       |                         |
operator signer + grant|                         |independent trust context
                       v                         v
                 native authoring -> native verification
                                        |
                             typed command from verified bytes
                                        |
                          atomic application attempt store
                                        |
                           credential-owning app adapter
                                        |
                           provider call -> app observation
```

The SDK owns canonical encoding/verification, exact projection, schema
validation, one-use store interfaces, and reference runner ordering. It does
not own the provider credential, endpoint, request body, reconciliation
meaning, or qualified receipt. The generator is packaging/tooling, not a new
runtime profile registry. Generated code is source in the consumer's repo;
the package must not dynamically execute a contract file as privileged code.

### Epic 1 — Repeatable developer creation

1. Finish the existing self-hosted SDK PRs under hosted CI before treating the
   interface as a baseline. Do not merge either PR while required gates fail.
2. Ship a restricted, versioned `profile.toml` contract and deterministic
   `init`, `check`, and `doctor` commands in the Python and TypeScript packages.
   The first generated operation is one fixed `auths.mcp/v2` service/tool; no
   arbitrary URL, method, headers, or callback registry. Reject unsupported
   schema constructs rather than widening them into `Any`/JSON.
3. Generate immutable typed command declarations, exact-tool construction,
   contract identity, and language-neutral canonical argument vectors. Bind
   the contract version in the action itself; changing the version must make
   an old action fail projection under the new contract.
4. Generated files are reproducible byte-for-byte. `check` detects drift,
   bounds violations, duplicate/unknown fields, changed identities, and
   unsupported constructs. Neither package may depend on the other language
   being installed to generate its own consumer.

**Acceptance:** a clean Python and a clean TypeScript consumer each define a
new exact operation using only a packed/published SDK; hostile and canonical
vectors agree across languages and native Rust. AP-SPEC-051's broader schema
vocabulary remains required for its own completion; this epic must not mark
051 complete while constructs or vectors are missing.

### Epic 2 — Real authority and trust setup

1. Provide a typed production-input bundle: existing signed grant chain,
   custody signer, independently provisioned trusted-context template,
   explicit challenge, and evaluation time. Reuse native proof semantics;
   do not mint or infer grants from a provider token.
2. Add preflight/doctor diagnostics that inspect presence, bounds, and
   compatibility without logging key material. They must distinguish signer
   identity, grant authority, trust anchor, request binding, and provider
   credential ownership. Missing production inputs fail closed.
3. Keep ephemeral self-trusting fixtures under `auths.testkit` only. Document
   an operator flow for signer/grant creation, trust distribution, expiry, and
   rotation. Do not pretend rotation or revocation happens automatically.

**Acceptance:** one packaged consumer signs and verifies with separately
supplied custody and trusted context. The production path has no fallback to
testkit authority and does not read the provider token during verification.

### Epic 3 — Conservative execution and recovery

1. Expose a narrow reference runner around `verify_command`, `AttemptStore`,
   and a typed application adapter. The order is strictly verify/project,
   atomic claim, credential access, exact request, durable outcome, optional
   observation. A denied, indeterminate, mismatched, or replayed command must
   not obtain a credential or enter the provider.
2. Distinguish a proved pre-entry rejection from an ambiguous post-entry
   failure. Any crash or transport uncertainty after claim is `unknown` until
   provider-specific read-only reconciliation. Never automatically repeat a
   possibly applied write.
3. Document the file store as single-host/POSIX only. A multi-host production
   deployment supplies an application-owned atomic durable store. The runner
   returns stage-specific local evidence, not a qualified Auths receipt.

**Acceptance:** competing claims, restart, failure at each checkpoint,
denial-before-credential, and unknown/reconcile behavior are exercised by
CI tests and by both demos. The application can still bypass the runner if it
retains the token; documentation states this limitation near the API.

### Epic 4 — Independent adoption evidence

1. Refactor Airtable and Todoist field-lab demos to consume the generated
   contracts and shared runner while retaining their distinct HTTP adapters,
   token custody, preflight/read-back, and provider-specific reconciliation.
   Remove superseded hand-written SDK-boundary glue in the same source cutover.
2. Add packed-wheel and npm-tarball clean-consumer exercises in hosted CI,
   including generated typing, canonical/hostile vectors, a denied command,
   replay, and ambiguous provider result. No live secret or live provider call
   runs in CI.
3. Give one developer unfamiliar with Auths a fresh-provider task and record
   whether they can complete it from published artifacts and docs without
   team help or editing Auths. Fix observed friction before claiming this epic
   complete; internal Airtable/Todoist authors are not substitutes.
4. Publish a short claim ledger: what native Auths verified, what the attempt
   store established, what each adapter observed, and what remains unqualified.

**Acceptance:** an external clean-room consumer succeeds, the packaged
cross-language matrix is green on the exact release candidate, and the two
field-lab demos retain their signed-proof and live-read-back paths. If no
independent participant is available, the epic stays open; a simulated
clean-room test is useful evidence but not a replacement.

The independent zero-context engineering participant built and reran a third
adapter from the packaged Python wheel; the [redacted report](../product/SELF_HOSTED_THIRD_ADAPTER_TRIAL.md)
records the distinction from human market adoption. SDK revision `0266fdc`
passed the [Python package](https://github.com/auths-dev/auths-proof/actions/runs/35663793077),
[TypeScript package](https://github.com/auths-dev/auths-proof/actions/runs/35663793306),
[installed-artifact recipes](https://github.com/auths-dev/auths-proof/actions/runs/35663793107),
and [authoritative CI](https://github.com/auths-dev/auths-proof/actions/runs/35663793124).
The exact-pinned field-lab demos passed local packaged-wheel tests and earlier
live write/read-back. Their hosted jobs did not start because of a billing
annotation in that repository. At the owner's direction, field-lab CI is not
being pursued for PR #123's engineering handoff; this does not count as a green
hosted-demo run under AP-SPEC-057 Epic 1.

## 4. APIs

The stable concepts remain those in AP-SPEC-051. Representative Python shape:

```python
contract = generated.CONTRACT
preflight = inspect_production_inputs(
    contract=contract,
    grants=operator_grants,
    signer=operator_signer,
    trusted_context_template=operator_trust,
)
prepared = contract.prepare(command, actor=preflight.actor, ...)
# Show prepared.review_fields and prepared.action_commitment to the approver.
authored = await author_mcp_proof(contract=contract, command=command, ...)
result = await run_once(
    contract=contract, proof=authored.proof, action=authored.action,
    trusted_context=operator_trust, attempts=application_store,
    operation_key=operation_key, adapter=application_adapter,
)
```

TypeScript provides the same separated preflight, author, verify, and run
concepts with a typed `AttemptStore`. A runner callback receives only an
`AuthorizedCommand` or its typed command after an atomic claim, never raw
unverified arguments. The adapter itself remains developer-owned and its
outcomes are explicitly attributed to it.

## 5. Verification and release discipline

Use one unsigned commit per epic on the current Auths branch; keep the field-
lab migration in its current branch with the corresponding epic-4 commit.
Do not run local build, test, format, lint, formal, package, or other checks
for this implementation. Push the bounded commits to the existing draft PRs
and let hosted CI provide verification. A failed hosted check is fixed from
its specific evidence, not treated as a reason to claim completion early.

Do not merge while either PR is red or while the two repositories disagree on
the SDK revision. Do not label the product production-qualified, provider-
qualified, or non-bypassable on the strength of these self-hosted examples.
