# 11 — Outcome-first recipes

**Status:** implemented; independent Recipe 3 cohort pending
**Milestones:** B — executable prototypes; D — recipes 1–4; E — recipe 5
**Design dependencies:** [01](01_CURRENT_COMPLEXITY_BASELINE.md) and [02](02_SECURITY_AND_PARITY_GUARDRAILS.md); prototypes inform [03](03_CUSTOMER_VOCABULARY.md) and [05](05_PRIMARY_PRODUCT_WAIST.md)

## Current issue

Auths documentation explains its architecture and guarantees well, but a new
user needs an outcome before they need the complete model. When examples begin
at different layers or manually expose workflow machinery, they teach multiple
ways to use the SDK and make the platform appear larger than necessary.

## Components of the problem

- architecture-first navigation;
- examples that use internal or framework concepts in normal application code;
- language examples that prove different subsets of the product;
- happy paths without nearby denied, replay, or unknown-outcome behavior;
- snippets that compile in the repository but not against packed artifacts;
- no uniform time-to-value or decision-count budget;
- demos that are comprehensive but too large to serve as first contact.

## Product decision

Maintain five primary recipes in TypeScript and Python. Each pair uses
the same domain, fixtures, product vocabulary, semantic operations, terminal
outcomes, and receipt evidence.

## Recipe set

### 1. Authenticate an identity

Outcome: decode a method-labelled identity, validate/resolve its current state,
and authenticate exact application bytes.

Proves:

- no authority or approval setup;
- replaceable identity method and signature suite;
- changed message bytes fail authentication;
- transport success is irrelevant.

Time budget: five minutes.

### 2. Verify existing authority

Outcome: verify proof, action, and trust bytes and inspect an authorized,
denied, or indeterminate decision without acquiring execution capability.

Proves:

- verification-only adoption;
- inert authorized evidence;
- exact canonical mutation failure;
- offline and packed-artifact operation.

Time budget: five minutes.

### 3. Execute one exact action

Outcome: run one development-mode protected effect and verify its signed
receipt.

Proves:

- short product facade;
- a visible bounded authority that permits only `publish_report`;
- reservation before credentials;
- typed profile-owned handler/provider execution;
- replay rejection;
- result and receipt.

Break-it requirement: attempt an undeclared tool or a resource outside the
authority. The result is denied, the handler call count remains zero, and no
execution receipt claims an effect.

Time budget: fifteen minutes including install.

### 4. Delegate to an agent

Outcome: create narrower, expiring, single-use authority for an agent and
execute one permitted action.

Proves:

- visible attenuation review;
- widening rejection before signing;
- child lifetime and custody;
- denial of a second or broader action.

Time budget: twenty minutes.

### 5. Run a cross-organization ordered plan

Outcome: obtain two authenticated approvals for identical plan bytes, execute
two actions in order, stop the process after a deliberately ambiguous provider
effect, restart, and reconcile it from the explicit file-backed development
store.

Proves:

- approval is exact and distinct from authority;
- multi-party/cross-company operation without shared identity infrastructure;
- ordered plan and partial completion evidence;
- outcome-unknown and explicit reconciliation;
- recovery across process restart with zero duplicate provider entry;
- portable receipt verification in the other language.

Time budget: thirty minutes locally.

## Recipe page template

Every recipe follows this structure:

```text
+------------------------------------------------------------+
| Outcome                                                    |
| What you will make happen                                  |
+------------------------------------------------------------+
| Before you start                                           |
| Runtime + one install command + expected duration          |
+------------------------------------------------------------+
| Run it                                                     |
| Copyable complete code, not disconnected snippets          |
+------------------------------------------------------------+
| What Auths protected                                       |
| Authority | exact action | effect boundary | receipt       |
+------------------------------------------------------------+
| Break it safely                                            |
| One mutation/replay/denial/ambiguity exercise              |
+------------------------------------------------------------+
| Take it to production                                      |
| Explicit mechanisms to replace; link to profile/framework  |
| contract only when that public contract is evidence-gated  |
+------------------------------------------------------------+
```

## Documentation information architecture

Top-level navigation:

1. Start: choose Identity, Verify, or Execute;
2. Recipes: the five outcomes;
3. Concepts: the five-word vocabulary and trust boundaries;
4. Integrations: maintained adapters and replacement guidance;
5. Framework: profiles, ports, conformance, and native ownership;
6. Operations: errors, receipts, reconciliation, diagnostics;
7. Protocol and assurance evidence.

## Executable recipe contract

Each recipe must:

- live in a standalone external-consumer fixture;
- install only the packed npm package or Python wheel;
- include complete imports and setup;
- pin or validate every non-Auths dependency;
- assert the intended success and at least one adversarial result;
- produce bounded deterministic output suitable for documentation snapshots;
- link every API to the current generated reference;
- include a TypeScript/Python parity metadata file;
- fail CI if documentation code and executable code differ.

## Milestone D unfamiliar-developer gate

Recipe 3 is not complete merely because its author can run it. Before the
Milestone D cutover is accepted:

- recruit at least five developers who have never used Auths and did not work
  on the implementation;
- give each a clean supported machine/VM with only the declared language
  runtime and ordinary package manager preinstalled, no Auths source checkout,
  package cache, prepared credentials, or hidden setup;
- provide only the published Recipe 3 page and links it contains;
- start the timer at the first install command;
- require installation, one successful bounded effect, receipt verification,
  and the undeclared-action break-it exercise;
- permit no live coaching, command correction, or undocumented workaround;
- require at least four of five participants to finish correctly within fifteen
  minutes; and
- record anonymized platform, completion, elapsed time, wrong turns, blockers,
  documentation lookups, and any intervention in the Spec 01 experience
  summary.

A participant who succeeds only after intervention is recorded as incomplete.
If the gate fails, Milestone B reopens the vocabulary/facade/recipe design and
Milestone D does not ship. Later cohorts may supersede earlier evidence but may
not delete it.

## Staged implementation

Recipe code begins as an executable prototype before public vocabulary and API
names are frozen. Recipes 1–4 become installed-artifact documentation in the
Milestone D cutover. Recipe 5 lands after the ordered-plan and recovery work in
Milestone E. The cross-company incident demo remains a later showcase and does
not define the cutover API by itself.

## Implementation steps

- [x] Delete or demote examples that teach superseded normal paths.
- [x] Build the five canonical fixture scenarios in Rust-owned test data.
- [x] Write complete TypeScript and Python external-consumer implementations.
- [x] Generate displayed snippets from those executable files.
- [x] Add safe break-it exercises and expected recovery output.
- [x] Add production replacement sections only when the corresponding Phase B
  reference from Spec 09 exists; otherwise state the exact contract to replace
  without pretending an integration is maintained.
- [x] Restructure package READMEs and documentation navigation around the
  recipe set.
- [x] Add timing instrumentation for clean-machine completion and report it in
  the SDK experience contract.
- [ ] Run moderated tests with developers who have not seen Auths; record terms,
  decisions, and steps that require explanation.
- [ ] Run the exact Milestone D unfamiliar-developer protocol and attach its
  evidence to the experience summary.

## Acceptance criteria

- All ten language recipes run against installed artifacts in CI.
- TypeScript and Python produce the same semantic results and receipt fixtures.
- No recipe imports internal modules or framework ports unless its outcome is
  explicitly framework authoring.
- The first three recipes require no knowledge of native handles, canonical
  encoding, lifecycle transitions, or Rust.
- Every recipe includes one fail-closed behavior and explains effect/retry state.
- Measured completion and concept counts meet Spec 01 budgets.
- At least four of five Auths-new developers complete Recipe 3 unaided within
  fifteen minutes on the declared clean-machine protocol.
- The cross-company recipe verifies a receipt produced by the other language.

## Non-goals

- Replacing comprehensive demos with tiny recipes.
- Teaching every adapter or authority dimension in introductory material.
- Maintaining examples for deleted prelaunch APIs.
