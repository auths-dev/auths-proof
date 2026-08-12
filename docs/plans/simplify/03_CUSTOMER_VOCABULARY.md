# 03 — Customer vocabulary

**Status:** implemented; final naming freeze awaits the moderated cohort  
**Milestone:** B — Contract design  
**Evidence inputs:** [01](01_CURRENT_COMPLEXITY_BASELINE.md) and [02](02_SECURITY_AND_PARITY_GUARDRAILS.md)  
**Co-designed with:** executable prototypes from [11](11_OUTCOME_FIRST_RECIPES.md)

## Current issue

The introductory SDK experience exposes several precise but overlapping terms:
grant, proof, trusted context, trusted authority, profile, plan, approval
configuration, verified action, command, lifecycle, reservation, execution
receipt, and more. A user must learn the architecture before understanding the
product promise.

The problem is not that these distinctions are false. It is that they are
presented before the user needs them and sometimes vary between TypeScript,
Python, Rust, and documentation.

## Components of the problem

- protocol terms appear as product-navigation terms;
- internal state-machine objects appear in normal method signatures;
- `authority`, `authorization`, `approval`, and `authentication` are easy to
  conflate;
- `action`, `verified action`, and `command` appear to be interchangeable even
  though only one is effect-capable;
- `result`, `decision`, `outcome`, and `receipt` lack one introductory model;
- module names sometimes describe implementation depth instead of purpose;
- TypeScript and Python choose different names for equivalent customer ideas.

## Product vocabulary decision

Use these five nouns as the core Auths security vocabulary across the beginner
journey:

| Product term | Plain meaning | Important distinction |
| --- | --- | --- |
| Identity | Who or what is presenting a credential | Identity does not grant permission |
| Authority | The bounded things an identity may do | Authority can only narrow when delegated |
| Action | The exact proposed operation | An action is inert data |
| Approval | Optional confirmation of the exact transaction | Approval is not authority |
| Receipt | Signed evidence of the decision or observed effect | A receipt cannot be replayed as permission |

Use `Result` as the language-native container for what a call returned, not as
another security concept.

These five nouns are not the Recipe 3 concept budget, and they do not all need
to appear before the first effect. Progressive disclosure is intentional:

| Journey | New core security vocabulary |
| --- | --- |
| Recipe 1 — Authenticate identity | `Identity` |
| Recipe 2 — Verify authority | `Authority`, `Action` |
| Recipe 3 — Execute one action | `Receipt`; refreshes `Authority` and `Action` |
| Recipe 4 — Delegate to an agent | narrows `Authority`; no mandatory approval |
| Recipe 5 — Cross-organization plan | `Approval` and ordered-plan terminology |

Recipe-specific cognitive load is measured separately in Spec 01. Recipe 3 may
also require the MCP action family, its typed handler/provider, and a
development setup decision. Those are real concepts, but they are not renamed
into security nouns to make a headline count pass.

## Progressive terminology

| Internal/framework term | First introduced when | Product presentation |
| --- | --- | --- |
| Grant/proof | Inspecting or sourcing authority | “Authority proof” in prose; exact type in framework docs |
| Trusted context | Configuring verification | “Trust configuration” until framework detail is needed |
| Profile | Selecting or defining application vocabulary | “Action family” in introductory prose; `profile` in APIs |
| Plan | Executing more than one ordered action | “Ordered plan” |
| Native command | Never in normal product docs | Framework-only “opaque authorized command” |
| Reservation | Explaining replay and provider safety | “Execution reservation” |
| Lifecycle transition | Debugging/reconciliation | “Execution state” |
| Canonical bytes | Verification, adapters, and receipts | Never required in the first-effect tutorial |

## Naming rules

- Name modules and entry points by customer purpose, never by difficulty.
- Do not introduce an `advanced` namespace.
- Use `verify` for inert verification and `execute` for the closed effect path.
- Reserve `authenticate` for proving control of identity material over exact
  bytes; never use it as a synonym for authorization.
- Reserve `approve` for optional transaction-bound confirmation; never use it
  as a synonym for permission.
- Use `authority` for the complete bounded permission object and `delegate` for
  creating narrower authority.
- Use `receipt` only for Rust-owned signed evidence.
- Stable error names describe what happened, not the internal function that
  noticed it.

## Documentation wireframe

```text
+------------------------------------------------------------+
| Auths                                                      |
| Prove exactly what software may do                          |
+------------------------------------------------------------+
| Start with:                                                |
| [Identity]  [Verify]  [Execute an action]                  |
|                                                            |
| Core ideas:                                                |
| Authority -> Action -> optional Approval -> Receipt         |
+------------------------------------------------------------+
| Build integrations:                                        |
| Profiles | Identity methods | Custody | Stores | Providers  |
+------------------------------------------------------------+
```

## Implementation steps

- [x] Build a glossary mapping every exported TypeScript, Python, and Rust term
  to one product concept and owner layer.
- [x] Detect same-name/different-meaning and different-name/same-meaning cases.
- [x] Prototype the first four TypeScript and Python recipes. The moderated
  unfamiliar-developer cohort remains the explicit final-freeze gate in
  `docs/product/vocabulary-review.json`; missing evidence is not reported as a
  pass.
- [x] Record the candidate TypeScript and Python names together in the
  machine-readable glossary. They remain provisional until the cohort gate.
- [x] Rewrite root package descriptions, README introductions, generated API
  navigation, and error headings around the five core security terms and the
  progressive-introduction table.
- [ ] Rename prelaunch APIs in one clean cut; delete replaced names and tests
  in Milestone D after Specs 05, 06, 07, 09, and 11 prove the replacement.
- [x] Add a documentation lint that rejects `advanced`, unexplained internal
  terminology in quickstarts, and authentication/approval/authorization misuse.
- [x] Add glossary links from detailed framework and protocol documentation.
- [ ] Test the vocabulary with developers unfamiliar with Auths before freezing
  the final product surface.

## Delivered evidence

- `docs/product/sdk-glossary.json` is the cross-language term and ownership
  registry.
- `cargo xtask sdk-vocabulary` maps the installed TypeScript and Python API
  snapshots, reports collisions and equivalent operations, and lints every
  maintained beginner document.
- The four pre-cutover recipe prototypes exercise the progressive language
  without claiming that the future facade already exists.
- `docs/product/vocabulary-review.json` makes the external cohort an explicit,
  non-passing evidence state until real participants complete it.

## Acceptance criteria

- Recipe 3 introduces no more than three core security concepts, two
  profile/domain concepts, and one setup-mode decision.
- A security or profile/domain concept is counted when the user must understand
  it to predict behavior. Imports, constructors, required arguments, and setup
  decisions are recorded separately rather than silently excluded.
- `Result`, local variable names, and ordinary language types are not security
  concepts; a typed provider/handler and `development` mode remain counted in
  their actual categories.
- After the five-recipe beginner journey, a reader can explain identity versus
  authority and approval versus authority.
- TypeScript and Python use one term for every equivalent product operation.
- Root API reference groups symbols by customer outcome rather than internal
  subsystem.
- No maintained quickstart uses `native command`, `trusted context`, canonical
  encoding, or lifecycle-transition vocabulary without an immediately relevant
  reason.
- Removed names have no alias, deprecation export, or compatibility test.

## Non-goals

- Renaming established protocol identifiers or wire fields for aesthetics.
- Hiding precise terminology from framework authors, auditors, or diagnostics.
- Describing approval as mandatory.
