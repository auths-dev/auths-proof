# Decouple human-readable review from approval

Status: scratch design note

## Goal

Let canonical actions expose safe, human-readable meaning without forcing every profile to adopt an approval workflow.

Data should be reviewable everywhere. Approval should be one optional consumer of that review data.

## Problem

The generic `ActionProfile` contract requires `approval_display`. That embeds approval vocabulary into every application profile, including profiles used for automatic verification, audit, simulation, policy evaluation, or machine-only enforcement.

Runtime approval remains optional, but profile authors are still forced to understand and implement an approval-shaped concept.

## Target boundary

Rename and generalize the neutral artifact:

```text
canonical action
      |
      v
ReviewDisplay / ReviewModel
   |       |        |       \
   v       v        v        v
approval  audit     CLI      observability
provider  log       output   tooling
```

The neutral review model should communicate exact meaning and remain cryptographically bound to canonical bytes. It should not record whether a human approved, rejected, or even saw the action.

## Design requirements

1. Profiles expose a canonical `review_display` or equivalent neutral method.
2. Review data remains bound to the canonical action digest.
3. Approval providers consume review data through an approval-layer adapter.
4. Automated applications can use profiles without importing approval packages.
5. Review fields remain bounded, ordered, deterministic, and display-safe.
6. The review model cannot authorize or mint an executable command.
7. Existing approval UX preserves exact byte binding through migration.

## Suggested vocabulary

- `ReviewDisplay`: deterministic human-facing representation.
- `ApprovalRequest`: a workflow request containing a `ReviewDisplay` plus approval policy and transaction binding.
- `ApprovalResponse`: provider result bound to the exact request.

This separates “what the action means” from “whether a human permits it.”

## Migration

1. Introduce `ReviewDisplay` with the current bounded fields.
2. Add `ActionProfile::review_display`.
3. Adapt approval workflows to consume it.
4. Remove `approval_display` and its aliases in the same prelaunch cutover.
5. Update profile conformance tests to use neutral terminology.
6. Move approval-specific copy and policy out of profile packages where possible.

## Acceptance criteria

- A profile can be implemented and used without depending on an approval provider.
- The same review model can drive approval, audit, and diagnostic output.
- Approval rejection and absence remain distinct states.
- No code interprets the existence of review data as evidence of approval.
