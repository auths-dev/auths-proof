# AP-SPEC-074 implementation handoff

This prompt is for a new agent working in the already-created worktree. It is not
an instruction to resume the paused AP073 implementation. The specification is
complete as a handoff document; the implementation described by it has not begun.

## Copy/paste prompt

```text
Make it your goal to implement AP-SPEC-074 completely:

/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof-effect-recovery/docs/specs/0074-bound-effects-and-recovery-state-machine.md

Work only in:
/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof-effect-recovery

Branch: codex/effect-recovery-foundation
Baseline: origin/main at e2d10a74fa0be5e6bfe2b9f698632c835cd7b11b

Start by reading AGENTS.md, the required profile/domain abstraction boundary plan,
and the full AP-SPEC-074. Inspect the worktree and preserve any existing changes.
Write your own durable goal prompt covering the complete specification, then
implement it. Keep progress and the acceptance/evidence ledger in
docs/plans/0074-implementation-status.md.

The goal has exactly two architectural pillars:
1. One immutable bound effect model shared by native authorization, deterministic
   request compilation, human approval, admission, execution and reporting.
2. One authoritative recovery transition model and transaction contract for
   reservation, provider entry, disclosure, acknowledgement and unknown outcomes.

Finish this foundation before expanding multi-agent delegation. Do not implement
participant trees, federation, broad identity lifecycle redesign or a new token
system. Do not merge/cherry-pick the AP073 branch wholesale. The separate
codex/identity-authority-foundation worktree is paused and contains uncommitted
work; do not modify, reset, clean or commit anything there. AP073 is not a
prerequisite or part of this goal.

Main already has the gateway's native verifier integration, closed recipe
compiler, submission step machine, attempt transitions, durable stores, lifecycle
reference contracts and deployment clock. Read these first and preserve sound
mechanisms. Do not create a third lifecycle framework. Complete P0's owner mapping,
ADR and abstraction case, then perform bounded direct cutovers through P1–P4.
Centralize shared semantic decisions; do not scatter independent clock, hash,
approval, retry or accounting fixes through routes, demos and bindings.

The shared model must retain typed differences between acquisition, disclosure
and mutation. A provider response, receipt signature, state match and recipient
ACK establish different facts. An unknown outcome must never authorize a blind
retry, redelivery or refund. Entry permits are issued once, only after the required
durable acknowledgement; persisted facts cannot recreate lost permits. Fresh
native authority, approval, configuration and revocation checks must be ordered
with the final entry decision. Bindings expose Rust semantics rather than
reimplementing them.

Produce actual behavior, fault-injection, concurrency, differential, installed
binding and formal/refinement evidence for the specification's invariants and
A01–A22. The first complete journey is one human and one agent: bounded acquisition,
controlled disclosure, exact approved write, independent observation and truthful
recovery. Use real local transport/process boundaries and maintained durable
adapters. Do not claim live-provider or isolation guarantees from a unit test.
Record external assumptions and unsupported rollback guarantees precisely.

Commit coherent implementation changes along the way using Conventional Commits.
Follow the repository's GitHub-first verification policy. Generate required
artifacts locally as needed to construct the change; do not duplicate broad local
build/test/lint/formal suites without the policy's justification. Observe CI only
after the spec implementation, fixtures and documentation are complete. Then push
explicitly to origin codex/effect-recovery-foundation (never to main), open/update
a draft PR against main, observe all required hosted workflows on the exact head,
repair failures and repeat. Do not merge or deploy.

Do not mark the goal complete for a spec, scaffold, wrapper, happy path, passing
compilation or isolated test. Finish the source cutover and required evidence.
If genuinely blocked by an external dependency, preserve the work and report the
specific incomplete criterion, evidence and smallest required intervention.
Do not weaken checks or silently narrow the scope to manufacture completion.

At completion, report the PR, exact revision, tests/CI results, central owners,
removed duplicate paths, and remaining deployment assumptions. Do not resume
multi-agent delegation as an automatic follow-on.
```

## Current handoff facts

- This worktree was created from freshly fetched `origin/main`, independently of
  draft PR #212 and its uncommitted changes.
- Only AP074 specification and handoff documentation are authored here.
- No implementation, test execution, push, CI observation, PR creation or agent
  dispatch is part of this documentation handoff.
- The existing AP073 goal was explicitly marked **paused** at the user's request.
- The specification distinguishes required future evidence from existing code.
