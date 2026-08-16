# Launch-readiness investigations

Two independent investigation prompts. Run them as **separate agents** — ideally in parallel, and
without letting either read the other's output. They are deliberately scoped to different questions,
and their value comes from being independent.

- **Prompt A — Code readiness.** What must change in the code before v1.0 ships.
- **Prompt B — Adoption readiness.** What must change for anyone to actually use it.

Both are investigations, not implementation tasks. Neither should change shipping code.

---

# Prompt A — Code readiness for v1.0

You have zero prior context. Read this whole brief before running anything.

## What you are looking at

`/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof`

Auths is a proof-carrying authorization system. An actor — a person or an AI agent — receives
precise, portable, cryptographically bounded permission to do **one exact thing**, and the system
leaves verifiable evidence of what happened. Delegation can only narrow, never widen. Everything
fails closed.

Roughly 110 Rust crates, plus TypeScript, Python, and WASM bindings, an independent Go
implementation, Lean 4 proofs under `formal/`, Kani harnesses, and ~50 `cargo xtask` gates.
Rust owns all semantics; every other language projects them.

## Your question

**What must change in this codebase before it can ship a credible 1.0?**

Credible means: a competent external security reviewer reads it and does not find something that
undermines the product's claims. Auths sells verifiable authority. Any gap between what it asserts
and what it actually checks is not an ordinary bug — it contradicts the thing being sold.

## Read these first

1. `AGENTS.md` — the repository contract. Prelaunch, zero external users, direct cutover, no
   compatibility shims. Violent refactors permitted; sloppy ones are not.
2. `docs/target-state/v1-api-contract.md` — the frozen API contract, including ratified decisions
   (§10A) and the empirical-resolution policy (§10Z). Treat ratified decisions as settled.
3. `git log --oneline bbeb654..HEAD` — work already completed. **Do not re-investigate what these
   commits fixed.** Read them to understand what is already addressed.
4. `docs/target-state/v1-api-review-findings.md` and `-bindings.md` — a prior audit produced 139
   findings with file:line citations.

## On the prior audit — read this carefully

The findings in those documents are **already known**, and much of the highest-severity material is
already fixed or in progress. Reading them prevents you from spending your budget rediscovering
known problems.

**A separate launch-readiness assessment also exists. It has been deliberately withheld from you.**

That is on purpose. We want an independent view, and an agent handed someone else's ranked list
tends to produce that list back with more words. Form your own judgment from the code.

Your value is concentrated in two places:

- **What is not in the prior audit at all.** It was scoped to API surface, semantic ownership, and
  the error model. Large areas of this repository were never examined through a launch lens.
- **Where you disagree with the prior audit's severity.** If something it called minor is actually
  launch-blocking, say so and prove it.

If your conclusions substantially overlap the prior work, that is a useful signal too — but only if
you reached them independently.

## Method

**Determine things empirically. Do not reason from names, and do not guess.**

- "Does this code do X?" → write the test, run it, the result is the answer
- "Do two implementations agree?" → differential test on identical inputs
- "Does this gate check what it claims?" → break the thing deliberately, confirm the gate goes red.
  A gate that stays green under a deliberate break is not a gate.
- Bounded exhaustive question → Kani (`cargo kani -p <crate>`)
- Must-hold-for-all-inputs → Lean (`cd formal && lake build`)

Every finding carries `file:line` and, where you ran something, the verbatim output. A finding
without evidence is an opinion.

## Verification surface

`cargo xtask <subcommand>`. Run `cargo xtask help` for the full list. Among them: `arch`,
`compliance`, `conformance`, `cross-language`, `binding-semantics`, `core-boundary`, `public-naming`,
`semantic-freeze`, `sdk-experience`, `sdk-vocabulary`, `product-waist-conformance`,
`mechanism-conformance`, `production-contract`, `evolution-policy`, `error-registry`,
`adversarial-conformance`, `fuzz-smoke`, `release-check`, `formal`.

Capture a baseline before you change anything.

**Two gates are currently red on purpose. Do not try to fix either:**

- `semantic-freeze` — six frozen-meaning identities have drifted deliberately and receive version
  assignments at the end of the current effort.
- `cargo xtask formal` — clearing the translation source closure requires re-running pinned charon
  and aeneas binaries, and neither is installed on this host. Use `lake` directly inside `formal/`.

## Scope

Everything in this repository is in scope. Deliberately including areas the prior audit did not
reach. Consider — and go beyond — operational readiness, failure and recovery behavior under real
conditions, resource exhaustion and denial-of-service surface, dependency and supply-chain posture,
concurrency and data integrity, upgrade and version-skew behavior, observability sufficient to
diagnose a production incident, cryptographic agility, test quality as opposed to test count, build
reproducibility, and anything else you would want answered before putting this on a payment path.

That list is a starting point, not a checklist. **If the most important thing you find is not on
it, that is the best possible outcome.**

## What "launch-blocking" means

Be disciplined about severity. Reserve **blocker** for things that would make launching irresponsible
— a security hole, a correctness bug on a money path, a claim the code does not support, or a defect
that breaks users on day one. Everything else is **major** or **minor**.

An honest short list of real blockers is worth more than a long list padded with preferences.

## Deliverable

Write `docs/target-state/v1-launch-readiness-independent.md`.

### The bar your document must clear

**A different agent, with zero context — no memory of this conversation, no knowledge of this
repository — must be able to open your document and implement any finding in it without asking a
single question.**

That is the acceptance test for your work. Before you submit, reread each finding and ask: *could
someone who has never seen this codebase execute this?* If they would have to go hunting for the
file, guess at the intended end state, or invent a way to check whether they succeeded, the finding
is not done.

This means findings are **work orders**, not observations. "The error model is inconsistent" is an
observation and is worthless. A work order names the file, the line, the current bytes, the required
bytes, and the command that proves it worked.

### Required structure

```markdown
# v1.0 Launch Readiness — Independent Assessment

## Verdict
Can this ship? The single most important thing standing in the way. Ten sentences maximum.

## Summary table
| ID | Title | Severity | Area | Est. effort | Depends on |
|----|-------|----------|------|-------------|------------|
| LR-001 | ... | blocker | ... | 2h / 1d / 3d | — |

## Findings
(every finding in the template below, blockers first, then major, then minor)

## Recommended execution order
A numbered sequence with the reasoning. Which findings unblock others, which can run in
parallel, and which must not be attempted at the same time because they touch the same files.

## Disagreements with the prior audit
Each with evidence.

## Areas examined that the prior audit did not
Named explicitly.

## Unresolved
What you could not determine, and the exact test, harness, or tool access that would settle it.

## Coverage statement
What you read. Honestly, what you did not.
```

### Required per-finding template

Every finding uses exactly this shape. No exceptions, including for minor ones.

```markdown
### LR-001 — <imperative title: "Stop X", "Make Y do Z">

- **Severity:** blocker | major | minor
- **Area:** e.g. rust-core / bindings / packaging / operations / supply-chain
- **Estimated effort:** e.g. 2 hours / 1 day / 3 days
- **Depends on:** LR-00N, or "—"
- **Files:** every path that must change, with line numbers

**What is true today**
Quote the actual code or output. Not a description of it — the bytes.

```rust
// core/crates/example/src/lib.rs:42-45
pub fn thing() -> bool { true }
```

**Why this blocks launch**
The concrete failure. Name the input, the code path, and the wrong result. If it is a security
finding, state the attack: what an adversary supplies and what they gain. If you could not
demonstrate the failure, say PLAUSIBLE rather than asserting it.

**Evidence**
The command you ran and its verbatim output. If you wrote a test to prove it, include the test
source and its failing output.

**Required end state**
What the code must do afterwards, precisely enough to implement. Where a rename or a specific
signature is required, give the exact identifier. Where a design decision remains open, say so
explicitly and give the options with a recommendation — do not leave the implementer guessing.

**How to implement**
Ordered steps. Concrete enough that someone unfamiliar with this repository can follow them.
Name the functions, the call sites, and the tests that will break.

**Blast radius**
What else breaks when this changes. Which crates, bindings, generated artifacts, fixtures, or
gates. If it drifts a frozen-meaning identity, name the identity and its current version.

**How to verify it worked**
The exact commands, and what passing looks like.

```bash
cargo test -p some-crate specific_test_name
cargo xtask cross-language
```

**Rollback**
How to undo it if it turns out to be wrong.
```

### Worked example of the required bar

This is what "implementable by a zero-context agent" looks like. Match this level of specificity.

> **What is true today**
>
> ```rust
> // core/crates/auths-model/src/lib.rs:929-936
> pub fn optional_budget_covers(ceiling: Option<&Budget>, requested: Option<&Budget>) -> bool {
>     match (ceiling, requested) {
>         (_, None) | (None, Some(_)) => true,
>         (Some(ceiling), Some(requested)) => ceiling.covers(requested),
>     }
> }
> ```
>
> **Why this blocks launch**
>
> `(Some(bounded_ceiling), None)` returns `true` — a bounded ceiling is treated as covering an
> action that declares no budget at all. The system denies that case today only because a guard at
> `auths-verifier/src/lib.rs:2543` runs at `:2227`, before `authorizes` at `:2251`. Correct behavior
> depends on statement order, not on the algebra. Reorder those two lines, or reach `authorizes` by
> any other path, and an action with no bound on what it may spend is authorized.
>
> **Evidence**
>
> ```
> $ cargo test -p auths-model --lib optional_budget
> test tests::optional_budget_no_request ... ok
> ```
> The passing test at `core/crates/auths-model/src/lib.rs:4856` asserts the wrong answer:
> `assert!(optional_budget_covers(Some(&zero), None));`
>
> **Required end state**
>
> An absent ceiling covers everything. An absent request under a *present* ceiling does not.
> This matches the three other implementations: `auths-verifier/src/lib.rs:2543`,
> `bindings/independent/go/auths/semantic.go:1341`,
> `bindings/independent/typescript/semantic-verifier.ts:1499`.
>
> **Blast radius**
>
> Inverts the assertion at `auths-model/src/lib.rs:4856` and the mutation-kill oracle at
> `auths-formal-refinement/src/lib.rs:412-416`, which currently requires `canonical == true` for
> this input. Verify the mutation matrix still kills its mutant. Drifts frozen-meaning identity
> `auths.core.protocol` (currently v15).
>
> **How to verify it worked**
>
> ```bash
> cargo test -p auths-model --lib
> cargo test -p auths-formal-refinement
> cargo xtask cross-language     # all four implementations must agree
> ```

### Rules for the document

- Do not modify shipping code. Throwaway tests to answer a question are expected — delete them or
  mark them clearly, and say which you did.
- Every claim carries `file:line`. A finding without evidence is an opinion, and opinions do not
  belong in this document.
- If you could not prove something, label it **PLAUSIBLE** and say what would settle it. Do not
  round uncertainty up to certainty.
- Where a fix requires a judgment call you are not positioned to make, state the options, give a
  recommendation, and mark it as needing a decision. Never leave it silent.

---

# Prompt B — Adoption readiness

You have zero prior context. Read this whole brief before running anything.

## What you are looking at

`/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof` — the product.
`/Users/bordumb/workspace/repositories/auths-proof-base/auths-docs` — its documentation site.

Auths is a proof-carrying authorization system. An actor — a person or an AI agent — receives
precise, portable, cryptographically bounded permission to do **one exact thing**, and the system
leaves verifiable evidence. Delegation can only narrow, never widen. Everything fails closed.

The technical core is strong and getting stronger: Lean-verified attenuation, four independent
implementations held in agreement by a canonical corpus, machine-checked security claims.

## Your question

**Why would anyone adopt this, and what currently stops them?**

You are not evaluating whether the technology is good. Assume it is. You are evaluating whether a
competent engineer who has never heard of Auths can get from "curious" to "this is running in my
service" — and whether they would want to.

The relevant history: Stripe did not win on payments technology, it won on seven lines of code.
Docker did not invent containers. Kubernetes was a worse Borg that anyone could run. Technical
excellence is necessary and never sufficient. The technically superior option loses routinely.

## The method that matters most: actually use it

**Do not theorize about ergonomics. Install the thing and time yourself.**

1. Start from the README as a newcomer would. Follow it literally. **Record every point at which you
   are confused, blocked, or have to read source code to continue.** Those moments are the finding.
2. Time each attempt. How many minutes from clone to a first successful authorization? To a first
   *denial* you triggered on purpose? For an authorization system the denial is the more important
   demo — it is the moment the value becomes visible.
3. Try each language: Rust, TypeScript, Python. Note where they diverge in difficulty. Note where a
   documented step does not work, and record the exact error.
4. Try the quickstarts and examples that are advertised. Verify each one actually runs.
   `bindings/recipes/` and `examples/` are starting points; `demos/` contains roughly 25 more.
5. Try the reference deployment in `demos/open-production-reference/`.

Your transcript of failures is more valuable than any analysis you write on top of it. Include the
verbatim errors.

## Areas to consider

Explore whichever of these prove productive, and add your own:

**First contact.** What does the README promise, and does the product deliver it in the time it
implies? What is the shortest honest path to value? Is it obvious within thirty seconds what problem
this solves and who has that problem?

**Documentation.** `auths-docs` is a Next.js site with content authored as TypeScript and JSON data
structures, not Markdown — read `content/page-builders.ts` first or you will waste an hour looking
for MDX. Assess it as a developer would: can you find what you need, is it accurate, do the examples
run? Note that shipping code was recently renamed in several places, so some documentation may
describe an API that no longer exists — verify rather than assume.

**Packaging and distribution.** What actually ships to npm, PyPI, and crates.io? Install each in a
clean environment and see what you get. Do the type declarations match the runtime surface? Does the
wheel work on the platforms it claims?

**The agent wedge.** The urgent unsolved problem in this space is AI agents acting with authority —
today the state of the art is handing an agent a broad API key and hoping. Auths is aimed directly at
that. Assess how well positioned it is: how hard is it to put Auths in front of an MCP server or an
agent framework? What would an integration look like for someone already using one? Is there a path
where an agent framework adopts this as its default authority mechanism, and what stands in the way?

**Demonstrations.** `demos/` and `docs/prompts/ambitious-demos/` exist. Which demos would actually
convince a skeptic, and do those exist? What is the single most persuasive thing this product could
show someone in two minutes, and can it show that today?

**Positioning.** Auths competes with "just use OAuth scopes" and "just use short-lived tokens."
Being correct does not win that argument; being easier than the wrong thing does. Where is Auths
genuinely easier, where is it genuinely harder, and is the harder part justified by something the
user will care about?

**Integration surface.** `product/integrations/` has real adapters — Stripe, PostgreSQL, Kubernetes,
GitHub, OpenTofu, Radicle, did:web. How discoverable and usable are they? Does adopting Auths require
replacing things people already run, or can it sit alongside them?

**Evidence a buyer needs.** Security reviewers, procurement, and platform teams ask for specific
artifacts. Determine what exists, what is claimed but missing, and what a serious evaluator would ask
for on day one.

Explore what proves interesting. **If the most important thing you find is not on this list, that is
the best possible outcome.**

## Rules

- **Verify, never assume.** If documentation says something works, run it. If an example is
  advertised, execute it. Report the verbatim error when it fails.
- **Do not fabricate.** Do not invent benchmarks, adoption numbers, competitor claims, or user
  research. A gap you name is fine; a gap you make up is not.
- **Separate "hard because the problem is hard" from "hard because we made it hard."** Precise
  authority is intrinsically more work than a bearer token. Say which friction is essential and which
  is self-inflicted — only the second is worth fixing.
- **Be specific about who.** "Developers want X" is not a finding. "An engineer adding Stripe refund
  authorization to an existing Node service hits X at step 3" is.

## Deliverable

Write `docs/target-state/adoption-readiness.md`.

### The bar your document must clear

**A different agent, with zero context — no memory of this conversation, no knowledge of this
repository or its documentation site — must be able to open your document and implement any
recommendation in it without asking a single question.**

That is the acceptance test. Adoption findings fail this more often than code findings do, because
it is easy to write "the quickstart is confusing" and think you have said something. You have not.
The implementable version names the file, quotes the confusing text, supplies the replacement, and
states how to tell whether it worked.

**"Improve the docs" is not a recommendation. "Replace lines 40-58 of `content/get-started-pages.ts`
with this text, because a first-time reader cannot tell what `provider` is, and verify by running
`npm run build` and checking `/get-started/quickstarts/agent-delegation` renders a runnable example"
is a recommendation.**

### Required structure

```markdown
# Adoption Readiness

## First-run report
Lead with this. The raw transcript of trying to use the product, with verbatim errors and
timings. It is the most valuable section and must come first.

## Time to first success
| Language | Clone → first authorization | Clone → first deliberate denial | Blocked at |
|----------|------------------------------|----------------------------------|------------|

## Verdict
Would a competent engineer adopt this today? What single change would most increase the odds?

## Summary table
| ID | Title | Impact | Area | Est. effort | Depends on |
|----|-------|--------|------|-------------|------------|
| AD-001 | ... | critical | onboarding | 1d | — |

## Recommendations
(every one in the template below, ranked by impact on adoption)

## Recommended execution order
Numbered, with reasoning about what unblocks what.

## The agent wedge
Assessment plus the shortest concrete path to an agent-framework integration.

## The two-minute demo
What would most convince a skeptic, whether it exists, and if not, exactly what to build.

## Essential vs self-inflicted friction
The explicit split.

## What a buyer will ask for
Artifact by artifact: exists / claimed but missing / absent.

## Coverage statement
What you ran. Honestly, what you did not.
```

### Required per-recommendation template

```markdown
### AD-001 — <imperative title: "Make the delegation quickstart runnable">

- **Impact:** critical | high | medium | low  — and *on whom*: e.g. "every first-time TypeScript user"
- **Area:** onboarding / docs / packaging / demos / integrations / positioning / evidence
- **Estimated effort:** e.g. 4 hours / 2 days
- **Depends on:** AD-00N, or "—"
- **Files:** every path that must change, with line numbers. Include the repo, since two are in
  play: `auths-proof` and `auths-docs`.

**What a user hits today**
The concrete experience, in the second person, with the verbatim error or the quoted text. Not
"the example is broken" — the actual command, the actual output.

```
$ npx tsx examples/rest-effect/typescript/main.ts
ReferenceError: provider is not defined
```

**Why this costs adoption**
Who abandons, at which step, and why. Be specific about the persona: "an engineer adding refund
authorization to an existing Node service" beats "developers".

**Required end state**
What the user should experience instead, concretely enough to build. If it is text, supply the
replacement text. If it is code, supply the code or state exactly what it must demonstrate.

**How to implement**
Ordered steps a stranger to this repository can follow. Name files, commands, and any generator
that must be re-run — note that the docs site authors content as TypeScript and JSON data
structures, not Markdown, so edits go through `content/` and not through page files.

**How to verify it worked**
The exact commands, and the observable result. Where possible make it a timing or a pass/fail,
not a judgment: "a new user reaches a denial in under 10 minutes" beats "the docs read better".

```bash
npm run build && npm test -- examples
```

**Blast radius**
What else must change to stay consistent. Other languages, the docs site, generated artifacts,
release manifests.
```

### Worked example of the required bar

> **What a user hits today**
>
> The site advertises seven quickstarts. `examples/scenarios.json` declares three, under different
> IDs (`rest-effect` vs `local-rest-effect`). Running the one that exists:
>
> ```
> $ npx tsx examples/rest-effect/typescript/main.ts
> ReferenceError: provider is not defined
> ```
>
> `provider` is referenced at `examples/rest-effect/typescript/main.ts:6` but never imported or
> constructed. The same defect exists in the Python and Rust variants.
>
> **Why this costs adoption**
>
> This is the first code a reader executes. An engineer evaluating Auths for a Stripe refund path
> copies it, gets a `ReferenceError` in under a minute, and concludes the project is unfinished.
> Nothing later in the funnel gets a chance to matter.
>
> **Required end state**
>
> Each example is a complete runnable program: imports, provider construction, error handling, and
> the fail-closed path. A reader can copy the file, run one command, and see both a success and a
> denial. Expected stdout is documented alongside it.
>
> **How to verify it worked**
>
> ```bash
> npx tsx examples/rest-effect/typescript/main.ts   # prints "completed"
> npx tsx examples/rest-effect/typescript/denied.ts # prints "denied: action_mismatch"
> ```
> and a CI job executes every example on every push.

### Rules for the document

- **Verify, never assume.** If the documentation says something works, run it. Report the verbatim
  error when it does not.
- **Do not fabricate.** No invented benchmarks, adoption numbers, competitor claims, or user
  research. A gap you name is fine; a gap you make up is not.
- **Timings are data.** Measure them. "Slow onboarding" is an opinion; "23 minutes and three source
  files read before the first successful call" is a finding.
- Do not modify shipping code. Fixing something trivial to get yourself unblocked is fine — note it
  clearly, and do not commit it.
