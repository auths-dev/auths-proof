# AP-SPEC-037: TypeScript SDK ergonomics closure, public-surface discipline, and exact plan approval

**Status:** Specified — implementation is not yet authorized; AP-SPEC-036's
remaining external-consumer and Python gates are not waived by this follow-up

**Governs:** The second TypeScript SDK ergonomics pass: closing accidental
public runtime hooks, making approval execution refine its committed policy,
binding plan approval to exact ordered members, completing the workflow module
cut, proving packed-package behavior, and replacing reference-shaped examples
with a compelling supported workflow

**Source evidence:** The repository-local AP-SPEC-036 implementation, its
`auths-agent-demo` consumer rewrite, and the contributor/API audit performed
on 2026-08-05

**Depends on:** AP-SPEC-027, AP-SPEC-036, AP-SPEC-035 where cross-language
claims are affected, the profile and domain abstraction boundary plan, issue
76's command-minting boundary, issue 85's application-profile boundary, and
the applicable release and independent-review gates

**Scope:** TypeScript API and package ergonomics that can be improved without
moving profile semantics into the shared kernel or changing the portable
authorization meaning

**Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are
requirements on conforming implementations.

## 0. Work order

Implementation MUST proceed in this order:

1. close the published API over package-private workflow capabilities;
2. unify committed approval policy and executed approval bounds;
3. bind one plan approval to its exact ordered transaction membership;
4. split the workflow implementation into real ownership modules;
5. install and execute the packed package in clean Node and browser fixtures;
6. add maintained macOS, Linux, and Windows package evidence;
7. replace skeletal examples with one complete copyable workflow; and
8. freeze the intended public declaration surface in CI.

The first three items are security and semantic-claim corrections. They MUST
land before documentation presents plan approval as exact or reusable.

## 1. Decision

AP-SPEC-036 established a credible TypeScript reference SDK. It removed
application-owned protocol encoding, raw-key constants, capability branding,
magic policy digests, manual plan aggregation, and manual receipt hashing from
the external demonstration. It also established profile-owned sealed commands,
closed gateways, three-valued decisions, development-only custody, immutable
inspection, and semantic mutation testing.

This follow-up does not add another generic workflow abstraction. It makes the
existing supported path smaller, more truthful, and easier to consume.

The public SDK MUST expose the minimum surface required to:

```text
define or select one profile
        |
        v
load Auths -> attach -> delegate -> authorize exact action or plan
        |
        v
authorized sealed command -> matching closed gateway
```

Package coordination hooks, internal resource registries, caller-selected
runtime registration, raw attached-agent resources, and command-minting
helpers MUST remain unreachable through published exports.

## 2. Findings that govern this work

| Finding | Current consequence | Required correction |
| --- | --- | --- |
| Root export breadth | `workflow/runtime.ts` exports package coordination alongside consumer workflow types | explicit public allowlist and package-private internal modules |
| Runtime registration | `registerProfileRuntime` is reachable through the root export graph | closure-owned or internal registration unreachable from package exports |
| Resource accessors | signer, engine, trusted context, and attached-agent resource helpers appear public | move behind package-private modules with no published subpath |
| Approval commitment split | `maxUses` and expiry are committed, then separately supplied to the session | one immutable typed policy instance drives commitment and execution |
| Plan commitment is display-only | the session shows a plan digest but does not independently prove transaction membership | ordered member commitments and exact membership validation |
| Workflow module cut is shallow | contributor modules mostly re-export a large `runtime.ts` | move implementation into bounded ownership modules |
| Package test is manifest-only | the package suite reads source and `package.json` without installing the tarball | clean `npm pack` installation and runtime import tests |
| Browser claim lacks current closure | refreshed packed-package browser behavior is not authoritative | maintained real-browser test against the tarball |
| Examples are skeletal | examples wrap `loadAuths` or `authorize` without teaching the workflow | one complete provider-neutral quickstart plus focused recipes |
| Capability metadata reference drifts | README names `sdk-capability.json` without a shipped or linked artifact | ship, link, or remove the reference according to release ownership |
| Public declarations can drift | no exact allowlist rejects a newly exported internal symbol | checked declaration/API snapshot |

## 3. Public API closure

### 3.1 Explicit root exports

`src/index.ts` MUST use an explicit allowlist. It MUST NOT use `export *` from
an implementation module whose export set contains package coordination.

The default root SHOULD contain only the supported normal workflow:

- workflow loading and deterministic disposal;
- attach, delegate, authorize, and authorize-plan objects and result types;
- typed provider ports;
- typed approval-policy construction;
- plan and safe inspection projections;
- portable three-valued result types needed by the normal workflow; and
- package-owned raw-key authority preparation where its development and
  production boundary is accurately documented.

Raw verifier operations MAY remain in `@auths-dev/sdk/advanced`. Profile
vocabularies remain in closed profile subpaths such as `./mcp` and
`./profile-kit`. Development custody and mutation helpers remain in
`./testkit`.

### 3.2 Package-private coordination

The following capability families MUST NOT be reachable from the root or any
documented published subpath:

- profile runtime registration;
- attached-agent resource extraction;
- client engine or signer extraction;
- trusted-context backing-byte extraction;
- delegated attached-agent construction;
- command or plan-command minting;
- internal WASM engine selection; and
- mutable resource registries.

Internal TypeScript imports MAY use these mechanisms. Their location and names
MUST make the boundary obvious, and package tests MUST prove that consumers
cannot import them through the package `exports` map.

This is public-surface discipline, not a claim that JavaScript can prevent a
host application from bypassing its own gateway. Auths protects effects only
when the application actually uses the closed gateway and verifier-minted
command path.

### 3.3 Prelaunch source cutover

Auths is prelaunch. This work MUST make one direct cutover to the intended
surface. It MUST NOT add deprecated aliases, compatibility barrels for
accidental exports, dual runtime registration, or legacy command paths.

## 4. One committed and executed approval policy

### 4.1 Problem

The current policy builder commits fields such as mode, maximum uses, expiry,
and requirements, but exposes a reference that retains only identifiers and
the digest. The approval session then accepts independently supplied execution
bounds. These two representations can disagree.

### 4.2 Required model

The builder MUST return one immutable typed policy value whose canonical
configuration and executable bounds are inseparable:

```ts
const policy = await approvalPolicy.planOnce({
  expiresInSeconds: 300,
  maxUses: plan.length,
  requirements: ["human-click"],
});

policy.reference;     // exact configuration commitment
policy.mode;          // "plan-once"
policy.maxUses;       // committed and executed bound
policy.expiresInSeconds;
```

The session MUST derive its maximum uses, relative expiry, mode, and
requirements from that value. A caller MUST NOT provide a second conflicting
copy.

The commitment MUST cover every field that changes approval execution. Fields
that do not affect execution MUST be classified explicitly as display or
application metadata and MUST NOT silently influence the authorization claim.

### 4.3 Required/executed evidence

Inspection MUST distinguish:

- required approval-policy commitment;
- executed approval-policy commitment;
- required plan commitment;
- approved plan commitment;
- committed maximum uses and expiry;
- observed use count and terminal state; and
- rejection reason when equality or bounds fail.

Required and executed policy mismatch MUST fail before a signer call, proof
construction, credential acquisition, or provider effect.

## 5. Exact ordered plan membership

### 5.1 Plan approval meaning

One human approval may authorize multiple later signing transactions only when
the approved object commits to their exact ordered membership.

For plan `P` with ordered member transactions `T_1 ... T_n`, the approved
commitment MUST bind at least:

```text
profile identity and version
ordered canonical action commitments
ordered signing transaction identities or a native derivation rule
authority summary
aggregate budget
member count
policy commitment
expiry
```

A valid reuse step MUST establish membership in `P`, the correct position,
the expected transaction identity, the unchanged policy commitment, remaining
use capacity, and unexpired state.

### 5.2 No display-only security field

Displaying a plan digest is useful UX but is not enforcement. The session MUST
reject a request when it cannot prove that request is the expected member of
the approved plan.

The implementation MAY use:

- an ordered list of exact transaction commitments;
- a bounded Merkle commitment with position proofs; or
- a native deterministic derivation that binds each transaction to the plan.

The implementation MUST NOT accept an arbitrary request merely because it has
the same policy and the session has remaining uses.

### 5.3 Failure behavior

The implementation MUST prove:

- reordered members fail;
- duplicated members fail;
- omitted members do not release a complete plan command;
- appended members fail;
- action or approval-display mutation fails;
- expiry and overuse fail;
- a failed member exposes no earlier command capability;
- session reuse by another plan fails; and
- retries with unchanged denied inputs remain terminal and effect-free.

## 6. Real workflow implementation modules

The contributor filesystem introduced by AP-SPEC-036 MUST become an ownership
boundary rather than a facade over one monolith.

The target implementation structure is:

```text
src/workflow/
├── client.ts                 # loading, client lifetime, public client API
├── attached-agent.ts         # attached-agent lifecycle and public methods
├── authorize.ts              # single-action orchestration
├── authorize-plan.ts         # exact plan session and result assembly
├── delegation.ts             # child creation coordination
├── authority-source.ts       # signed authority source and validation
├── trusted-context.ts        # trusted-context source and snapshots
├── approvals.ts              # public approval contracts
├── custody.ts                # public signer contracts
├── errors.ts                 # stable workflow/provider error families
├── types.ts                  # shared public value types
└── internal/
    ├── client-resources.ts
    ├── agent-resources.ts
    ├── profile-runtime.ts
    ├── copying.ts
    └── validation.ts
```

Names MAY change when a smaller cut is clearer, but ownership MUST be real:
normal changes to approval, attachment, sources, or plan authorization SHOULD
not require understanding an unrelated 1,800-line runtime.

The refactor MUST preserve native Rust/WASM semantics and canonical fixtures.
It MUST be a direct source cutover with no second workflow runtime.

## 7. Packed-package and platform evidence

### 7.1 Clean package fixture

`test:package` MUST build and pack the SDK, install the tarball into a clean
temporary consumer, and test only published imports. It MUST NOT reach into
`src/`, `dist/`, sibling workspace packages, or a mutable path dependency.

The fixture MUST:

- import every supported package subpath;
- typecheck consumer code against the packed declarations;
- load the packaged WASM in Node;
- execute one authorized, denied, and indeterminate result;
- prove internal subpaths cannot be imported;
- prove testkit is opt-in and clearly non-production;
- verify package contents and capability metadata; and
- leave no persistent private material.

The test name and documentation MUST distinguish a manifest-shape test from a
real packed-package consumer test.

### 7.2 Browser evidence

A real browser fixture MUST install or bundle the same packed tarball and run:

- packaged WASM loading;
- one normal authorization workflow;
- one denial with zero gateway calls;
- one plan authorization and sealed gateway handoff;
- disposal and repeated-load behavior; and
- supported bundler resolution.

Browser evidence MUST come from the package under test, not a sibling source
import.

### 7.3 Operating-system matrix

Maintained CI MUST run the applicable packed Node fixture on macOS, Linux, and
Windows. Browser coverage MAY use a smaller justified OS matrix, but the exact
claim and exclusions MUST be recorded.

No platform is supported merely because TypeScript compilation succeeded.

## 8. Consumer documentation and examples

### 8.1 README order

The README MUST lead with the normal agent workflow, not the raw three-byte-
input verifier. The first copyable path SHOULD show:

```text
profile -> authority -> load -> attach -> delegate -> authorize -> gateway
```

Raw proof/action/context verification belongs in an explicitly advanced
section linked to `@auths-dev/sdk/advanced`.

### 8.2 Complete quickstart

At least one maintained example MUST be executable and self-contained. It MUST
include:

- a small closed profile;
- a development-only signer clearly labeled as such;
- bounded root authority;
- an attached parent and narrower child;
- an exact action or short plan;
- a visible approval provider;
- all three authorization outcomes or focused variants;
- a matching closed gateway;
- deterministic disposal; and
- comments identifying which semantics belong to the profile and which belong
  to Auths.

Focused examples for verification, attachment, and delegation MAY remain, but
they MUST teach a real operation rather than simply wrap one SDK method.

### 8.3 Claim metadata

If the README cites `sdk-capability.json`, that artifact MUST have a single
authoritative owner, be generated or validated by release tooling, be included
in the published package when promised, and be checked against the exact
package version. Otherwise the README MUST link to the actual release evidence
and remove the nonexistent package-local reference.

## 9. Public API snapshot

CI MUST freeze the intended public TypeScript declaration surface. The check
MUST reject:

- a newly exported internal helper;
- a removed supported symbol without an authorized prelaunch source cutover;
- a changed provider or result contract without corresponding spec and
  consumer evidence;
- an undocumented package subpath;
- a public method whose argument type depends on a private token; and
- declaration output that references unpublished internal paths.

The snapshot MAY be a normalized `.d.ts` bundle, API Extractor report, or an
equivalent deterministic allowlist. It MUST describe the installed package,
not only the source tree.

## 10. Security and architecture invariants

Every implementation unit MUST preserve:

- local, effect-free verification;
- three-valued decisions;
- identity distinct from authority;
- profile-owned canonicalization and effect meaning;
- verifier-owned command minting;
- closed, profile-matching gateways;
- no effect for denied or indeterminate results;
- no global executor, operation union, receipt union, or credential provider;
- externally held production keys;
- explicit development-only custody;
- exact required/executed configuration evidence;
- bounded attacker-controlled bytes, collections, work, and lifetimes; and
- operation without an Auths-hosted service.

This refactor MUST NOT move GitHub, MCP, Stripe, database, infrastructure, or
other domain semantics into a generic workflow kernel. Shared mechanisms must
satisfy the profile and domain abstraction boundary plan.

## 11. Non-goals

This specification does not authorize:

- a general CLI;
- production custody providers;
- a hosted verification dependency;
- a universal profile or policy language;
- generic effect execution;
- framework-specific application state in the SDK;
- automatic provider effects after authorization;
- Python Full Workflow implementation before AP-SPEC-035's entry gate;
- stable-v1, production-readiness, compliance, or independent-review claims;
- package publication or release promotion; or
- compatibility machinery for accidental prelaunch exports.

## 12. Evidence and tests

Applicable PR units MUST include:

- a public-export negative corpus;
- packed-package import and declaration tests;
- runtime attempts to reach internal registration and minting paths;
- exact-plan reorder, duplicate, omission, append, mutation, replay, expiry,
  overuse, and cross-plan substitution tests;
- required/executed approval-policy mismatch tests;
- signer-not-called and gateway-not-called assertions on every precondition
  failure;
- real-WASM authorized, denied, and indeterminate integration tests;
- Node and real-browser packed-package tests;
- macOS, Linux, and Windows evidence for the claimed Node surface;
- an executable end-to-end example;
- generated public API drift checks; and
- an updated external-consumer scorecard.

Tests MUST demonstrate that required defects are observable. A compilation-
only test or a source-manifest inspection is not packed-package evidence.

## 13. Bounded PR units

1. **`AP37-PR1` — published surface closure.** Replace wildcard workflow
   exports with an explicit allowlist, move coordination hooks behind an
   unpublished boundary, remove accidental prelaunch exports, and add negative
   consumer import tests.
2. **`AP37-PR2` — unified approval policy.** Replace the split policy reference
   and session bounds with one immutable committed/executed policy object. Add
   mismatch, expiry, use-limit, mutation, and inspection evidence.
3. **`AP37-PR3` — exact ordered plan approval.** Bind approval reuse to exact
   plan membership and transaction identity. Add the complete substitution and
   terminal-failure corpus before retaining the `plan-once` claim.
4. **`AP37-PR4` — workflow implementation cut.** Move implementation out of
   the monolithic runtime into ownership modules, delete the old runtime, and
   preserve native differential and lifecycle evidence.
5. **`AP37-PR5` — installed package conformance.** Add clean tarball install,
   supported-subpath imports, packaged WASM execution, internal-path denial,
   and package-content checks.
6. **`AP37-PR6` — browser and platform closure.** Run the packed package in a
   real browser and maintain the justified macOS/Linux/Windows matrix.
7. **`AP37-PR7` — workflow-first documentation.** Replace skeletal examples,
   reorder the README, reconcile capability metadata, and update the external
   consumer scorecard.
8. **`AP37-PR8` — public API freeze.** Add the installed declaration snapshot,
   ownership metadata, intentional-update command, and CI drift gate.

Every PR MUST state its baseline, affected public surfaces, tests, evidence,
claim impact, exclusions, and remaining gates. Code PRs require authoritative
CI on their exact revision. Documentation-only PRs do not establish missing
runtime evidence.

## 14. Exit gate

AP-SPEC-037 is complete only when:

- the installed root API contains no package coordination or resource-access
  hooks;
- internal registration and minting paths cannot be imported through any
  published subpath;
- one immutable approval policy drives both its commitment and execution;
- plan approval reuse accepts only the exact ordered committed members;
- the old monolithic workflow runtime has been deleted;
- the clean packed package passes Node and real-browser workflows;
- the supported Node matrix passes on macOS, Linux, and Windows;
- the first README example and maintained quickstart teach the normal closed-
  gateway workflow;
- package claim metadata exists and agrees with the tested version, or all
  references to it have been corrected;
- CI rejects unreviewed public API drift; and
- all authoritative repository checks pass on the exact revision.

Completion improves the TypeScript SDK's integrity, usability, and package
evidence. It does not close AP-SPEC-036's Python parity gate, establish an
independent security review, publish a package, or promote a release.

## 15. Related documents

- [AP-SPEC-027: TypeScript Full Workflow
  SDK](0027-product-grade-typescript-sdk.md)
- [AP-SPEC-035: Python Full Workflow SDK](0035-python-full-workflow-sdk.md)
- [AP-SPEC-036: SDK ergonomics and external-consumer workflow
  closure](0036_sdk_ergonomics.md)
- [Profile and Domain Abstraction Boundary
  Plan](../target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md)
- [Auths Product and Go-to-Market
  Strategy](../plans/GO_TO_MARKET_STRATEGY.md)
