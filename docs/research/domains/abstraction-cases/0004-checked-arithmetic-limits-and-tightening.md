# Case 0004: checked arithmetic, limits, and tightening

## Decision

Approve small closed leaf primitives and a common proof shape. Reject a
universal numeric policy or expression language.

## Consumers

All domains use byte/item/time/work bounds. Stripe, PostgreSQL, Kubernetes,
OpenTofu, GitHub, Radicle, and records use distinct capacity dimensions.

## Exact shared contract

Integer operations are checked; units must match; boundary inclusivity and
rounding are explicit; sorted collections are duplicate-free and bounded.
Each policy defines its own `tightens` relation and proves that fixed-context
tightening cannot newly yield eligibility or undercount outputs.

## Deliberate exclusions

Cross-unit conversion, provider prices, row semantics, replica semantics,
resource counts, monetary denominators, rolling-window meaning, and arbitrary
expressions.

## Comparison

| Identical | Divergent |
| --- | --- |
| No overflow/underflow | Unit and capacity meaning |
| Explicit inclusive/exclusive bounds | Rounding and denominator rules |
| Hard byte/item/work limits | Policy-specific maxima |
| Fixed-context monotonicity proof shape | Syntactic tightening decider |

## Versioning and compatibility

Each primitive has an immutable semantic identifier. Policy evaluator versions
pin the primitive versions and their own rounding/inclusivity rules.

## Invariants and evidence

Lean proves representability, checked arithmetic, boundary laws, and the
generic extensional definition of tightening. Each domain proves its concrete
decider sound. Rust uses translated pure predicates, Kani boundaries,
properties, mutation tests, and exact boundary fixtures.

## Migration and rollback

Introduce leaves behind differential tests. Domain numeric types remain until
byte/decision equivalence is established. Rollback returns to the simple
reference implementation without changing policy bytes.

## Performance

Use direct fixed-width operations with explicit failure. Optimize only after
work/allocation counters identify a bottleneck.

## Why smaller composition is insufficient

Checked addition alone does not encode units, inclusivity, or result
refinement. The approved surface is still a composition of small primitives,
but the proof obligations must be registered together.

## Domain-owned code retained

All policy calculations, denominators, conversions, capacity interpretation,
and tightening deciders.
