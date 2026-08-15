import Auths.Rich.Theorems

/-!
Rich target-V1 attenuation, coverage, transition, diagnostic, and
well-founded-depth theorems.  There is deliberately no `Nat` product-order
surrogate in this module.

## The trust-root dimension

`Auths.Generated.AttenuationProjection` declares eleven dimensions, and
acceptance is their conjunction.  The statements below pin the first of them —
`rootPreserved` — to a predicate over real root identities, so that the
generated conjunction cannot be satisfied by a dimension that is constantly
`true`.
-/

namespace Auths.Attenuation

open Auths.Rich

/--
Acceptance of the generated attenuation contract implies the trust root is
preserved.  With a constant `rootPreserved` this is provable but empty; it has
content exactly because `rootPreserved` is decided from `parent.root`,
`parent.subject`, `parent.lastGrant`, and `grant.issuer`.
-/
theorem attenuation_requires_trust_root {v : Vocabulary}
    (parent : ChainState v) (grant : Grant v)
    (accepted :
      Auths.Generated.attenuationAccepts
        (delegationProjection parent grant) = true) :
    rootPreserved parent grant :=
  ((rich_projection_accepts_iff_root_and_scope_depth_checks
    parent grant).1 accepted).1

/--
The contrapositive, stated for every input: a broken trust root denies the
whole projection no matter what the other ten dimensions report.
-/
theorem attenuation_denied_when_root_broken {v : Vocabulary}
    (parent : ChainState v) (grant : Grant v)
    (broken : ¬ rootPreserved parent grant) :
    Auths.Generated.attenuationAccepts
      (delegationProjection parent grant) = false :=
  broken_root_denies_every_projection parent grant broken

/--
The dimension is falsifiable.  A grant issued by any principal other than the
one the parent speaks for drives it to `false`, so no implementation that
returns a literal `true` can satisfy this theorem.
-/
theorem attenuation_root_dimension_is_not_a_literal {v : Vocabulary}
    (parent : ChainState v) (grant : Grant v)
    (foreign : grant.issuer ≠ parent.subject) :
    (delegationProjection parent grant).rootPreserved = false :=
  root_dimension_false_of_foreign_issuer parent grant foreign

/-- The dimension reports the semantic predicate exactly, in both directions. -/
theorem attenuation_root_dimension_is_exact {v : Vocabulary}
    (parent : ChainState v) (grant : Grant v) :
    (delegationProjection parent grant).rootPreserved = true ↔
      rootPreserved parent grant :=
  root_dimension_is_exact parent grant

end Auths.Attenuation
