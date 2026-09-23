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
theorem attenuation_requires_trust_root {v : Vocabulary} [ExtensionLaws v]
    (parent : ChainState v) (grant : Grant v)
    (accepted :
      certifiedAccepts (delegationProjection parent grant) = true) :
    rootPreserved parent grant :=
  ((rich_projection_accepts_iff_root_and_scope_depth_checks
    parent grant).1 accepted).1

/--
The contrapositive, stated for every input: a broken trust root denies the
whole projection no matter what the other ten dimensions report.
-/
theorem attenuation_denied_when_root_broken {v : Vocabulary} [ExtensionLaws v]
    (parent : ChainState v) (grant : Grant v)
    (broken : ¬ rootPreserved parent grant) :
    certifiedAccepts (delegationProjection parent grant) = false :=
  broken_root_denies_every_projection parent grant broken

/--
The dimension is falsifiable.  A grant issued by any principal other than the
one the parent speaks for drives it to `false`, so no implementation that
returns a literal `true` can satisfy this theorem.
-/
theorem attenuation_root_dimension_is_not_a_literal {v : Vocabulary} [ExtensionLaws v]
    (parent : ChainState v) (grant : Grant v)
    (foreign : grant.issuer ≠ parent.subject) :
    (delegationProjection parent grant).value.rootPreserved = false :=
  root_dimension_false_of_foreign_issuer parent grant foreign

/-- The dimension reports the semantic predicate exactly, in both directions. -/
theorem attenuation_root_dimension_is_exact {v : Vocabulary} [ExtensionLaws v]
    (parent : ChainState v) (grant : Grant v) :
    (delegationProjection parent grant).value.rootPreserved = true ↔
      rootPreserved parent grant :=
  root_dimension_is_exact parent grant

/-!
## The critical-extension dimension

The eleventh dimension judges each critical-extension identifier by the law
its handler declares. The statements below pin the dimension to that relation
and exhibit the inputs on which it is `false`, so a literal cannot satisfy
them.
-/

/--
Acceptance of the generated attenuation contract implies every critical
extension satisfies its identifier's law.
-/
theorem attenuation_requires_critical_extensions {v : Vocabulary} [ExtensionLaws v]
    (parent : ChainState v) (grant : Grant v)
    (accepted :
      certifiedAccepts (delegationProjection parent grant) = true) :
    extensionsLe (some grant.extensions) parent.scope.extensions :=
  (((rich_projection_accepts_iff_root_and_scope_depth_checks
    parent grant).1 accepted).2.2.2).extensions

/--
The contrapositive, stated for every input: a stripped or widened critical
extension denies the whole projection no matter what the other ten dimensions
report.
-/
theorem attenuation_denied_when_extensions_altered {v : Vocabulary} [ExtensionLaws v]
    (parent : ChainState v) (grant : Grant v)
    (broken : ¬ extensionsLe (some grant.extensions) parent.scope.extensions) :
    certifiedAccepts (delegationProjection parent grant) = false :=
  altered_extensions_deny_every_projection parent grant broken

/--
The dimension is falsifiable. Any grant that strips an identifier of a pinned
critical-extension set drives it to `false`, whatever the laws, so no
implementation that returns a literal `true` can satisfy this theorem.
-/
theorem attenuation_extension_dimension_is_not_a_literal {v : Vocabulary} [ExtensionLaws v]
    (parent : ChainState v) (grant : Grant v)
    (pinned : CriticalExtensions v)
    (pinnedBy : parent.scope.extensions = some pinned)
    {entry : CriticalExtension v} (member : entry ∈ pinned.entries)
    (stripped : ∀ candidate ∈ grant.extensions.entries, candidate.id ≠ entry.id) :
    (delegationProjection parent grant).value.extensionsAttenuate = false :=
  extensions_dimension_false_of_stripped parent grant pinned pinnedBy member stripped

/-- The dimension reports the semantic relation exactly, in both directions. -/
theorem attenuation_extension_dimension_is_exact {v : Vocabulary} [ExtensionLaws v]
    (parent : ChainState v) (grant : Grant v) :
    (delegationProjection parent grant).value.extensionsAttenuate = true ↔
      extensionsLe (some grant.extensions) parent.scope.extensions :=
  extensions_dimension_is_exact parent grant

/--
A critical extension attached anywhere in a chain is carried by every later
state. This is the property the whole mechanism exists for: an unaware verifier
must not be able to have the constraint removed from under it.
-/
theorem attenuation_chain_cannot_strip_a_critical_extension {v : Vocabulary} [ExtensionLaws v]
    {start : ChainState v} {rest : List (ChainState v)}
    (chain : DelegationChain start rest)
    (pinned : CriticalExtensions v)
    (pinnedBy : start.scope.extensions = some pinned) :
    ∀ state ∈ rest, ∃ carried, state.scope.extensions = some carried ∧
      ∀ entry ∈ pinned.entries, carried.carries entry.id :=
  chain_retains_pinned_extension_identifiers chain pinned pinnedBy

/--
Delegation never widens authority, given that every critical-extension handler
law is a preorder that narrows: no state reachable along a chain admits a
complete authorization fact its start refuses.
-/
theorem attenuation_chain_never_widens_authority {v : Vocabulary} [ExtensionLaws v]
    (laws : ExtensionLawsNarrow v)
    {start : ChainState v} {rest : List (ChainState v)}
    (chain : DelegationChain start rest) :
    ∀ state ∈ rest, semanticAttenuates state.scope start.scope :=
  chain_never_widens_authority laws chain

end Auths.Attenuation
