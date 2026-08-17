import Auths.Rich.Semantics
import qualification.aeneas.generated.model.Funs
import Mathlib.Tactic

/-!
# Mutation witnesses

`formal/refinement-mutations-v1.json` lists 23 ways an attenuation dimension
could be weakened. Until now each entry carried only prose: an `operator`
describing the mutation and a `witness` sentence asserting it would be caught.
The assurance audit checked that the FILE EXISTED. Nothing checked the claims.

That is the same defect this branch exists to remove -- a claim recorded rather
than enforced -- sitting inside the evidence for the claims.

Each theorem below is a COMPILED boundary example: it calls the actual ordered
decision function (`evaluateGrant`, `evaluateAuthorScope`, or
`evaluateCoverage`) on a concrete input.  The expected outcome changes under
the named rich-semantics mutation, so the named theorem fails to compile.  A
shipping-Rust mutation is caught separately by the Aeneas refinement theorem
that binds the translated evaluator to this unchanged rich boundary.

Every witness is decidable and closes by kernel-checked `decide`, so these are
computations, not appeals to an assumption or to native-code evaluation.
Primitive relation facts are deliberately insufficient here: they would keep
compiling if the decision function stopped using the relation.
-/

namespace Auths.Rich.Mutations

open Auths.Rich

/-- Concrete carriers for the witnesses. Equality is all the dimensions use. -/
@[reducible] def natVocabulary : Vocabulary where
  PrincipalCarrier := Nat
  ProfileCarrier := Nat
  PermissionCarrier := Nat
  AudienceCarrier := Nat
  DigestCarrier := Nat
  BudgetAlgebraCarrier := Nat
  StatusMethodCarrier := Nat
  AssuranceCarrier := Nat
  GrantIdCarrier := Nat
  ExtensionIdCarrier := Nat
  ExtensionBodyCarrier := Nat
  principalDecidableEq := inferInstance
  profileDecidableEq := inferInstance
  permissionDecidableEq := inferInstance
  audienceDecidableEq := inferInstance
  digestDecidableEq := inferInstance
  budgetAlgebraDecidableEq := inferInstance
  statusMethodDecidableEq := inferInstance
  assuranceDecidableEq := inferInstance
  grantIdDecidableEq := inferInstance
  extensionIdDecidableEq := inferInstance
  extensionBodyDecidableEq := inferInstance
  extensionIdLinearOrder := inferInstance
  extensionBodyLinearOrder := inferInstance
  extensionBodySize := fun _ => 0

abbrev V := natVocabulary

private def window (start finish : Nat) (h : start ≤ finish := by decide) :
    InclusiveWindow :=
  ⟨start, finish, h⟩

private def baseProfileScope : ProfileScope V where
  rootAllowed := {⟨0⟩}
  selected := some ⟨0⟩
  selectedAllowed := by simp

private def baseScope (assurance : Nat := 0) : AuthorityScope V where
  profileScope := baseProfileScope
  permissions := {⟨0⟩}
  validity := window 0 10
  audiences := {⟨0⟩}
  actionConstraint := .anyBody
  budget := none
  status := .expiryOnly
  assurance := ⟨assurance⟩
  extensions := none

private def baseState
    (root subject depth : Nat) (last : Option Nat) : ChainState V where
  root := ⟨root⟩
  subject := ⟨subject⟩
  scope := baseScope
  remainingDepth := depth
  lastGrant := last.map (fun id => ⟨id⟩)

private def baseGrant
    (issuer : Nat := 0) (remainingDepth : Nat := 0)
    (parent : Option Nat := none) (assurance : Nat := 0) : Grant V where
  issuer := ⟨issuer⟩
  subject := ⟨1⟩
  profile := ⟨0⟩
  permissions := {⟨0⟩}
  validity := window 0 10
  audiences := {⟨0⟩}
  actionConstraint := .anyBody
  budget := none
  remainingDepth := remainingDepth
  parent := parent.map (fun id => ⟨id⟩)
  status := .expiryOnly
  assurance := ⟨assurance⟩
  extensions := CriticalExtensions.empty V

private def baseAction
    (actor : Nat := 0) (terminalGrant : Option Nat := none)
    (profile : Nat := 0) (permission : Nat := 0)
    (audience : Nat := 0) (digest : Nat := 0)
    (requestedBudget : Option (BudgetCeiling V) := none) : Action V where
  actor := ⟨actor⟩
  terminalGrant := terminalGrant.map (fun id => ⟨id⟩)
  profile := ⟨profile⟩
  permission := ⟨permission⟩
  validity := window 0 10
  audience := ⟨audience⟩
  bodyDigest := ⟨digest⟩
  requestedBudget := requestedBudget

private def extension (id body : Nat) : CriticalExtension V :=
  ⟨⟨id⟩, ⟨body⟩⟩

private def singletonExtension (id body : Nat) : CriticalExtensions V :=
  CriticalExtensions.singleton (extension id body) (by
    simp [hardMaxExtensionBytes])

private def delegationDeniedWith
    (expected : DelegationDiagnostic) : DelegationDecision V → Bool
  | .accepted _ => false
  | .denied actual => decide (actual = expected)

/-! ## Validity window -/

/-- `validity-start-direction`: reversing the lower bound accepts a child that
begins BEFORE its parent, which is authority the parent never held. -/
theorem validity_start_direction :
    evaluateAuthorScope
      { baseScope with validity := window 5 10 }
      { baseScope with validity := window 3 10 }
      2 1 = .denied .validity := by decide

/-- `validity-end-direction`: reversing the upper bound accepts a child that
outlives its parent. -/
theorem validity_end_direction :
    evaluateAuthorScope
      { baseScope with validity := window 5 10 }
      { baseScope with validity := window 5 12 }
      2 1 = .denied .validity := by decide

/-! ## Finite-set direction and membership -/

theorem permission_subset_direction :
    evaluateAuthorScope
      { baseScope with permissions := {⟨0⟩, ⟨1⟩} }
      { baseScope with permissions := {⟨0⟩} }
      2 1 = .accepted := by decide

theorem audience_subset_direction :
    evaluateAuthorScope
      { baseScope with audiences := {⟨0⟩, ⟨1⟩} }
      { baseScope with audiences := {⟨0⟩} }
      2 1 = .accepted := by decide

theorem permission_membership_decision :
    evaluateCoverage (baseState 0 0 2 none) baseAction
      .expressible = .authorized := by decide

theorem audience_membership_decision :
    evaluateCoverage (baseState 0 0 2 none) baseAction
      .expressible = .authorized := by decide

theorem body_digest_membership_decision :
    evaluateCoverage
      { baseState 0 0 2 none with
        scope := { baseScope with
          actionConstraint := .allowedBodyDigests {⟨0⟩} } }
      baseAction .expressible = .authorized := by decide

theorem body_digest_subset_direction :
    evaluateAuthorScope
      { baseScope with actionConstraint := .allowedBodyDigests {⟨0⟩, ⟨1⟩} }
      { baseScope with actionConstraint := .allowedBodyDigests {⟨0⟩} }
      2 1 = .accepted := by decide

/-! ## Action constraints -/

theorem action_exact_equality :
    evaluateCoverage
      { baseState 0 0 2 none with
        scope := { baseScope with actionConstraint := .exactBodyDigest ⟨0⟩ } }
      (baseAction (digest := 1)) .expressible =
        .denied .actionConstraintMismatch := by decide

theorem action_constructor_fallback :
    evaluateAuthorScope
      { baseScope with actionConstraint := .exactBodyDigest ⟨0⟩ }
      { baseScope with actionConstraint := .allowedBodyDigests {⟨0⟩, ⟨1⟩} }
      2 1 = .denied .actionConstraint := by
  have different :
      ({⟨0⟩, ⟨1⟩} : FiniteSet (Digest V)) ≠ {⟨0⟩} := by decide
  simp [evaluateAuthorScope, baseScope, baseProfileScope, profileLe,
    windowContained, actionConstraintLe, different]

theorem action_singleton_exact_rejection :
    evaluateAuthorScope
      { baseScope with actionConstraint := .exactBodyDigest ⟨0⟩ }
      { baseScope with actionConstraint := .allowedBodyDigests {⟨0⟩} }
      2 1 = .accepted := by
  simp [evaluateAuthorScope, baseScope, baseProfileScope, profileLe,
    windowContained, actionConstraintLe, budgetLe, statusLe, extensionsLe]

/-! ## Budget -/

/-- `budget-value-direction`: reversing the numeric comparison accepts a child
ceiling ABOVE its parent. -/
theorem budget_value_direction :
    evaluateAuthorScope
      { baseScope with budget := some ⟨⟨0⟩, 3⟩ }
      { baseScope with budget := some ⟨⟨0⟩, 5⟩ }
      2 1 = .denied .budget := by decide

/-- `budget-algebra-equality`: ignoring the algebra identifier compares numbers
denominated in different units. -/
theorem budget_algebra_equality :
    evaluateAuthorScope
      { baseScope with budget := some ⟨⟨0⟩, 5⟩ }
      { baseScope with budget := some ⟨⟨1⟩, 1⟩ }
      2 1 = .denied .budget := by decide

/-- `optional-budget-bounded-parent`: an unbounded child beneath a bounded
parent is an unbounded grant. -/
theorem optional_budget_bounded_parent :
    evaluateAuthorScope
      { baseScope with budget := some ⟨⟨0⟩, 5⟩ }
      { baseScope with budget := none }
      2 1 = .denied .budget := by decide

/-- `optional-budget-no-request`: treating a missing request as vacuously
covered is exactly the fail-open this branch removed from the shipping Rust.
An action that declares no bound states no bound at all. -/
theorem optional_budget_no_request :
    evaluateCoverage
      { baseState 0 0 2 none with
        scope := { baseScope with budget := some ⟨⟨0⟩, 5⟩ } }
      baseAction .expressible = .denied .budgetCeilingExceeded := by
  decide

/-! ## Delegation depth -/

/-- `delegation-depth-strictness`: accepting equal depth lets a chain delegate
forever without ever exhausting its budget of hops. -/
theorem delegation_depth_strictness :
    delegationDeniedWith .delegationExpanded
      (evaluateGrant (baseState 0 0 3 none) ⟨0⟩
        (baseGrant (remainingDepth := 3))) = true := by decide

/-! ## Status -/

/-- `status-age-direction`: reversing the age comparison accepts a child that
tolerates STALER observations than its parent. -/
theorem status_age_direction :
    evaluateAuthorScope
      { baseScope with status := .snapshotRequired ⟨0⟩ ⟨5, by decide⟩ }
      { baseScope with status := .snapshotRequired ⟨0⟩ ⟨10, by decide⟩ }
      2 1 = .denied .status := by decide

/-- `status-method-equality`: ignoring the method identifier accepts a snapshot
produced by a different status system than the parent required. -/
theorem status_method_equality :
    evaluateAuthorScope
      { baseScope with status := .snapshotRequired ⟨0⟩ ⟨5, by decide⟩ }
      { baseScope with status := .snapshotRequired ⟨1⟩ ⟨5, by decide⟩ }
      2 1 = .denied .status := by decide

/-! ## Identity and linkage -/

/-- `assurance-equality`: treating distinct assurance policies as equal accepts
a grant issued under weaker evidence rules. -/
theorem assurance_equality :
    evaluateAuthorScope (baseScope 0) (baseScope 1) 2 1 =
      .denied .assurance := by decide

/-- `profile-version-equality`: the version is part of profile identity.

Stated against the TRANSLATED `profile_ref_equal` rather than the rich carrier.
The rich layer models a profile as one opaque identity, so a version change is
indistinguishable there from any other change of profile -- which would prove
something weaker than the mutation describes. The translated function compares
`version` before `id`, so a version-only difference is decided without reaching
the opaque `as_bytes`, and this witness kills a mutant that ignores it. -/
theorem profile_version_equality :
    auths_model.profile_ref_equal
        { id := "auths.opentofu.saved-plan-apply", version := 2#u16 }
        { id := "auths.opentofu.saved-plan-apply", version := 1#u16 } =
      Aeneas.Std.Result.ok false := by
  rfl

/-- `principal-linkage-equality`: two principals sharing a method are still two
principals; conflating them breaks the chain. -/
theorem principal_linkage_equality :
    delegationDeniedWith .brokenGrantChain
      (evaluateGrant (baseState 0 0 1 none) ⟨0⟩
        (baseGrant (issuer := 1))) = true := by decide

/-- `grant-linkage-equality`: treating any two present grant identifiers as
equal lets a grant claim a parent it never descended from. -/
theorem grant_linkage_equality :
    delegationDeniedWith .brokenGrantChain
      (evaluateGrant (baseState 0 0 1 (some 0)) ⟨2⟩
        (baseGrant (parent := some 1))) = true := by decide

/-! ## Critical extensions -/

theorem critical_extension_equality :
    evaluateAuthorScope
      { baseScope with extensions := some (singletonExtension 0 0) }
      { baseScope with extensions := some (singletonExtension 0 1) }
      2 1 = .denied .extensions := by decide

/-- A reversed identifier pair is not a Rust-canonical extension sequence. -/
theorem critical_extensions_reversed_not_sorted :
    ¬ ([extension 1 0, extension 0 0].Pairwise criticalExtensionLt) := by
  decide

end Auths.Rich.Mutations
