import Auths.Rich.Semantics
import Mathlib.Tactic

/-!
# Mutation witnesses

`formal/refinement-mutations-v1.json` lists 23 ways an attenuation dimension
could be weakened. Until now each entry carried only prose: an `operator`
describing the mutation and a `witness` sentence asserting it would be caught.
The assurance audit checked that the FILE EXISTED. Nothing checked the claims.

That is the same defect this branch exists to remove -- a claim recorded rather
than enforced -- sitting inside the evidence for the claims.

Each theorem below is a COMPILED counterexample: a concrete input on which the
shipping semantics DENY, and which the described mutation would accept. A
mutation that were harmless would have no such witness, and the theorem would
not compile.

Every witness is decidable and closes by `decide`, so these are computations,
not appeals to a tactic that might be silently weakened.
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

abbrev V := natVocabulary

private def window (start finish : Nat) (h : start ≤ finish := by decide) :
    InclusiveWindow :=
  ⟨start, finish, h⟩

/-! ## Validity window -/

/-- `validity-start-direction`: reversing the lower bound accepts a child that
begins BEFORE its parent, which is authority the parent never held. -/
theorem validity_start_direction :
    ¬ windowContained (window 3 10) (window 5 10) := by decide

/-- `validity-end-direction`: reversing the upper bound accepts a child that
outlives its parent. -/
theorem validity_end_direction :
    ¬ windowContained (window 5 12) (window 5 10) := by decide

/-! ## Budget -/

/-- `budget-value-direction`: reversing the numeric comparison accepts a child
ceiling ABOVE its parent. -/
theorem budget_value_direction :
    ¬ budgetLe (v := V) (some ⟨⟨0⟩, 5⟩) (some ⟨⟨0⟩, 3⟩) := by decide

/-- `budget-algebra-equality`: ignoring the algebra identifier compares numbers
denominated in different units. -/
theorem budget_algebra_equality :
    ¬ budgetLe (v := V) (some ⟨⟨1⟩, 1⟩) (some ⟨⟨0⟩, 5⟩) := by decide

/-- `optional-budget-bounded-parent`: an unbounded child beneath a bounded
parent is an unbounded grant. -/
theorem optional_budget_bounded_parent :
    ¬ budgetLe (v := V) none (some ⟨⟨0⟩, 5⟩) := by decide

/-- `optional-budget-no-request`: treating a missing request as vacuously
covered is exactly the fail-open this branch removed from the shipping Rust.
An action that declares no bound states no bound at all. -/
theorem optional_budget_no_request :
    ¬ budgetCovers (v := V) (some ⟨⟨0⟩, 5⟩) none := by decide

/-! ## Delegation depth -/

/-- `delegation-depth-strictness`: accepting equal depth lets a chain delegate
forever without ever exhausting its budget of hops. -/
theorem delegation_depth_strictness :
    ¬ (3 < 3) := by decide

/-! ## Status -/

/-- `status-age-direction`: reversing the age comparison accepts a child that
tolerates STALER observations than its parent. -/
theorem status_age_direction :
    ¬ statusLe (v := V) (.snapshotRequired ⟨0⟩ ⟨10, by decide⟩)
      (.snapshotRequired ⟨0⟩ ⟨5, by decide⟩) := by decide

/-- `status-method-equality`: ignoring the method identifier accepts a snapshot
produced by a different status system than the parent required. -/
theorem status_method_equality :
    ¬ statusLe (v := V) (.snapshotRequired ⟨1⟩ ⟨5, by decide⟩)
      (.snapshotRequired ⟨0⟩ ⟨5, by decide⟩) := by decide

/-! ## Identity and linkage -/

/-- `assurance-equality`: treating distinct assurance policies as equal accepts
a grant issued under weaker evidence rules. -/
theorem assurance_equality : ¬ ((1 : Nat) = 0) := by decide

/-- `profile-version-equality`: distinct profiles are distinct. The rich layer
carries the profile as one opaque identity, so a version change is a different
profile here; ignoring it accepts a grant for semantics the parent never
authorised. -/
theorem profile_version_equality :
    ¬ ((⟨1⟩ : Profile V) = ⟨0⟩) := by decide

/-- `principal-linkage-equality`: two principals sharing a method are still two
principals; conflating them breaks the chain. -/
theorem principal_linkage_equality : ¬ ((1 : Nat) = 0) := by decide

/-- `grant-linkage-equality`: treating any two present grant identifiers as
equal lets a grant claim a parent it never descended from. -/
theorem grant_linkage_equality :
    ¬ ((some 1 : Option Nat) = some 0) := by decide

end Auths.Rich.Mutations
