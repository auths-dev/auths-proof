import Auths.Rich.Semantics
import Mathlib.Tactic

namespace Auths.Rich

universe u

theorem finiteSet_subset_refl {α : Type u} (set : FiniteSet α) :
    set ⊆ set :=
  Finset.Subset.refl set

theorem finiteSet_subset_trans {α : Type u}
    {a b c : FiniteSet α} (hab : a ⊆ b) (hbc : b ⊆ c) :
    a ⊆ c :=
  Finset.Subset.trans hab hbc

theorem finiteSet_subset_antisymm {α : Type u}
    {a b : FiniteSet α} (hab : a ⊆ b) (hba : b ⊆ a) :
    a = b :=
  Finset.Subset.antisymm hab hba

theorem finiteSet_membership_monotone {α : Type u}
    {child parent : FiniteSet α} {item : α}
    (subset : child ⊆ parent) (member : item ∈ child) :
    item ∈ parent :=
  subset member

theorem window_contained_refl (window : InclusiveWindow) :
    windowContained window window := by
  simp [windowContained]

theorem window_contained_trans {a b c : InclusiveWindow}
    (hab : windowContained a b) (hbc : windowContained b c) :
    windowContained a c := by
  simp only [windowContained] at *
  omega

theorem window_contained_antisymm {a b : InclusiveWindow}
    (hab : windowContained a b) (hba : windowContained b a) :
    a = b := by
  rcases a with ⟨aStart, aFinish, aWellFormed⟩
  rcases b with ⟨bStart, bFinish, bWellFormed⟩
  simp only [windowContained] at hab hba
  simp_all
  omega

theorem window_coverage_monotone
    {action child parent : InclusiveWindow}
    (childLe : windowContained child parent)
    (covered : windowContained action child) :
    windowContained action parent :=
  window_contained_trans covered childLe

theorem action_constraint_refl {v : Vocabulary}
    (constraint : ActionConstraint v) :
    actionConstraintLe constraint constraint := by
  cases constraint <;> simp [actionConstraintLe]

theorem action_constraint_trans {v : Vocabulary}
    {a b c : ActionConstraint v}
    (hab : actionConstraintLe a b) (hbc : actionConstraintLe b c) :
    actionConstraintLe a c := by
  cases a <;> cases b <;> cases c <;>
    simp only [actionConstraintLe] at hab hbc ⊢ <;>
    first | aesop | exact Finset.Subset.trans hab hbc

theorem action_constraint_allows_monotone {v : Vocabulary}
    {child parent : ActionConstraint v} {digest : Digest v}
    (order : actionConstraintLe child parent)
    (allowed : actionConstraintAllows child digest) :
    actionConstraintAllows parent digest := by
  cases child <;> cases parent <;>
    simp only [actionConstraintLe, actionConstraintAllows] at order allowed ⊢ <;>
    aesop

/-- Mutual attenuation makes raw action constraints extensionally equivalent. -/
theorem action_constraint_antisymm {v : Vocabulary}
    {a b : ActionConstraint v}
    (hab : actionConstraintLe a b) (hba : actionConstraintLe b a) :
    ∀ digest, actionConstraintAllows a digest ↔ actionConstraintAllows b digest := by
  intro digest
  exact ⟨action_constraint_allows_monotone hab,
    action_constraint_allows_monotone hba⟩

/-- Canonical representatives recover structural antisymmetry. -/
theorem action_constraint_canonical_antisymm {v : Vocabulary}
    {a b : ActionConstraint v}
    (aCanonical : actionConstraintCanonical a)
    (bCanonical : actionConstraintCanonical b)
    (hab : actionConstraintLe a b) (hba : actionConstraintLe b a) :
    a = b := by
  cases a <;> cases b <;>
    simp_all [actionConstraintCanonical, actionConstraintLe]
  exact Finset.Subset.antisymm hab hba

theorem budget_refl {v : Vocabulary}
    (budget : Option (BudgetCeiling v)) :
    budgetLe budget budget := by
  cases budget <;> simp [budgetLe]

theorem budget_trans {v : Vocabulary}
    {a b c : Option (BudgetCeiling v)}
    (hab : budgetLe a b) (hbc : budgetLe b c) :
    budgetLe a c := by
  cases c with
  | none => trivial
  | some c =>
      cases b with
      | none => simp [budgetLe] at hbc
      | some b =>
          cases a with
          | none => simp [budgetLe] at hab
          | some a =>
              simp only [budgetLe] at hab hbc ⊢
              exact ⟨hab.1.trans hbc.1, hab.2.trans hbc.2⟩

theorem budget_antisymm {v : Vocabulary}
    {a b : Option (BudgetCeiling v)}
    (hab : budgetLe a b) (hba : budgetLe b a) :
    a = b := by
  cases a with
  | none =>
      cases b with
      | none => rfl
      | some b => simp [budgetLe] at hab
  | some a =>
      cases b with
      | none => simp [budgetLe] at hba
      | some b =>
          simp only [budgetLe] at hab hba
          have algebraEquality : a.algebra = b.algebra := hab.1
          have valueEquality : a.value = b.value :=
            Nat.le_antisymm hab.2 hba.2
          cases a
          cases b
          simp_all

theorem budget_coverage_monotone {v : Vocabulary}
    {child parent requested : Option (BudgetCeiling v)}
    (order : budgetLe child parent)
    (covered : budgetCovers child requested) :
    budgetCovers parent requested := by
  cases parent with
  | none => simp [budgetCovers]
  | some parent =>
      cases child with
      | none => simp [budgetLe] at order
      | some child =>
          simp only [budgetLe] at order
          cases requested with
          | none => simp only [budgetCovers] at covered
          | some requested =>
              simp only [budgetCovers] at covered ⊢
              exact ⟨covered.1.trans order.1, covered.2.trans order.2⟩

theorem extensions_refl {v : Vocabulary}
    (extensions : Option (CriticalExtensions v)) :
    extensionsLe extensions extensions := by
  cases extensions <;> simp [extensionsLe]

theorem extensions_trans {v : Vocabulary}
    {a b c : Option (CriticalExtensions v)}
    (hab : extensionsLe a b) (hbc : extensionsLe b c) :
    extensionsLe a c := by
  cases c with
  | none => trivial
  | some c =>
      cases b with
      | none => simp [extensionsLe] at hbc
      | some b =>
          cases a with
          | none => simp [extensionsLe] at hab
          | some a =>
              simp only [extensionsLe] at hab hbc ⊢
              exact hab.trans hbc

theorem extensions_antisymm {v : Vocabulary}
    {a b : Option (CriticalExtensions v)}
    (hab : extensionsLe a b) (hba : extensionsLe b a) :
    a = b := by
  cases a with
  | none =>
      cases b with
      | none => rfl
      | some b => simp [extensionsLe] at hab
  | some a =>
      cases b with
      | none => simp [extensionsLe] at hba
      | some b =>
          simp only [extensionsLe] at hab
          rw [hab]

/--
A parent that has pinned an extension set admits exactly that set.

This is the falsifiable content of dimension 11: for every pinned set there is
a child set the relation refuses, so no constant can satisfy it.
-/
@[simp] theorem extensions_le_pinned_iff {v : Vocabulary}
    (child parent : CriticalExtensions v) :
    extensionsLe (some child) (some parent) ↔ child = parent :=
  Iff.rfl

/-- A child that drops a pinned set is refused, for every pinned set. -/
theorem extensions_le_false_of_dropped {v : Vocabulary}
    (parent : CriticalExtensions v) :
    ¬ extensionsLe (none : Option (CriticalExtensions v)) (some parent) := by
  simp [extensionsLe]

/-- A child that alters a pinned set is refused, for every alteration. -/
theorem extensions_le_false_of_altered {v : Vocabulary}
    {child parent : CriticalExtensions v}
    (altered : child ≠ parent) :
    ¬ extensionsLe (some child) (some parent) := by
  simpa [extensionsLe] using altered

/--
The class the two theorems above quantify over is inhabited, so neither is
vacuous: dropping the single extension of a one-element set is refused.
-/
theorem extensions_le_refuses_a_dropped_singleton {v : Vocabulary}
    (extension : CriticalExtension v)
    (bodyBounded :
      v.extensionBodySize extension.body.value ≤ hardMaxExtensionBytes) :
    ¬ extensionsLe
        (some (CriticalExtensions.empty v))
        (some (CriticalExtensions.singleton extension bodyBounded)) :=
  extensions_le_false_of_altered
    (CriticalExtensions.empty_ne_singleton extension bodyBounded)

theorem status_refl {v : Vocabulary} (status : StatusPolicy v) :
    statusLe status status := by
  cases status <;> simp [statusLe]

theorem status_trans {v : Vocabulary}
    {a b c : StatusPolicy v}
    (hab : statusLe a b) (hbc : statusLe b c) :
    statusLe a c := by
  cases c with
  | expiryOnly => trivial
  | snapshotRequired cMethod cAge =>
      cases b with
      | expiryOnly => simp [statusLe] at hbc
      | snapshotRequired bMethod bAge =>
          cases a with
          | expiryOnly => simp [statusLe] at hab
          | snapshotRequired aMethod aAge =>
              simp only [statusLe] at hab hbc ⊢
              exact ⟨hab.1.trans hbc.1, hab.2.trans hbc.2⟩

theorem status_antisymm {v : Vocabulary}
    {a b : StatusPolicy v}
    (hab : statusLe a b) (hba : statusLe b a) :
    a = b := by
  cases a <;> cases b <;> simp_all [statusLe]
  rename_i aMethod aAge bMethod bAge
  have methodEquality : aMethod = bMethod := hab.1
  have ageEquality : aAge.seconds = bAge.seconds := by omega
  cases methodEquality
  rcases aAge with ⟨aSeconds, aPositive⟩
  rcases bAge with ⟨bSeconds, bPositive⟩
  simp_all

theorem status_satisfaction_monotone {v : Vocabulary}
    {child parent : StatusPolicy v} {facts : EvidenceFacts v}
    (order : statusLe child parent)
    (satisfied : statusSatisfied child facts) :
    statusSatisfied parent facts := by
  cases parent with
  | expiryOnly => trivial
  | snapshotRequired parentMethod parentAge =>
      cases child with
      | expiryOnly => simp [statusLe] at order
      | snapshotRequired childMethod childAge =>
          simp only [statusLe] at order
          simp only [statusSatisfied] at satisfied ⊢
          exact ⟨satisfied.1.trans (congrArg some order.1),
            satisfied.2.trans order.2⟩

theorem profile_refl {v : Vocabulary} (profile : ProfileScope v) :
    profileLe profile profile := by
  constructor
  · rfl
  · cases profile.selected <;> simp

theorem profile_trans {v : Vocabulary}
    {a b c : ProfileScope v}
    (hab : profileLe a b) (hbc : profileLe b c) :
    profileLe a c := by
  rcases a with ⟨aRoot, aSelected, aAllowed⟩
  rcases b with ⟨bRoot, bSelected, bAllowed⟩
  rcases c with ⟨cRoot, cSelected, cAllowed⟩
  cases aSelected <;> cases bSelected <;> cases cSelected <;>
    simp_all [profileLe]

theorem profile_antisymm {v : Vocabulary}
    {a b : ProfileScope v}
    (hab : profileLe a b) (hba : profileLe b a) :
    a = b := by
  rcases a with ⟨aRoot, aSelected, aAllowed⟩
  rcases b with ⟨bRoot, bSelected, bAllowed⟩
  cases aSelected <;> cases bSelected <;>
    simp_all [profileLe]

theorem profile_coverage_monotone {v : Vocabulary}
    {child parent : ProfileScope v} {profile : Profile v}
    (order : profileLe child parent)
    (covered : profileAllows child profile) :
    profileAllows parent profile := by
  cases childSelected : child.selected with
  | none =>
      cases parentSelected : parent.selected with
      | none =>
          simp only [profileAllows, childSelected] at covered
          simp only [profileAllows, parentSelected]
          exact order.1 ▸ covered
      | some parentProfile =>
          simp [profileLe, childSelected, parentSelected] at order
  | some childProfile =>
      cases parentSelected : parent.selected with
      | none =>
          simp only [profileAllows, childSelected] at covered
          simp only [profileAllows, parentSelected]
          have member := child.selectedAllowed childProfile childSelected
          exact order.1 ▸ (covered ▸ member)
      | some parentProfile =>
          simp only [profileAllows, childSelected] at covered
          simp only [profileAllows, parentSelected]
          simp only [profileLe, childSelected, parentSelected] at order
          exact covered.trans order.2

theorem structural_scope_le_refl {v : Vocabulary}
    (scope : AuthorityScope v) :
    structuralScopeLe scope scope := by
  simp [structuralScopeLe, profile_refl, window_contained_refl,
    action_constraint_refl, budget_refl, status_refl, extensions_refl]

theorem structural_scope_le_trans {v : Vocabulary}
    {a b c : AuthorityScope v}
    (hab : structuralScopeLe a b) (hbc : structuralScopeLe b c) :
    structuralScopeLe a c := by
  rcases hab with ⟨profileAB, permissionAB, validityAB, audienceAB,
    actionAB, budgetAB, statusAB, assuranceAB, extensionsAB⟩
  rcases hbc with ⟨profileBC, permissionBC, validityBC, audienceBC,
    actionBC, budgetBC, statusBC, assuranceBC, extensionsBC⟩
  exact ⟨
    profile_trans profileAB profileBC,
    Finset.Subset.trans permissionAB permissionBC,
    window_contained_trans validityAB validityBC,
    Finset.Subset.trans audienceAB audienceBC,
    action_constraint_trans actionAB actionBC,
    budget_trans budgetAB budgetBC,
    status_trans statusAB statusBC,
    assuranceAB.trans assuranceBC,
    extensions_trans extensionsAB extensionsBC
  ⟩

theorem scope_le_canonical_antisymmetry {v : Vocabulary}
    {a b : AuthorityScope v}
    (aActionCanonical : actionConstraintCanonical a.actionConstraint)
    (bActionCanonical : actionConstraintCanonical b.actionConstraint)
    (hab : structuralScopeLe a b) (hba : structuralScopeLe b a) :
    a = b := by
  rcases hab with ⟨profileAB, permissionAB, validityAB, audienceAB,
    actionAB, budgetAB, statusAB, assuranceAB, extensionsAB⟩
  rcases hba with ⟨profileBA, permissionBA, validityBA, audienceBA,
    actionBA, budgetBA, statusBA, assuranceBA, extensionsBA⟩
  have profileEquality := profile_antisymm profileAB profileBA
  have permissionEquality := Finset.Subset.antisymm permissionAB permissionBA
  have validityEquality := window_contained_antisymm validityAB validityBA
  have audienceEquality := Finset.Subset.antisymm audienceAB audienceBA
  have actionEquality := action_constraint_canonical_antisymm
    aActionCanonical bActionCanonical actionAB actionBA
  have budgetEquality := budget_antisymm budgetAB budgetBA
  have statusEquality := status_antisymm statusAB statusBA
  have extensionsEquality := extensions_antisymm extensionsAB extensionsBA
  rcases a with ⟨aProfile, aPermissions, aValidity, aAudiences, aAction,
    aBudget, aStatus, aAssurance, aExtensions⟩
  rcases b with ⟨bProfile, bPermissions, bValidity, bAudiences, bAction,
    bBudget, bStatus, bAssurance, bExtensions⟩
  simp_all

theorem action_coverage_downward_closed {v : Vocabulary}
    {child parent : AuthorityScope v} {action : Action v}
    (order : structuralScopeLe child parent)
    (covered : actionCovers child action) :
    actionCovers parent action := by
  rcases order with ⟨profileOrder, permissionOrder, validityOrder,
    audienceOrder, actionOrder, budgetOrder, statusOrder, assuranceOrder,
    extensionsOrder⟩
  rcases covered with ⟨profileCovered, permissionCovered, validityCovered,
    audienceCovered, actionCovered, budgetCovered⟩
  exact ⟨
    profile_coverage_monotone profileOrder profileCovered,
    permissionOrder permissionCovered,
    window_coverage_monotone validityOrder validityCovered,
    audienceOrder audienceCovered,
    action_constraint_allows_monotone actionOrder actionCovered,
    budget_coverage_monotone budgetOrder budgetCovered
  ⟩

theorem evidence_requirements_downward_closed {v : Vocabulary}
    {child parent : AuthorityScope v} {facts : EvidenceFacts v}
    (order : structuralScopeLe child parent)
    (satisfied : evidenceRequirementsSatisfied child facts) :
    evidenceRequirementsSatisfied parent facts := by
  rcases order with ⟨_, _, _, _, _, _, statusOrder, assuranceOrder, _⟩
  rcases satisfied with ⟨statusSatisfiedByFacts, assuranceSatisfied⟩
  exact ⟨
    status_satisfaction_monotone statusOrder statusSatisfiedByFacts,
    assuranceSatisfied.trans assuranceOrder
  ⟩

theorem complete_admission_downward_closed {v : Vocabulary}
    {child parent : AuthorityScope v} {facts : AuthorizationFacts v}
    (order : structuralScopeLe child parent)
    (accepted : admits child facts) :
    admits parent facts :=
  ⟨action_coverage_downward_closed order accepted.1,
    evidence_requirements_downward_closed order accepted.2⟩

theorem semantic_attenuation_preorder_refl {v : Vocabulary}
    (scope : AuthorityScope v) :
    semanticAttenuates scope scope := by
  intro facts accepted
  exact accepted

theorem semantic_attenuation_preorder_trans {v : Vocabulary}
    {a b c : AuthorityScope v}
    (hab : semanticAttenuates a b) (hbc : semanticAttenuates b c) :
    semanticAttenuates a c := by
  intro facts accepted
  exact hbc facts (hab facts accepted)

theorem structural_scope_le_implies_semantic_attenuation {v : Vocabulary}
    {child parent : AuthorityScope v}
    (order : structuralScopeLe child parent) :
    semanticAttenuates child parent := by
  intro facts accepted
  exact complete_admission_downward_closed order accepted

def scopeSemanticEquivalent {v : Vocabulary}
    (left right : AuthorityScope v) : Prop :=
  semanticAttenuates left right ∧ semanticAttenuates right left

theorem scope_semantic_equivalence {v : Vocabulary}
    (scope : AuthorityScope v) :
    scopeSemanticEquivalent scope scope :=
  ⟨semantic_attenuation_preorder_refl scope,
    semantic_attenuation_preorder_refl scope⟩

def structuralScopeLeDecide {v : Vocabulary}
    (child parent : AuthorityScope v) : Bool :=
  decide (structuralScopeLe child parent)

theorem structural_scope_le_decides_declared_v1_relation {v : Vocabulary}
    (child parent : AuthorityScope v) :
    structuralScopeLeDecide child parent = true ↔
      structuralScopeLe child parent := by
  simp [structuralScopeLeDecide]

theorem accepted_scope_le {v : Vocabulary}
    (parent : AuthorityScope v) (grant : Grant v)
    (checks : grantScopeChecks parent grant) :
    structuralScopeLe (acceptedScope parent grant checks) parent := by
  rcases checks with ⟨profileCheck, permissionCheck, validityCheck,
    audienceCheck, actionCheck, budgetCheck, statusCheck, assuranceCheck,
    extensionsCheck⟩
  constructor
  · constructor
    · rfl
    · cases selected : parent.profileScope.selected with
      | none => trivial
      | some selectedProfile =>
          simpa [acceptedScope, profileAllows, selected] using profileCheck
  · exact ⟨permissionCheck, validityCheck, audienceCheck, actionCheck,
      budgetCheck, statusCheck, assuranceCheck, extensionsCheck⟩

theorem delegate_implies_scope_le {v : Vocabulary}
    {parent child : ChainState v} {grantId : GrantId v} {grant : Grant v}
    (accepted : delegates parent grantId grant child) :
    structuralScopeLe child.scope parent.scope := by
  rcases accepted.2 with ⟨checks, childEquality⟩
  subst child
  exact accepted_scope_le parent.scope grant checks.2.2

theorem delegate_preserves_root {v : Vocabulary}
    {parent child : ChainState v} {grantId : GrantId v} {grant : Grant v}
    (accepted : delegates parent grantId grant child) :
    child.root = parent.root := by
  rcases accepted with ⟨_, ⟨_, rfl⟩⟩
  rfl

/-!
### Trust-root preservation

`delegate_preserves_root` alone is not the security claim: it holds for any
definition of `delegates` because `acceptedNextState` copies the root field.
The claim only has content once an edge is *required* to descend from that
root.  The theorems below establish that requirement over all inputs.
-/

/-- An edge is only accepted from a parent that descends from its own root. -/
theorem delegate_requires_rooted_parent {v : Vocabulary}
    {parent child : ChainState v} {grantId : GrantId v} {grant : Grant v}
    (accepted : delegates parent grantId grant child) :
    rooted parent :=
  accepted.1.1.1

/-- An accepted edge is issued by the principal the parent speaks for. -/
theorem delegate_requires_parent_issuer {v : Vocabulary}
    {parent child : ChainState v} {grantId : GrantId v} {grant : Grant v}
    (accepted : delegates parent grantId grant child) :
    grant.issuer = parent.subject :=
  accepted.1.1.2

/-- Rootedness is closed under accepted edges, so the invariant is inductive. -/
theorem delegate_preserves_rootedness {v : Vocabulary}
    {parent child : ChainState v} {grantId : GrantId v} {grant : Grant v}
    (accepted : delegates parent grantId grant child) :
    rooted child := by
  rcases accepted with ⟨_, ⟨_, rfl⟩⟩
  exact Or.inl rfl

/--
The first edge of any chain is issued by the root itself.  This is the case
`delegate_preserves_root` cannot see: with an unrooted parent the model would
mint authority under a root that never conferred it.
-/
theorem first_edge_is_issued_by_the_root {v : Vocabulary}
    {parent child : ChainState v} {grantId : GrantId v} {grant : Grant v}
    (fresh : parent.lastGrant = none)
    (accepted : delegates parent grantId grant child) :
    grant.issuer = parent.root := by
  have issuer := delegate_requires_parent_issuer accepted
  rcases delegate_requires_rooted_parent accepted with applied | isRoot
  · rw [fresh] at applied
    exact absurd applied (by simp)
  · rw [issuer, ← isRoot]

/-- Every state reachable from `start` descends from `start.root`. -/
theorem chain_preserves_root {v : Vocabulary}
    {start : ChainState v} {rest : List (ChainState v)}
    (chain : DelegationChain start rest) :
    ∀ state ∈ rest, state.root = start.root := by
  induction chain with
  | nil => simp
  | cons parent child grantId grant rest edge tail inductionHypothesis =>
      intro state member
      rcases List.mem_cons.1 member with head | inTail
      · rw [head]
        exact delegate_preserves_root edge
      · exact (inductionHypothesis state inTail).trans
          (delegate_preserves_root edge)

/-- Every state reachable from a rooted `start` is itself rooted. -/
theorem chain_preserves_rootedness {v : Vocabulary}
    {start : ChainState v} {rest : List (ChainState v)}
    (chain : DelegationChain start rest) :
    ∀ state ∈ rest, rooted state := by
  induction chain with
  | nil => simp
  | cons parent child grantId grant rest edge tail inductionHypothesis =>
      intro state member
      rcases List.mem_cons.1 member with head | inTail
      · rw [head]
        exact delegate_preserves_rootedness edge
      · exact inductionHypothesis state inTail

/-- A parent that descends from no root delegates nothing, for every grant. -/
theorem unrooted_parent_delegates_nothing {v : Vocabulary}
    (parent : ChainState v) (grantId : GrantId v) (grant : Grant v)
    (unrooted : ¬ rooted parent) :
    evaluateGrant parent grantId grant = .denied .brokenGrantChain := by
  simp [evaluateGrant, linked, rootPreserved, unrooted]

/-- A parent that descends from no root authorizes no action either. -/
theorem unrooted_authority_covers_nothing {v : Vocabulary}
    (authority : ChainState v) (action : Action v)
    (unrooted : ¬ rooted authority) :
    evaluateCoverage authority action = .denied .brokenGrantChain := by
  simp [evaluateCoverage, unrooted]

/--
The generated trust-root dimension reports exactly the semantic predicate.
This is what makes the dimension non-vacuous: it is `false` on a real class of
inputs, so a literal `true` would refute it.
-/
theorem root_dimension_is_exact {v : Vocabulary}
    (parent : ChainState v) (grant : Grant v) :
    (delegationProjection parent grant).rootPreserved = true ↔
      rootPreserved parent grant := by
  simp [delegationProjection]

/-- Witness that the dimension is falsifiable, stated over all inputs. -/
theorem root_dimension_false_of_foreign_issuer {v : Vocabulary}
    (parent : ChainState v) (grant : Grant v)
    (foreign : grant.issuer ≠ parent.subject) :
    (delegationProjection parent grant).rootPreserved = false := by
  simp [delegationProjection, rootPreserved, foreign]

/--
No other attenuation dimension can rescue a broken root: acceptance is the
conjunction, so the whole projection is rejected.
-/
theorem broken_root_denies_every_projection {v : Vocabulary}
    (parent : ChainState v) (grant : Grant v)
    (broken : ¬ rootPreserved parent grant) :
    Auths.Generated.attenuationAccepts
      (delegationProjection parent grant) = false := by
  simp [Auths.Generated.attenuationAccepts, delegationProjection, broken]

/-!
### Critical-extension preservation

`extensionsAttenuate` was a literal `true` until the model gained an
`extensions` field, so the eleven-dimension contract was proved over ten
dimensions and reported eleven — structurally the same defect as the old
`root_preserved: true`.  The theorems below pin the dimension to the semantic
relation and exhibit the input classes on which it is `false`, so a literal
cannot satisfy them.
-/

/-- The generated extension dimension reports exactly the semantic relation. -/
theorem extensions_dimension_is_exact {v : Vocabulary}
    (parent : ChainState v) (grant : Grant v) :
    (delegationProjection parent grant).extensionsAttenuate = true ↔
      extensionsLe (some grant.extensions) parent.scope.extensions := by
  simp [delegationProjection]

/--
Witness that the dimension is falsifiable, stated over all inputs: a grant that
alters a pinned critical-extension set drives it to `false`.
-/
theorem extensions_dimension_false_of_altered_set {v : Vocabulary}
    (parent : ChainState v) (grant : Grant v)
    (pinned : CriticalExtensions v)
    (pinnedBy : parent.scope.extensions = some pinned)
    (altered : grant.extensions ≠ pinned) :
    (delegationProjection parent grant).extensionsAttenuate = false := by
  simp [delegationProjection, extensionsLe, pinnedBy, altered]

/--
No other attenuation dimension can rescue a stripped critical extension:
acceptance is the conjunction, so the whole projection is rejected.
-/
theorem altered_extensions_deny_every_projection {v : Vocabulary}
    (parent : ChainState v) (grant : Grant v)
    (broken : ¬ extensionsLe (some grant.extensions) parent.scope.extensions) :
    Auths.Generated.attenuationAccepts
      (delegationProjection parent grant) = false := by
  simp [Auths.Generated.attenuationAccepts, delegationProjection, broken]

/-- Every accepted edge preserves a pinned critical-extension set exactly. -/
theorem delegate_preserves_pinned_extensions {v : Vocabulary}
    {parent child : ChainState v} {grantId : GrantId v} {grant : Grant v}
    (accepted : delegates parent grantId grant child)
    (pinned : CriticalExtensions v)
    (pinnedBy : parent.scope.extensions = some pinned) :
    child.scope.extensions = some pinned := by
  rcases accepted with ⟨_, ⟨checks, rfl⟩⟩
  obtain ⟨_, _, _, _, _, _, _, _, preserved⟩ := checks.2.2
  rw [pinnedBy] at preserved
  simp only [extensionsLe] at preserved
  simp [acceptedNextState, acceptedScope, preserved]

/--
Once a chain has pinned a critical-extension set, every reachable state carries
that same set.  This is the inductive statement the single-edge theorem does
not carry, and it is what makes "a delegate cannot strip a critical extension"
a claim about whole chains rather than about one hop.
-/
theorem chain_preserves_pinned_extensions {v : Vocabulary}
    {start : ChainState v} {rest : List (ChainState v)}
    (chain : DelegationChain start rest)
    (pinned : CriticalExtensions v)
    (pinnedBy : start.scope.extensions = some pinned) :
    ∀ state ∈ rest, state.scope.extensions = some pinned := by
  induction chain with
  | nil => simp
  | cons parent child grantId grant rest edge tail inductionHypothesis =>
      intro state member
      have childPinned : child.scope.extensions = some pinned :=
        delegate_preserves_pinned_extensions edge pinned pinnedBy
      rcases List.mem_cons.1 member with head | inTail
      · rw [head]
        exact childPinned
      · exact inductionHypothesis childPinned state inTail

theorem delegate_updates_subject_and_parent {v : Vocabulary}
    {parent child : ChainState v} {grantId : GrantId v} {grant : Grant v}
    (accepted : delegates parent grantId grant child) :
    child.subject = grant.subject ∧ child.lastGrant = some grantId := by
  rcases accepted with ⟨_, ⟨_, rfl⟩⟩
  exact ⟨rfl, rfl⟩

theorem delegate_strict_depth {v : Vocabulary}
    {parent child : ChainState v} {grantId : GrantId v} {grant : Grant v}
    (accepted : delegates parent grantId grant child) :
    child.remainingDepth < parent.remainingDepth := by
  rcases accepted with ⟨_, ⟨checks, rfl⟩⟩
  exact checks.2.1

theorem delegate_never_widens {v : Vocabulary}
    {parent child : ChainState v} {grantId : GrantId v} {grant : Grant v}
    (accepted : delegates parent grantId grant child) :
    structuralScopeLe child.scope parent.scope :=
  delegate_implies_scope_le accepted

theorem remaining_depth_well_founded {v : Vocabulary} :
    WellFounded
      (fun child parent : ChainState v =>
        child.remainingDepth < parent.remainingDepth) :=
  (measure ChainState.remainingDepth).wf

theorem finite_delegation_chain {v : Vocabulary}
    {start : ChainState v} {rest : List (ChainState v)}
    (chain : DelegationChain start rest) :
    rest.length ≤ start.remainingDepth := by
  induction chain with
  | nil => simp
  | cons parent child grantId grant rest edge tail inductionHypothesis =>
      simp only [List.length_cons]
      have depth := delegate_strict_depth edge
      omega

theorem chain_transitive_attenuation {v : Vocabulary}
    {root middle terminal : ChainState v}
    {firstId secondId : GrantId v} {firstGrant secondGrant : Grant v}
    (first : delegates root firstId firstGrant middle)
    (second : delegates middle secondId secondGrant terminal) :
    structuralScopeLe terminal.scope root.scope :=
  structural_scope_le_trans
    (delegate_implies_scope_le second)
    (delegate_implies_scope_le first)

theorem authorized_action_covered {v : Vocabulary}
    {parent child : ChainState v} {grantId : GrantId v} {grant : Grant v}
    {action : Action v}
    (accepted : delegates parent grantId grant child)
    (authorized : actionCovers child.scope action) :
    actionCovers parent.scope action :=
  action_coverage_downward_closed (delegate_implies_scope_le accepted) authorized

/--
The generated conjunction accepts exactly the trust-root dimension together
with every scope and depth dimension.

The `rootPreserved` conjunct is not redundant: before the trust root became a
computed dimension this theorem read `↔ scopeDepthChecks parent grant`, which
is precisely the vacuity — the eleven-dimension contract was proved equivalent
to ten dimensions.

`scopeDepthChecks` now also carries `extensionsLe`.  While `extensionsAttenuate`
was a literal `true` this equivalence held with `grantScopeChecks` silent about
critical extensions, so the same vacuity was present in the eleventh dimension
and invisible here.
-/
theorem rich_projection_accepts_iff_root_and_scope_depth_checks {v : Vocabulary}
    (parent : ChainState v) (grant : Grant v) :
    Auths.Generated.attenuationAccepts
      (delegationProjection parent grant) = true ↔
      rootPreserved parent grant ∧ scopeDepthChecks parent grant := by
  simp [Auths.Generated.attenuationAccepts, delegationProjection,
    scopeDepthChecks, grantScopeChecks]
  tauto

theorem apply_grant_success_iff_linked_and_projection {v : Vocabulary}
    (parent : ChainState v) (grantId : GrantId v) (grant : Grant v)
    (child : ChainState v) :
    evaluateGrant parent grantId grant = .accepted child ↔
      linked parent grant ∧
      Auths.Generated.attenuationAccepts
        (delegationProjection parent grant) = true ∧
      ∃ checks : scopeDepthChecks parent grant,
        child = acceptedNextState parent grantId grant checks := by
  rw [rich_projection_accepts_iff_root_and_scope_depth_checks]
  simp only [evaluateGrant]
  split_ifs with linkage checks <;> simp_all [linked, eq_comm]

theorem apply_grant_success_iff_delegates {v : Vocabulary}
    (parent : ChainState v) (grantId : GrantId v) (grant : Grant v)
    (child : ChainState v) :
    evaluateGrant parent grantId grant = .accepted child ↔
      delegates parent grantId grant child := by
  rw [apply_grant_success_iff_linked_and_projection,
    rich_projection_accepts_iff_root_and_scope_depth_checks]
  simp [delegates, linked]
  tauto

theorem apply_grant_success_unique {v : Vocabulary}
    {parent : ChainState v} {grantId : GrantId v} {grant : Grant v}
    {left right : ChainState v}
    (leftAccepted : evaluateGrant parent grantId grant = .accepted left)
    (rightAccepted : evaluateGrant parent grantId grant = .accepted right) :
    left = right := by
  rw [apply_grant_success_iff_delegates] at leftAccepted rightAccepted
  rcases leftAccepted with ⟨_, ⟨leftChecks, leftEquality⟩⟩
  rcases rightAccepted with ⟨_, ⟨rightChecks, rightEquality⟩⟩
  exact leftEquality.trans (by
    have : acceptedNextState parent grantId grant leftChecks =
        acceptedNextState parent grantId grant rightChecks := by
      congr
    exact this.trans rightEquality.symm)

theorem authority_delegate_diagnostic_sound_complete {v : Vocabulary}
    (parent : ChainState v) (grantId : GrantId v) (grant : Grant v) :
    (∃ child, evaluateGrant parent grantId grant = .accepted child) ↔
      linked parent grant ∧ scopeDepthChecks parent grant := by
  constructor
  · rintro ⟨child, accepted⟩
    rw [apply_grant_success_iff_delegates] at accepted
    exact ⟨accepted.1, accepted.2.choose⟩
  · rintro ⟨linkage, checks⟩
    exact ⟨acceptedNextState parent grantId grant checks, by
      rw [apply_grant_success_iff_delegates]
      exact ⟨linkage, ⟨checks, rfl⟩⟩⟩

theorem authority_delegate_first_failure {v : Vocabulary}
    (parent : ChainState v) (grantId : GrantId v) (grant : Grant v) :
    (evaluateGrant parent grantId grant =
        .denied .brokenGrantChain ↔ ¬ linked parent grant) ∧
    (evaluateGrant parent grantId grant =
        .denied .delegationExpanded ↔
          linked parent grant ∧ ¬ scopeDepthChecks parent grant) := by
  simp only [evaluateGrant]
  split_ifs with linkage checks <;> simp_all

theorem author_planning_diagnostic_sound_complete {v : Vocabulary}
    (parent child : AuthorityScope v) (parentDepth childDepth : Nat) :
    evaluateAuthorScope parent child parentDepth childDepth = .accepted ↔
      structuralScopeLe child parent ∧
      0 < parentDepth ∧ childDepth < parentDepth := by
  simp only [evaluateAuthorScope]
  split_ifs <;> simp_all [structuralScopeLe]

theorem coverage_decision_ok_iff_covers {v : Vocabulary}
    (authority : ChainState v) (action : Action v) :
    evaluateCoverage authority action = .authorized ↔
      terminalCovers authority action := by
  simp only [evaluateCoverage]
  split_ifs <;> simp_all [terminalCovers, actionCovers]

theorem coverage_diagnostic_sound_complete {v : Vocabulary}
    (authority : ChainState v) (action : Action v) :
    (evaluateCoverage authority action = .authorized ↔
      terminalCovers authority action) ∧
    (∀ reason, evaluateCoverage authority action = .denied reason →
      ¬ terminalCovers authority action) := by
  constructor
  · exact coverage_decision_ok_iff_covers authority action
  · intro reason denied covered
    have authorized : evaluateCoverage authority action = .authorized :=
      (coverage_decision_ok_iff_covers authority action).2 covered
    rw [authorized] at denied
    contradiction

theorem translated_rich_spec_target
    {v : Vocabulary}
    (evaluateRustGrant :
      ChainState v → GrantId v → Grant v → DelegationDecision v)
    (evaluateRustCoverage :
      ChainState v → Action v → CoverageDecision)
    (grantIdentity :
      ∀ parent grantId grant,
        evaluateRustGrant parent grantId grant =
          evaluateGrant parent grantId grant)
    (coverageIdentity :
      ∀ authority action,
        evaluateRustCoverage authority action =
          evaluateCoverage authority action) :
    (∀ parent grantId grant child,
      evaluateRustGrant parent grantId grant = .accepted child ↔
        delegates parent grantId grant child) ∧
    (∀ authority action,
      evaluateRustCoverage authority action = .authorized ↔
        terminalCovers authority action) := by
  constructor
  · intro parent grantId grant child
    rw [grantIdentity, apply_grant_success_iff_delegates]
  · intro authority action
    rw [coverageIdentity, coverage_decision_ok_iff_covers]

end Auths.Rich
