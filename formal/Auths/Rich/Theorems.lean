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
    simp_all [actionConstraintLe]
  all_goals first
    | exact hbc hab
    | exact Finset.Subset.trans hab hbc

theorem action_constraint_antisymm {v : Vocabulary}
    {a b : ActionConstraint v}
    (hab : actionConstraintLe a b) (hba : actionConstraintLe b a) :
    a = b := by
  cases a <;> cases b <;> simp_all [actionConstraintLe]
  exact Finset.Subset.antisymm hab hba

theorem action_constraint_allows_monotone {v : Vocabulary}
    {child parent : ActionConstraint v} {digest : Digest v}
    (order : actionConstraintLe child parent)
    (allowed : actionConstraintAllows child digest) :
    actionConstraintAllows parent digest := by
  cases child <;> cases parent <;>
    simp_all [actionConstraintLe, actionConstraintAllows]
  exact order allowed

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
  cases requested with
  | none => simp [budgetCovers]
  | some requested =>
      cases parent with
      | none => simp [budgetCovers]
      | some parent =>
          cases child with
          | none => simp [budgetLe] at order
          | some child =>
              simp only [budgetLe] at order
              simp only [budgetCovers] at covered ⊢
              exact ⟨covered.1.trans order.1, covered.2.trans order.2⟩

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
    action_constraint_refl, budget_refl, status_refl]

theorem structural_scope_le_trans {v : Vocabulary}
    {a b c : AuthorityScope v}
    (hab : structuralScopeLe a b) (hbc : structuralScopeLe b c) :
    structuralScopeLe a c := by
  rcases hab with ⟨profileAB, permissionAB, validityAB, audienceAB,
    actionAB, budgetAB, statusAB, assuranceAB⟩
  rcases hbc with ⟨profileBC, permissionBC, validityBC, audienceBC,
    actionBC, budgetBC, statusBC, assuranceBC⟩
  exact ⟨
    profile_trans profileAB profileBC,
    Finset.Subset.trans permissionAB permissionBC,
    window_contained_trans validityAB validityBC,
    Finset.Subset.trans audienceAB audienceBC,
    action_constraint_trans actionAB actionBC,
    budget_trans budgetAB budgetBC,
    status_trans statusAB statusBC,
    assuranceAB.trans assuranceBC
  ⟩

theorem scope_le_canonical_antisymmetry {v : Vocabulary}
    {a b : AuthorityScope v}
    (hab : structuralScopeLe a b) (hba : structuralScopeLe b a) :
    a = b := by
  rcases hab with ⟨profileAB, permissionAB, validityAB, audienceAB,
    actionAB, budgetAB, statusAB, assuranceAB⟩
  rcases hba with ⟨profileBA, permissionBA, validityBA, audienceBA,
    actionBA, budgetBA, statusBA, assuranceBA⟩
  have profileEquality := profile_antisymm profileAB profileBA
  have permissionEquality := Finset.Subset.antisymm permissionAB permissionBA
  have validityEquality := window_contained_antisymm validityAB validityBA
  have audienceEquality := Finset.Subset.antisymm audienceAB audienceBA
  have actionEquality := action_constraint_antisymm actionAB actionBA
  have budgetEquality := budget_antisymm budgetAB budgetBA
  have statusEquality := status_antisymm statusAB statusBA
  rcases a with ⟨aProfile, aPermissions, aValidity, aAudiences, aAction,
    aBudget, aStatus, aAssurance⟩
  rcases b with ⟨bProfile, bPermissions, bValidity, bAudiences, bAction,
    bBudget, bStatus, bAssurance⟩
  simp_all

theorem action_coverage_downward_closed {v : Vocabulary}
    {child parent : AuthorityScope v} {action : Action v}
    (order : structuralScopeLe child parent)
    (covered : actionCovers child action) :
    actionCovers parent action := by
  rcases order with ⟨profileOrder, permissionOrder, validityOrder,
    audienceOrder, actionOrder, budgetOrder, statusOrder, assuranceOrder⟩
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
  rcases order with ⟨_, _, _, _, _, _, statusOrder, assuranceOrder⟩
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
    audienceCheck, actionCheck, budgetCheck, statusCheck, assuranceCheck⟩
  constructor
  · constructor
    · rfl
    · cases selected : parent.profileScope.selected with
      | none => trivial
      | some selectedProfile =>
          simpa [acceptedScope, profileAllows, selected] using profileCheck
  · exact ⟨permissionCheck, validityCheck, audienceCheck, actionCheck,
      budgetCheck, statusCheck, assuranceCheck⟩

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

theorem rich_projection_accepts_iff_scope_depth_checks {v : Vocabulary}
    (parent : ChainState v) (grant : Grant v) :
    Auths.Generated.attenuationAccepts
      (delegationProjection parent grant) = true ↔
      scopeDepthChecks parent grant := by
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
  rw [rich_projection_accepts_iff_scope_depth_checks]
  simp only [evaluateGrant]
  split_ifs with linkage checks <;> simp_all [eq_comm]

theorem apply_grant_success_iff_delegates {v : Vocabulary}
    (parent : ChainState v) (grantId : GrantId v) (grant : Grant v)
    (child : ChainState v) :
    evaluateGrant parent grantId grant = .accepted child ↔
      delegates parent grantId grant child := by
  rw [apply_grant_success_iff_linked_and_projection,
    rich_projection_accepts_iff_scope_depth_checks]
  simp [delegates]

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
