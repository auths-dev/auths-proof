import Auths.Verifier.StatusAllViews
import Auths.Verifier.StatusExamples
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
namespace Auths.StatusSelection

theorem ordered_of_pairwise (values : List String)
    (ordered : values.Pairwise (fun left right => (compare left right).isLE)) : Search.Ordered values := by
  intro i j left right before atLeft atRight
  obtain ⟨leftBound, leftValue⟩ := List.getElem?_eq_some_iff.mp atLeft
  obtain ⟨rightBound, rightValue⟩ := List.getElem?_eq_some_iff.mp atRight
  subst left right
  by_cases same : i = j
  · subst j; simp
  · exact List.pairwise_iff_getElem.mp ordered i j leftBound rightBound (by omega)

namespace AnchorExamples

def anchors : AuthsStatusSelection.auths_model.StatusScopeAnchors :=
  ⟨["anchor:a", "anchor:c"], by scalar_tac⟩

theorem anchors_ordered : Search.Ordered anchors.val :=
  ordered_of_pairwise _ (by decide)

theorem first_listed_anchor :
    AuthsStatusSelection.auths_model.StatusScopeAnchors.contains anchors "anchor:a" = ok true := by
  simpa [anchors] using Search.scope_contains anchors "anchor:a" anchors_ordered

theorem last_listed_anchor :
    AuthsStatusSelection.auths_model.StatusScopeAnchors.contains anchors "anchor:c" = ok true := by
  simpa [anchors] using Search.scope_contains anchors "anchor:c" anchors_ordered

theorem unlisted_anchor_refused :
    AuthsStatusSelection.auths_model.StatusScopeAnchors.contains anchors "anchor:b" = ok false := by
  simpa [anchors] using Search.scope_contains anchors "anchor:b" anchors_ordered

def ownSnapshot : AuthsStatusSelection.auths_model.PrincipalStatusSnapshot :=
  let snapshot := Examples.snapshot [Examples.principalStatement .Active 2#u64 40#u64] (by scalar_tac)
  {snapshot with trust := ⟨[{Examples.rule with scope := .OwnAnchor}], by scalar_tac⟩}

def anchor (base : AuthsStatusSelection.auths_model.TrustAnchor) (principal : String) : AuthsStatusSelection.auths_model.TrustAnchor :=
  {base with id := "anchor:a", principal := principal}

theorem own_ordered : rulesOrdered ownSnapshot.trust.val := by
  intro rule member
  simp only [ownSnapshot, List.mem_singleton] at member
  subst rule
  trivial

theorem own_anchor_active (base : AuthsStatusSelection.auths_model.TrustAnchor) :
    AuthsStatusSelection.ExactStatusMethod.Insts.Auths_portsStatusMethod.principal
      Examples.implementation Examples.required ownSnapshot "raw:actor" (.Anchor (anchor base "raw:issuer")) 50#u64
      ⦃ actual => ∃ evaluation, actual = .Ok evaluation ∧ evaluationView evaluation = ⟨.active, 60⟩ ⦄ := by
  have result := principal_method_all_views Examples.implementation Examples.required ownSnapshot "raw:actor"
    (.Anchor (anchor base "raw:issuer")) 50#u64 own_ordered
  simpa [Examples.implementation, Examples.required, ownSnapshot, Examples.snapshot, Examples.rule,
    Examples.principalStatement, ruleView, principalView, principalActive, policyView, scopeView, viewView,
    anchor, Model.evaluate, Model.visible, Model.scopeCovers, Model.sequenceFloor, Model.fresh, Model.deadline,
    Model.wordMaximum] using result

theorem other_anchor_hidden (base : AuthsStatusSelection.auths_model.TrustAnchor) :
    AuthsStatusSelection.ExactStatusMethod.Insts.Auths_portsStatusMethod.principal
      Examples.implementation Examples.required ownSnapshot "raw:actor" (.Anchor (anchor base "raw:other")) 50#u64
      ⦃ actual => ∃ evaluation, actual = .Ok evaluation ∧ evaluationView evaluation = ⟨.missing, 100⟩ ⦄ := by
  have result := principal_method_all_views Examples.implementation Examples.required ownSnapshot "raw:actor"
    (.Anchor (anchor base "raw:other")) 50#u64 own_ordered
  simpa [Examples.implementation, Examples.required, ownSnapshot, Examples.snapshot, Examples.rule,
    Examples.principalStatement, ruleView, principalView, principalActive, policyView, scopeView, viewView,
    anchor, Model.evaluate, Model.visible, Model.scopeCovers, Model.sequenceFloor, Model.fresh, Model.deadline,
    Model.wordMaximum] using result

end AnchorExamples
end Auths.StatusSelection
