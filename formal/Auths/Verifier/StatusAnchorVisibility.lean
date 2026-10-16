import Auths.Verifier.StatusSearchContains
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsStatusSelection
namespace Auths.StatusSelection

def scopeOrdered : AuthsStatusSelection.auths_model.StatusScope → Prop
  | .Anchors values => Search.Ordered values.val
  | _ => True

def rulesOrdered (rules : List AuthsStatusSelection.auths_model.StatusTrustRule) : Prop :=
  ∀ rule ∈ rules, scopeOrdered rule.scope

theorem scope_covers (scope : AuthsStatusSelection.auths_model.StatusScope)
    (issuer : String) (anchor : AuthsStatusSelection.auths_model.TrustAnchor)
    (ordered : scopeOrdered scope) :
    AuthsStatusSelection.auths_model.StatusScope.covers scope issuer anchor =
      ok (Model.scopeCovers (scopeView scope) issuer (.anchor anchor.id anchor.principal)) := by
  cases scope <;>
    simp only [AuthsStatusSelection.auths_model.StatusScope.covers,
      AuthsStatusSelection.auths_model.TrustAnchor.impl.principal,
      AuthsStatusSelection.auths_model.TrustAnchor.impl.id, principal_eq, bind_tc_ok,
      scopeView, Model.scopeCovers]
  exact Search.scope_contains _ _ ordered

theorem anchor_visibility_stopped (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule)
    (issuer : String) (anchor : AuthsStatusSelection.auths_model.TrustAnchor) (position : Std.Usize) :
    AuthsStatusSelection.auths_model.status_issuer_in_scope_loop rules issuer anchor false position = ok false := by
  rw [AuthsStatusSelection.auths_model.status_issuer_in_scope_loop.eq_def]
  simp

theorem anchor_visibility_loop_refines (remainingRules : List AuthsStatusSelection.auths_model.StatusTrustRule)
    (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule) (issuer : String)
    (anchor : AuthsStatusSelection.auths_model.TrustAnchor) (position : Std.Usize)
    (remaining : rules.val.drop position.val = remainingRules) (ordered : rulesOrdered remainingRules) :
    AuthsStatusSelection.auths_model.status_issuer_in_scope_loop rules issuer anchor true position ⦃ actual =>
      actual = Model.visible (remainingRules.map ruleView) issuer (.anchor anchor.id anchor.principal) ⦄ := by
  induction remainingRules generalizing position with
  | nil =>
    have finished : ¬ position < rules.len := by
      have size := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at size
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [AuthsStatusSelection.auths_model.status_issuer_in_scope_loop.eq_def]
    simp [finished, Model.visible]
  | cons head tail ih =>
    have headOrdered : scopeOrdered head.scope := ordered head (by simp)
    have tailOrdered : rulesOrdered tail := by
      intro rule member; exact ordered rule (by simp [member])
    obtain ⟨guard, atHead⟩ := indexed_head rules position head tail remaining
    obtain ⟨next, step, nextValue, nextRemaining⟩ := indexed_next rules position head tail remaining
    rw [AuthsStatusSelection.auths_model.status_issuer_in_scope_loop.eq_def]
    simp only [guard, ↓reduceIte, atHead, bind_tc_ok,
      AuthsStatusSelection.auths_model.StatusTrustRule.impl.issuer, principal_eq]
    cases matched : (head.issuer == issuer) with
    | false =>
      simp only [Bool.false_eq_true, ↓reduceIte, step, bind_tc_ok]
      simpa only [List.map_cons, Model.visible_cons, ruleView, matched, Bool.false_eq_true, ↓reduceIte] using
        ih next nextRemaining tailOrdered
    | true =>
      simp only [↓reduceIte, AuthsStatusSelection.auths_model.StatusTrustRule.impl.scope,
        scope_covers _ _ _ headOrdered, bind_tc_ok, step]
      cases covered : Model.scopeCovers (scopeView head.scope) issuer (.anchor anchor.id anchor.principal) with
      | false =>
        simp [anchor_visibility_stopped, Model.visible_cons, ruleView, matched, covered]
      | true =>
        simpa [Model.visible_cons, ruleView, matched, covered] using ih next nextRemaining tailOrdered

theorem visibility_refines (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule)
    (issuer : String) (view : AuthsStatusSelection.auths_model.StatusView) (ordered : rulesOrdered rules.val) :
    AuthsStatusSelection.auths_model.status_issuer_visible rules issuer view ⦃ actual =>
      actual = Model.visible (rules.val.map ruleView) issuer (viewView view) ⦄ := by
  cases viewEquation : view with
  | Approver => exact approver_visibility_refines rules issuer
  | Anchor anchor =>
    simpa [AuthsStatusSelection.auths_model.status_issuer_visible,
      AuthsStatusSelection.auths_model.status_issuer_in_scope, viewView] using
      anchor_visibility_loop_refines rules.val rules issuer anchor 0#usize (by simp) ordered

theorem visibility_exact (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule)
    (issuer : String) (view : AuthsStatusSelection.auths_model.StatusView) (ordered : rulesOrdered rules.val) :
    AuthsStatusSelection.auths_model.status_issuer_visible rules issuer view =
      ok (Model.visible (rules.val.map ruleView) issuer (viewView view)) := by
  obtain ⟨actual, equation, meaning⟩ := spec_imp_exists (visibility_refines rules issuer view ordered)
  exact equation.trans (congrArg Result.ok meaning)

end Auths.StatusSelection
