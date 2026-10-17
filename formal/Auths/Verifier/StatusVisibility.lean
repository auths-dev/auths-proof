import Auths.Verifier.StatusFloor
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsStatusSelection
namespace Auths.StatusSelection
set_option maxHeartbeats 2000000

theorem approver_visibility_stopped (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule)
    (issuer : String) (position : Std.Usize) :
    AuthsStatusSelection.auths_model.status_issuer_visible_loop rules issuer false position = ok false := by
  rw [AuthsStatusSelection.auths_model.status_issuer_visible_loop.eq_def]
  simp

theorem approver_visibility_loop_refines (remainingRules : List AuthsStatusSelection.auths_model.StatusTrustRule)
    (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule) (issuer : String) (position : Std.Usize)
    (remaining : rules.val.drop position.val = remainingRules) :
    AuthsStatusSelection.auths_model.status_issuer_visible_loop rules issuer true position ⦃ actual =>
      actual = Model.visible (remainingRules.map ruleView) issuer .approver ⦄ := by
  induction remainingRules generalizing position with
  | nil =>
    have finished : ¬ position < rules.len := by
      have size := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at size
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [AuthsStatusSelection.auths_model.status_issuer_visible_loop.eq_def]
    simp [finished, Model.visible]
  | cons head tail ih =>
    obtain ⟨guard, atHead⟩ := indexed_head rules position head tail remaining
    obtain ⟨next, step, nextValue, nextRemaining⟩ := indexed_next rules position head tail remaining
    rw [AuthsStatusSelection.auths_model.status_issuer_visible_loop.eq_def]
    simp only [guard, ↓reduceIte, atHead, bind_tc_ok,
      AuthsStatusSelection.auths_model.StatusTrustRule.impl.issuer, principal_eq]
    cases matched : (head.issuer == issuer) with
    | false =>
      have different : head.issuer ≠ issuer := by simpa using matched
      simp only [Bool.false_eq_true, ↓reduceIte, step, bind_tc_ok]
      simpa only [List.map_cons, Model.visible_cons, ruleView, matched, Bool.false_eq_true, ↓reduceIte] using ih next nextRemaining
    | true =>
      have same : head.issuer = issuer := by simpa using matched
      simp only [↓reduceIte, AuthsStatusSelection.auths_model.StatusTrustRule.impl.scope]
      cases scope : head.scope <;>
        simp only [bind_tc_ok, step]
      · simp [approver_visibility_stopped, Model.visible, ruleView, bne_eq, same, scope, scopeView, Model.scopeCovers]
      · simp [approver_visibility_stopped, Model.visible, ruleView, bne_eq, same, scope, scopeView, Model.scopeCovers]
      · simpa [Model.visible, ruleView, bne_eq, same, scope, scopeView, Model.scopeCovers] using ih next nextRemaining

theorem approver_visibility_refines (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule) (issuer : String) :
    AuthsStatusSelection.auths_model.status_issuer_visible rules issuer .Approver ⦃ actual =>
      actual = Model.visible (rules.val.map ruleView) issuer .approver ⦄ := by
  simpa [AuthsStatusSelection.auths_model.status_issuer_visible] using
    approver_visibility_loop_refines rules.val rules issuer 0#usize (by simp)

theorem approver_visibility_exact (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule) (issuer : String) :
    AuthsStatusSelection.auths_model.status_issuer_visible rules issuer .Approver =
      ok (Model.visible (rules.val.map ruleView) issuer .approver) := by
  obtain ⟨actual, equation, meaning⟩ := spec_imp_exists (approver_visibility_refines rules issuer)
  exact equation.trans (congrArg Result.ok meaning)

theorem unknown_issuer_visible (rules : List Model.Rule) (issuer : String) (view : Model.View)
    (unknown : ∀ rule ∈ rules, rule.issuer ≠ issuer) : Model.visible rules issuer view = true := by
  simp only [Model.visible, List.all_eq_true]
  intro rule member
  have different := unknown rule member
  simp [different]
end Auths.StatusSelection
