import Auths.Verifier.StatusLeaves
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsStatusSelection
namespace Auths.StatusSelection
set_option maxHeartbeats 2000000

theorem sequence_floor_already_found (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule)
    (method issuer : String) (value : Std.U64) (position : Std.Usize) :
    status_sequence_floor_loop rules method issuer (some value) position = ok (some value) := by
  rw [status_sequence_floor_loop.eq_def]
  simp [core.option.Option.is_none]

theorem sequence_floor_loop_refines (remainingRules : List AuthsStatusSelection.auths_model.StatusTrustRule)
    (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule) (method issuer : String) (position : Std.Usize)
    (remaining : rules.val.drop position.val = remainingRules) :
    status_sequence_floor_loop rules method issuer none position ⦃ actual =>
      actual.map (fun value => value.val) =
        Model.sequenceFloor (remainingRules.map ruleView) method issuer ⦄ := by
  induction remainingRules generalizing position with
  | nil =>
    have finished : ¬ position < rules.len := by
      have size := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at size
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [status_sequence_floor_loop.eq_def]
    simp [finished, Model.sequenceFloor]
  | cons head tail ih =>
    obtain ⟨guard, atHead⟩ := indexed_head rules position head tail remaining
    obtain ⟨next, step, nextValue, nextRemaining⟩ := indexed_next rules position head tail remaining
    rw [status_sequence_floor_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atHead, bind_tc_ok,
      AuthsStatusSelection.auths_model.StatusTrustRule.impl.method, method_eq]
    cases matchedMethod : (head.method == method) <;>
      cases matchedIssuer : (head.issuer == issuer) <;>
      simp only [matchedIssuer, Bool.false_eq_true, ↓reduceIte,
        AuthsStatusSelection.auths_model.StatusTrustRule.impl.issuer, principal_eq,
        AuthsStatusSelection.auths_model.StatusTrustRule.impl.sequence_floor, bind_tc_ok, step]
    all_goals
      first
      | simpa [Model.sequenceFloor, ruleView, matchedMethod, matchedIssuer] using ih next nextRemaining
      | simp [sequence_floor_already_found, Model.sequenceFloor, ruleView, matchedMethod, matchedIssuer]

theorem sequence_floor_refines (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule) (method issuer : String) :
    status_sequence_floor rules method issuer ⦃ actual =>
      actual.map (fun value => value.val) = Model.sequenceFloor (rules.val.map ruleView) method issuer ⦄ := by
  simpa [status_sequence_floor] using
    sequence_floor_loop_refines rules.val rules method issuer 0#usize (by simp)
def nativeFloor (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule) (method issuer : String) : Option Std.U64 :=
  (rules.val.find? (fun rule => rule.method == method && rule.issuer == issuer)).map (fun rule => rule.sequence_floor)

theorem native_floor_view (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule) (method issuer : String) :
    (nativeFloor rules method issuer).map (fun value => value.val) = Model.sequenceFloor (rules.val.map ruleView) method issuer := by
  simp [nativeFloor, Model.sequenceFloor, ruleView, Function.comp_def]

theorem sequence_floor_exact (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule) (method issuer : String) :
    status_sequence_floor rules method issuer = ok (nativeFloor rules method issuer) := by
  obtain ⟨actual, equation, meaning⟩ := spec_imp_exists (sequence_floor_refines rules method issuer)
  have same : actual = nativeFloor rules method issuer := by
    apply Option.map_injective (fun _ _ equality => UScalar.eq_of_val_eq equality)
    exact meaning.trans (native_floor_view rules method issuer).symm
  exact equation.trans (congrArg Result.ok same)

end Auths.StatusSelection
