import Auths.Composition.Model
import qualification.aeneas.generated.composition.Funs

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_composition
open Auths.Composition.Model
namespace Auths.Composition.Refinement
set_option maxHeartbeats 2000000

def view (state : auths_composition.summary.Summary) : Summary :=
  ⟨state.authorized.val, state.indeterminate.val, state.denial, state.requirement⟩

@[step] theorem denial_order_exact (value : auths_composition.auths_model.DenialReason) :
    auths_composition.auths_model.DenialReason.code_order value ⦃ result => result.val = denialRank value ⦄ := by
  cases h : value <;> simp [auths_composition.auths_model.DenialReason.code_order, denialRank, spec_ok]

@[step] theorem denial_precedes_exact (left right : auths_composition.auths_model.DenialReason) :
    auths_composition.auths_model.DenialReason.code_precedes left right
      ⦃ result => result = decide (denialRank left < denialRank right) ⦄ := by
  unfold auths_composition.auths_model.DenialReason.code_precedes
  step as ⟨l, hl⟩
  step as ⟨r, hr⟩
  simp [UScalar.lt_equiv, hl, hr]

@[step] theorem requirement_order_exact (value : auths_composition.auths_model.Requirement) :
    auths_composition.auths_model.Requirement.code_order value ⦃ result => result.val = requirementRank value ⦄ := by
  cases h : value <;> simp [auths_composition.auths_model.Requirement.code_order, requirementRank, spec_ok]

@[step] theorem requirement_precedes_exact (left right : auths_composition.auths_model.Requirement) :
    auths_composition.auths_model.Requirement.code_precedes left right
      ⦃ result => result = decide (requirementRank left < requirementRank right) ⦄ := by
  unfold auths_composition.auths_model.Requirement.code_precedes
  step as ⟨l, hl⟩
  step as ⟨r, hr⟩
  simp [UScalar.lt_equiv, hl, hr]

@[step] theorem push_exact (state : auths_composition.summary.Summary) (outcome : BranchOutcome)
    (authorizedFits : state.authorized.val + 1 ≤ Usize.max)
    (indeterminateFits : state.indeterminate.val + 1 ≤ Usize.max) :
    auths_composition.summary.push state outcome
      ⦃ result => view result = record (view state) outcome ⦄ := by
  cases h : outcome with
  | Authorized =>
    unfold auths_composition.summary.push
    step as ⟨next, nextEq⟩
    simp [view, record, nextEq]
  | Denied reason | StructurallyInvalid reason =>
    unfold auths_composition.summary.push
    cases h : state.denial with
    | none => simp [h, spec_ok, view, record, retainMinimum]
    | some previous =>
      step as ⟨before, beforeEq⟩
      simp only [beforeEq]
      split <;> simp_all [spec_ok, view, record, retainMinimum]
  | Indeterminate requirement =>
    unfold auths_composition.summary.push
    step as ⟨next, nextEq⟩
    cases h : state.requirement with
    | none => simp [h, spec_ok, view, record, retainMinimum, nextEq]
    | some previous =>
      step as ⟨before, beforeEq⟩
      simp only [beforeEq]
      split <;> simp_all [spec_ok, view, record, retainMinimum]

theorem all_exact (state : auths_composition.summary.Summary) :
    auths_composition.summary.all state = ok (allOutcome (view state)) := by
  cases hd : state.denial <;> cases hi : state.requirement <;>
    simp [auths_composition.summary.all, allOutcome, view, hd, hi]

theorem saturating_add_exact (left right : Std.Usize) :
    (core.num.Usize.saturating_add left right).val = min Usize.max (left.val + right.val) := by
  simp only [core.num.Usize.saturating_add, UScalar.saturating_add, UScalar.val,
    BitVec.toNat_ofNat, UScalar.max_USize_eq]
  apply Nat.mod_eq_of_lt
  have maximum : Usize.max < 2 ^ UScalarTy.Usize.numBits := by
    simp only [Usize.max, Usize.numBits]
    exact Nat.sub_lt (Nat.two_pow_pos _) (by decide)
  exact Nat.lt_of_le_of_lt (Nat.min_le_left _ _) maximum

theorem threshold_exact (state : auths_composition.summary.Summary) (required : Std.U16) :
    auths_composition.summary.threshold state required =
      ok (thresholdOutcome required.val (view state)) := by
  have requiredBound : required.val ≤ Usize.max := by scalar_tac
  unfold auths_composition.summary.threshold evaluate_threshold_counts
    auths_composition.auths_algebra_kernel.generated.threshold_counts
  simp only [lift, bind_tc_ok, UScalar.le_equiv,
    core.convert.num.FromUsizeU16.from_val_eq, saturating_add_exact]
  by_cases authorized : required.val ≤ state.authorized.val
  · simp [authorized, thresholdOutcome, view]
  · by_cases possible : required.val ≤ state.authorized.val + state.indeterminate.val
    · have saturated : required.val ≤ min Usize.max
          (state.authorized.val + state.indeterminate.val) := Nat.le_min.mpr ⟨requiredBound, possible⟩
      cases h : state.requirement <;>
        simp [authorized, possible, saturated, thresholdOutcome, view, h]
    · have saturated : ¬ required.val ≤ min Usize.max
          (state.authorized.val + state.indeterminate.val) := by omega
      cases h : state.denial <;>
        simp [authorized, possible, saturated, thresholdOutcome, view, h]


theorem denial_precedes_lexical (left right : auths_composition.auths_model.DenialReason) :
    auths_composition.auths_model.DenialReason.code_precedes left right =
      ok (decide (List.Lex (· < ·) (denialCode left) (denialCode right))) := by
  obtain ⟨result, evaluates, meaning⟩ := spec_imp_exists (denial_precedes_exact left right)
  simpa only [meaning, denial_rank_lexical] using evaluates

theorem requirement_precedes_lexical (left right : auths_composition.auths_model.Requirement) :
    auths_composition.auths_model.Requirement.code_precedes left right =
      ok (decide (List.Lex (· < ·) (requirementCode left) (requirementCode right))) := by
  obtain ⟨result, evaluates, meaning⟩ := spec_imp_exists (requirement_precedes_exact left right)
  simpa only [meaning, requirement_rank_lexical] using evaluates

theorem threshold_authorized_exact (state : auths_composition.summary.Summary) (required : Std.U16) :
    auths_composition.summary.threshold state required = ok .Authorized ↔
      required.val ≤ state.authorized.val := by
  rw [threshold_exact]
  simpa only [Result.ok.injEq, view] using threshold_authorized_iff required.val (view state)

def sourceFold (state : auths_composition.summary.Summary) :
    List BranchOutcome → Result auths_composition.summary.Summary
  | [] => ok state
  | outcome :: remaining => do
      let next ← auths_composition.summary.push state outcome
      sourceFold next remaining

theorem source_fold_exact (state : auths_composition.summary.Summary) (outcomes : List BranchOutcome)
    (authorizedFits : state.authorized.val + outcomes.length ≤ Usize.max)
    (indeterminateFits : state.indeterminate.val + outcomes.length ≤ Usize.max) :
    sourceFold state outcomes
      ⦃ result => view result = outcomes.foldl record (view state) ⦄ := by
  induction outcomes generalizing state with
  | nil => simp [sourceFold]
  | cons outcome remaining ih =>
    simp only [sourceFold]
    have authorizedStep : state.authorized.val + 1 ≤ Usize.max := by
      simp only [List.length_cons] at authorizedFits
      omega
    have indeterminateStep : state.indeterminate.val + 1 ≤ Usize.max := by
      simp only [List.length_cons] at indeterminateFits
      omega
    step as ⟨next, nextEq⟩
    have authorizedNext : next.authorized.val + remaining.length ≤ Usize.max := by
      have counts := congrArg Summary.authorized nextEq
      cases h : outcome <;> simp_all [view, record] <;> omega
    have indeterminateNext : next.indeterminate.val + remaining.length ≤ Usize.max := by
      have counts := congrArg Summary.indeterminate nextEq
      cases h : outcome <;> simp_all [view, record] <;> omega
    have continuation := ih next authorizedNext indeterminateNext
    apply spec_mono continuation
    intro result meaning
    simpa only [List.foldl_cons, nextEq] using meaning

end Auths.Composition.Refinement
