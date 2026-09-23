import Auths.Product.Theorems
import Auths.Product.CeilingCount
import qualification.aeneas.generated.bounded_policy.Funs

open Aeneas Aeneas.Std Result

namespace Auths.Product.Refinement

def generatedConfigurationMatch :
    Auths.Product.ConfigurationMatch →
      auths_bounded_policy.kernel.ConfigurationMatchCode
  | .matches => .Match
  | .semanticMismatch => .SemanticMismatch
  | .canonicalizationMismatch => .CanonicalizationMismatch
  | .digestMismatch => .DigestMismatch
  | .implementationMismatch => .ImplementationMismatch

theorem translated_configuration_refines_projection
    (semanticEqual canonicalizationEqual digestEqual
      implementationEqualOrUnpinned : Bool) :
    auths_bounded_policy.kernel.configuration_match_code
      semanticEqual canonicalizationEqual digestEqual
      implementationEqualOrUnpinned =
        ok (generatedConfigurationMatch
          (projectedConfigurationMatch
            semanticEqual canonicalizationEqual digestEqual
            implementationEqualOrUnpinned)) := by
  cases semanticEqual <;>
    cases canonicalizationEqual <;>
    cases digestEqual <;>
    cases implementationEqualOrUnpinned <;>
    rfl

theorem translated_checked_add_refines_nat
    (left right : U64) :
    match auths_bounded_policy.kernel.checked_add_u64 left right with
    | ok (some result) =>
        left.val + right.val ≤ U64.max ∧
          result.val = left.val + right.val
    | ok none => U64.max < left.val + right.val
    | fail _ => False
    | div => False := by
  simp only [auths_bounded_policy.kernel.checked_add_u64]
  have specification := U64.checked_add_bv_spec left right
  cases equation : U64.checked_add left right <;>
    simp_all

theorem translated_checked_sub_refines_nat
    (left right : U64) :
    match auths_bounded_policy.kernel.checked_sub_u64 left right with
    | ok (some result) =>
        right.val ≤ left.val ∧ result.val = left.val - right.val
    | ok none => left.val < right.val
    | fail _ => False
    | div => False := by
  simp only [auths_bounded_policy.kernel.checked_sub_u64]
  have specification := U64.checked_sub_bv_spec left right
  cases equation : U64.checked_sub left right <;>
    simp_all

theorem translated_checked_mul_refines_nat
    (left right : U64) :
    match auths_bounded_policy.kernel.checked_mul_u64 left right with
    | ok (some result) =>
        left.val * right.val ≤ U64.max ∧
          result.val = left.val * right.val
    | ok none => U64.max < left.val * right.val
    | fail _ => False
    | div => False := by
  simp only [auths_bounded_policy.kernel.checked_mul_u64]
  have specification := U64.checked_mul_bv_spec left right
  cases equation : U64.checked_mul left right <;>
    simp_all

theorem translated_checked_div_rejects_zero (value : U64) :
    auths_bounded_policy.kernel.checked_div_u64 value (U64.ofNat 0) =
      ok none := by
  simp only [auths_bounded_policy.kernel.checked_div_u64]
  have specification := U64.checked_div_bv_spec value (U64.ofNat 0)
  cases equation : U64.checked_div value (U64.ofNat 0) with
  | none => rfl
  | some result => simp [equation] at specification

def generatedCeilingCountCode :
    Auths.Product.CeilingCount.Code → auths_bounded_policy.kernel.CeilingCountCode
  | .eligible => .Eligible
  | .aboveCeiling => .AboveCeiling
  | .windowExhausted => .WindowExhausted

/-- The translated evaluation leaf computes exactly the model's decision. -/
theorem translated_ceiling_count_refines_model
    (value ceiling count maxCount : U64) :
    auths_bounded_policy.kernel.ceiling_count_code value ceiling count maxCount =
      ok (generatedCeilingCountCode
        (Auths.Product.CeilingCount.codeOf value.val ceiling.val count.val maxCount.val)) := by
  unfold auths_bounded_policy.kernel.ceiling_count_code Auths.Product.CeilingCount.codeOf
  by_cases above : value.val > ceiling.val
  · have above' : value > ceiling := by scalar_tac
    simp [above, above', generatedCeilingCountCode]
  · have notAbove : ¬ value > ceiling := by scalar_tac
    by_cases exhausted : count.val ≥ maxCount.val
    · have exhausted' : count >= maxCount := by scalar_tac
      simp [above, notAbove, exhausted, exhausted', generatedCeilingCountCode]
    · have notExhausted : ¬ count >= maxCount := by scalar_tac
      simp [above, notAbove, exhausted, notExhausted, generatedCeilingCountCode]

/-- The translated tightening leaf computes exactly the model's decider. -/
theorem translated_ceiling_count_tightens_refines_model
    (childCeiling childMax childWindow parentCeiling parentMax parentWindow : U64) :
    auths_bounded_policy.kernel.ceiling_count_tightens
        childCeiling childMax childWindow parentCeiling parentMax parentWindow =
      ok (Auths.Product.CeilingCount.numericTightens
        childCeiling.val childMax.val childWindow.val
        parentCeiling.val parentMax.val parentWindow.val) := by
  unfold auths_bounded_policy.kernel.ceiling_count_tightens
    Auths.Product.CeilingCount.numericTightens
  by_cases windows : childWindow.val = parentWindow.val
  · have windows' : childWindow = parentWindow := by scalar_tac
    by_cases above : childCeiling.val > parentCeiling.val
    · have above' : childCeiling > parentCeiling := by scalar_tac
      simp [windows, windows', above, above']
    · have notAbove : ¬ childCeiling > parentCeiling := by scalar_tac
      simp [windows, windows', above, notAbove]
  · have windows' : childWindow ≠ parentWindow := by
      intro equal
      exact windows (by rw [equal])
    simp [windows, windows']

end Auths.Product.Refinement
