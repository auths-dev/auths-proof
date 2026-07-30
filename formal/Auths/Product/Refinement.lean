import Auths.Product.Theorems
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

end Auths.Product.Refinement
