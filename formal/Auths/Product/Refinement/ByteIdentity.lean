import qualification.aeneas.generated.gateway.Funs
import Auths.Product.RequestConstruction
import Mathlib.Tactic
open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
namespace Auths.Product.Refinement.ByteIdentity
set_option maxHeartbeats 4000000

/-- Exact byte identity, with no string normalization or case folding. -/
@[step] theorem field_name_equal_exact (left right : Slice Std.U8) :
    construct.field_name_equal left right ⦃ result => result = decide (left.val = right.val) ⦄ := by
  unfold construct.field_name_equal
  dsimp only
  by_cases lengths : left.val.length = right.val.length
  · have sameLen : left.len = right.len := by scalar_tac
    simp only [sameLen, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
    unfold construct.field_name_equal_loop
    apply loop.spec_decr_nat
      (measure := fun state => left.val.length - state.1.val)
      (inv := fun state => state.1.val ≤ left.val.length ∧
        (state.2 = true ↔ left.val.take state.1.val = right.val.take state.1.val))
    · rintro ⟨position, equal⟩ ⟨within, processed⟩
      unfold construct.field_name_equal_loop.body
      dsimp only
      split <;> rename_i remaining
      · split <;> rename_i running
        · have inside : position.val < left.val.length := by simpa using remaining
          have rightInside : position.val < right.val.length := by omega
          step as ⟨leftByte, leftAt⟩
          step as ⟨rightByte, rightAt⟩
          step as ⟨next, nextValue⟩
          refine ⟨by omega, ?_, by omega⟩
          have before := processed.mp running
          rw [nextValue, List.take_succ_eq_append_getElem inside,
            List.take_succ_eq_append_getElem rightInside]
          simp only [← leftAt, ← rightAt, before, List.append_cancel_left_eq,
            List.cons.injEq, and_true, decide_eq_true_eq]
        · simp only [spec_ok]
          have different : left.val ≠ right.val := by
            intro same
            have := processed.mpr (by rw [same])
            contradiction
          simp [different]
      · simp only [spec_ok]
        have atEnd : left.val.length ≤ position.val := by simpa using remaining
        have completed : left.val.take position.val = left.val := List.take_of_length_le atEnd
        have rightCompleted : right.val.take position.val = right.val := List.take_of_length_le (by omega)
        simp only [completed, rightCompleted] at processed
        exact Bool.eq_iff_iff.mpr (by simpa using processed)
    · exact ⟨by simp, by simp⟩
  · have nativeDifferent : left.len ≠ right.len := by
      intro same
      apply lengths
      simpa only [Slice.len_val, Slice.length] using congrArg UScalar.val same
    have different : left.val ≠ right.val := fun same => lengths (congrArg List.length same)
    simp [nativeDifferent, different]

@[step] theorem hex_lower_exact (nibble : Std.U8) (small : nibble.val < 16) :
    construct.hex_lower nibble ⦃ result => result.val = hexLower nibble.val ⦄ := by
  unfold construct.hex_lower hexLower
  by_cases low : nibble.val < 10
  · have lowScalar : nibble < 10#u8 := by scalar_tac
    simp only [lowScalar, if_true, low]
    step as ⟨result, resultEq⟩
    omega
  · have highScalar : ¬ nibble < 10#u8 := by scalar_tac
    simp only [highScalar, if_false, low]
    step as ⟨shifted, shiftedEq⟩
    step as ⟨result, resultEq⟩
    omega




end Auths.Product.Refinement.ByteIdentity
