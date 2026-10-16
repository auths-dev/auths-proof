import Auths.Product.SchemaIndex
import Auths.Product.Refinement.Gateway
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
namespace Auths.Product.SchemaIndex.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

/-- Exact byte identity, with no string normalization or case folding. -/
@[step] theorem field_name_equal_spec (left right : Slice Std.U8) :
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

def namesView (names : Slice (alloc.vec.Vec Std.U8)) : List SchemaIndex.Name :=
  names.val.map (fun fieldName => fieldName.val.map (·.val))

/-- Source first-match lookup returns exactly the readable schema position.
    The actual compiler uses it on its unique, ordered schema-fieldName snapshot. -/
@[step] theorem field_index_spec (names : Slice (alloc.vec.Vec Std.U8)) (wanted : Slice Std.U8) :
    construct.field_index names wanted ⦃ result =>
      result.map UScalar.val = SchemaIndex.position (namesView names) (wanted.val.map (·.val)) ⦄ := by
  unfold construct.field_index construct.field_index_loop
  apply loop.spec_decr_nat
    (measure := fun state => names.val.length - state.1.val)
    (inv := fun state => state.1.val ≤ names.val.length ∧
      match state.2 with
      | some position => SchemaIndex.position (namesView names) (wanted.val.map (·.val)) = some position.val
      | none => ∀ index, index < state.1.val →
          (namesView names)[index]? ≠ some (wanted.val.map (·.val)))
  · rintro ⟨position, found⟩ ⟨bound, processed⟩
    unfold construct.field_index_loop.body
    dsimp only
    split <;> rename_i within
    · cases found with
      | some index =>
        simp only [core.option.Option.is_none]
        exact processed.symm
      | none =>
        simp only [core.option.Option.is_none, Option.isNone, ↓reduceIte]
        have inside : position.val < names.val.length := by simpa using within
        step as ⟨fieldName, nameAt⟩
        step with field_name_equal_spec as ⟨equal, equalSpec⟩
        cases equal
        · simp only [Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
          step as ⟨next, nextValue⟩
          refine ⟨by omega, ?_, by omega⟩
          intro index before
          by_cases earlier : index < position.val
          · exact processed index earlier
          · have sameIndex : index = position.val := by omega
            subst index
            simp_all [namesView, List.getElem?_map]
            exact equalSpec ∘ Auths.Product.Refinement.Gateway.byteList_inj.mp
        · simp only [↓reduceIte, bind_tc_ok]
          step as ⟨next, nextValue⟩
          refine ⟨by omega, ?_, by omega⟩
          apply SchemaIndex.position_eq_first
          · simp_all [namesView, List.getElem?_map]
          · exact processed
    · simp only [spec_ok]
      cases found with
      | some index => simpa using processed.symm
      | none =>
        symm
        apply (SchemaIndex.absent_iff _ _).mpr
        intro member
        obtain ⟨index, atIndex⟩ := List.mem_iff_getElem?.mp member
        have inside : index < position.val := by
          have indexed : index < (namesView names).length := List.getElem?_eq_some_iff.mp atIndex |>.1
          simp only [namesView, List.length_map] at indexed
          have atEnd : names.val.length ≤ position.val := by simpa using within
          omega
        exact processed index inside atIndex
  · exact ⟨by simp, by simp⟩

end Auths.Product.SchemaIndex.Refinement
