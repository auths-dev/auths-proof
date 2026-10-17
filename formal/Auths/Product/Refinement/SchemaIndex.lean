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
  exact Auths.Product.Refinement.ByteIdentity.field_name_equal_exact left right

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
