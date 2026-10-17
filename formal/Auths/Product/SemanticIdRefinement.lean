import qualification.aeneas.generated.connections.Funs
import Auths.Product.SemanticId
open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_connections
namespace Auths.Product.SemanticId.Refinement
abbrev bytes (values : List Std.U8) : List Nat := values.map (·.val)
@[step] theorem semantic_head_exact (byte : Std.U8) :
    kernel.semantic_head_valid byte ⦃ actual => actual = decide (head byte.val) ⦄ := by
  unfold kernel.semantic_head_valid
  repeat' split
  all_goals simp_all only [spec_ok, head]
  all_goals apply Bool.eq_iff_iff.mpr
  all_goals simp only [decide_eq_true_eq, true_iff]
  all_goals scalar_tac

@[step] theorem semantic_tail_exact (byte : Std.U8) :
    kernel.semantic_tail_valid byte ⦃ actual => actual = decide (tail byte.val) ⦄ := by
  unfold kernel.semantic_tail_valid
  step with semantic_head_exact as ⟨allowed, allowedMeaning⟩
  repeat' split
  all_goals simp_all only [spec_ok, tail, UScalar.eq_equiv]
  all_goals apply Bool.eq_iff_iff.mpr
  all_goals simp only [decide_eq_true_eq, true_iff]
  all_goals simp_all

@[step] theorem semantic_valid_exact (value : Slice Std.U8) (maximum : Std.Usize) :
    kernel.semantic_id_valid value maximum ⦃ actual =>
      actual = decide (valid (bytes value.val) maximum.val) ⦄ := by
  unfold kernel.semantic_id_valid
  step as ⟨empty, emptyMeaning⟩
  cases empty
  · simp only [Bool.false_eq_true, ↓reduceIte]
    have nonempty : value.val ≠ [] := by simpa [Slice.length] using emptyMeaning.symm
    have firstInside : 0 < value.val.length := List.length_pos_iff.mpr nonempty
    split <;> rename_i exceeds
    · simp only [spec_ok]
      have tooLarge : maximum.val < value.val.length := by simpa using exceeds
      simp [valid, bytes, tooLarge.not_ge]
    · have fits : value.val.length ≤ maximum.val := by simpa using exceeds
      step as ⟨first, firstMeaning⟩
      have firstAt : (bytes value.val)[0]! = first.val := by
        rw [getElem!_pos (bytes value.val) 0 (by simpa using firstInside)]
        simp [bytes, ← firstMeaning]
      step with semantic_head_exact as ⟨allowed, allowedMeaning⟩
      cases allowed
      · simp only [Bool.false_eq_true, ↓reduceIte, spec_ok]
        have invalid : ¬ valid (bytes value.val) maximum.val := by
          intro accepted
          have permitted := accepted.2.2.1
          rw [firstAt] at permitted
          simp [permitted] at allowedMeaning
        simp [invalid]
      · simp only [↓reduceIte]
        have firstValid : head (bytes value.val)[0]! := by
          rw [firstAt]
          simpa using allowedMeaning.symm
        unfold kernel.semantic_id_valid_loop
        apply loop.spec_decr_nat
          (measure := fun index => value.val.length - index.val)
          (inv := fun index => index.val ≤ value.val.length ∧ ∀ byte ∈ value.val.take index.val, tail byte.val)
        · intro index processed
          unfold kernel.semantic_id_valid_loop.body
          dsimp only
          split <;> rename_i within
          · have inside : index.val < value.val.length := by simpa using within
            step as ⟨byte, byteAt⟩
            step with semantic_tail_exact as ⟨allowed, allowedMeaning⟩
            cases allowed
            · simp only [Bool.false_eq_true, ↓reduceIte, spec_ok]
              have invalid : ¬ valid (bytes value.val) maximum.val := by
                intro valid
                have member : byte.val ∈ bytes value.val := by
                  apply List.mem_map.mpr
                  exact ⟨byte, by rw [byteAt]; exact List.getElem_mem inside, rfl⟩
                have bound := valid.2.2.2 byte.val member
                simp [bound] at allowedMeaning
              simp [invalid]
            · simp only [↓reduceIte]
              step as ⟨next, nextEq⟩
              have permitted : tail byte.val := by simpa using allowedMeaning.symm
              refine ⟨by omega, ?_, by omega⟩
              rw [nextEq, List.take_succ_eq_append_getElem inside]
              simp only [List.mem_append, List.mem_cons, List.not_mem_nil, or_false]
              intro current member
              rcases member with earlier | rfl
              · exact processed.2 current earlier
              · simpa only [← byteAt] using permitted
          · simp only [spec_ok]
            have atEnd : value.val.length ≤ index.val := by simpa using within
            have complete : ∀ byte ∈ value.val, tail byte.val := by
              simpa only [List.take_of_length_le atEnd] using processed.2
            have valid : valid (bytes value.val) maximum.val := by
              refine ⟨by simpa using nonempty, by simpa using fits, firstValid, ?_⟩
              intro byte member
              obtain ⟨native, nativeMember, rfl⟩ := List.mem_map.mp member
              exact complete native nativeMember
            simp [valid]
        · exact ⟨by simp, by simp⟩
  · simp only [↓reduceIte, spec_ok]
    have emptyList : value.val = [] := by simpa [Slice.length] using emptyMeaning.symm
    simp [valid, bytes, emptyList]



theorem source_earns_no_nul (value : Slice Std.U8) (maximum : Std.Usize) :
    kernel.semantic_id_valid value maximum ⦃ actual => actual = true → 0 ∉ bytes value.val ⦄ := by
  step with semantic_valid_exact as ⟨actual, exactMeaning⟩
  rename_i accepted
  rw [accepted] at exactMeaning
  have checked : valid (bytes value.val) maximum.val := by simpa using exactMeaning.symm
  exact valid_has_no_nul _ _ checked

theorem source_earns_ascii (value : Slice Std.U8) (maximum : Std.Usize) :
    kernel.semantic_id_valid value maximum ⦃ actual => actual = true →
      ∀ byte ∈ bytes value.val, byte < 128 ⦄ := by
  step with semantic_valid_exact as ⟨actual, exactMeaning⟩
  rename_i accepted byte member
  rw [accepted] at exactMeaning
  have checked : valid (bytes value.val) maximum.val := by simpa using exactMeaning.symm
  exact valid_is_ascii _ _ checked byte member

theorem source_earns_bounds (value : Slice Std.U8) (maximum : Std.Usize) :
    kernel.semantic_id_valid value maximum ⦃ actual => actual = true →
      value.val ≠ [] ∧ value.val.length ≤ maximum.val ⦄ := by
  step with semantic_valid_exact as ⟨actual, exactMeaning⟩
  rename_i accepted
  rw [accepted] at exactMeaning
  have checked : valid (bytes value.val) maximum.val := by simpa using exactMeaning.symm
  exact ⟨by simpa using checked.1, by simpa using checked.2.1⟩

end Auths.Product.SemanticId.Refinement
