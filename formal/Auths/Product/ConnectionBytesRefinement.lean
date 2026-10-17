import qualification.aeneas.generated.connections.Funs
import Auths.Product.ConnectionBytes
open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_connections
namespace Auths.Product.ConnectionBytes.Refinement
set_option maxHeartbeats 4000000
abbrev bytes (values : List Std.U8) : List Nat := values.map (·.val)

@[step] theorem lower_tail_exact (byte : Std.U8) :
    kernel.lower_tail_valid byte ⦃ actual => actual = decide (lowerTail byte.val) ⦄ := by
  unfold kernel.lower_tail_valid
  repeat' split
  all_goals simp_all only [spec_ok, lowerTail, lowerHead, UScalar.eq_equiv]
  all_goals apply Bool.eq_iff_iff.mpr
  all_goals simp only [decide_eq_true_eq, true_iff]
  all_goals scalar_tac

@[step] theorem graphic_valid_exact (value : Slice Std.U8) (maximum : Std.Usize) :
    kernel.ascii_graphic_valid value maximum ⦃ actual =>
      actual = decide (graphicValid (bytes value.val) maximum.val) ⦄ := by
  unfold kernel.ascii_graphic_valid
  step as ⟨empty, emptyMeaning⟩
  cases empty
  · simp only [Bool.false_eq_true, ↓reduceIte]
    have nonempty : value.val ≠ [] := by simpa [Slice.length] using emptyMeaning.symm
    split <;> rename_i exceeds
    · simp only [spec_ok]
      have tooLarge : maximum.val < value.val.length := by simpa using exceeds
      simp [graphicValid, bytes, tooLarge.not_ge]
    · have fits : value.val.length ≤ maximum.val := by simpa using exceeds
      unfold kernel.ascii_graphic_valid_loop
      apply loop.spec_decr_nat
        (measure := fun index => value.val.length - index.val)
        (inv := fun index => index.val ≤ value.val.length ∧ ∀ byte ∈ value.val.take index.val, graphic byte.val)
      · intro index processed
        unfold kernel.ascii_graphic_valid_loop.body
        dsimp only
        split <;> rename_i within
        · have inside : index.val < value.val.length := by simpa using within
          step as ⟨byte, byteAt⟩
          split <;> rename_i low
          · simp only [spec_ok]
            have invalid : ¬ graphicValid (bytes value.val) maximum.val := by
              intro valid
              have member : byte.val ∈ bytes value.val := by apply List.mem_map.mpr; exact ⟨byte, by rw [byteAt]; exact List.getElem_mem inside, rfl⟩
              have bound := valid.2.2 byte.val member
              unfold graphic at bound
              scalar_tac
            simp [invalid]
          · split <;> rename_i high
            · simp only [spec_ok]
              have invalid : ¬ graphicValid (bytes value.val) maximum.val := by
                intro valid
                have member : byte.val ∈ bytes value.val := by apply List.mem_map.mpr; exact ⟨byte, by rw [byteAt]; exact List.getElem_mem inside, rfl⟩
                have bound := valid.2.2 byte.val member
                unfold graphic at bound
                scalar_tac
              simp [invalid]
            · step as ⟨next, nextEq⟩
              refine ⟨by omega, ?_, by omega⟩
              rw [nextEq, List.take_succ_eq_append_getElem inside]
              simp only [List.mem_append, List.mem_cons, List.not_mem_nil, or_false]
              intro current member
              rcases member with earlier | rfl
              · exact processed.2 current earlier
              · rw [← byteAt]
                unfold graphic
                scalar_tac
        · simp only [spec_ok]
          have atEnd : value.val.length ≤ index.val := by simpa using within
          have complete : ∀ byte ∈ value.val, graphic byte.val := by simpa only [List.take_of_length_le atEnd] using processed.2
          have valid : graphicValid (bytes value.val) maximum.val := by
            refine ⟨by simpa using nonempty, by simpa using fits, ?_⟩
            intro byte member
            obtain ⟨native, nativeMember, rfl⟩ := List.mem_map.mp member
            exact complete native nativeMember
          simp [valid]
      · exact ⟨by simp, by simp⟩
  · simp only [↓reduceIte, spec_ok]
    have emptyList : value.val = [] := by simpa [Slice.length] using emptyMeaning.symm
    simp [graphicValid, bytes, emptyList]

@[step] theorem lower_valid_exact (value : Slice Std.U8) (maximum : Std.Usize) :
    kernel.lower_token_valid value maximum ⦃ actual =>
      actual = decide (lowerValid (bytes value.val) maximum.val) ⦄ := by
  unfold kernel.lower_token_valid
  step as ⟨empty, emptyMeaning⟩
  cases empty
  · simp only [Bool.false_eq_true, ↓reduceIte]
    have nonempty : value.val ≠ [] := by simpa [Slice.length] using emptyMeaning.symm
    have firstInside : 0 < value.val.length := List.length_pos_iff.mpr nonempty
    split <;> rename_i exceeds
    · simp only [spec_ok]
      have tooLarge : maximum.val < value.val.length := by simpa using exceeds
      simp [lowerValid, bytes, tooLarge.not_ge]
    · have fits : value.val.length ≤ maximum.val := by simpa using exceeds
      step as ⟨first, firstMeaning⟩
      have firstAt : (bytes value.val)[0]! = first.val := by
        rw [getElem!_pos (bytes value.val) 0 (by simpa using firstInside)]
        simp [bytes, ← firstMeaning]
      split <;> rename_i low
      · simp only [spec_ok]
        have invalid : ¬ lowerValid (bytes value.val) maximum.val := by
          intro valid
          have bound := valid.2.2.1
          rw [firstAt] at bound
          unfold lowerHead at bound
          scalar_tac
        simp [invalid]
      · split <;> rename_i high
        · simp only [spec_ok]
          have invalid : ¬ lowerValid (bytes value.val) maximum.val := by
            intro valid
            have bound := valid.2.2.1
            rw [firstAt] at bound
            unfold lowerHead at bound
            scalar_tac
          simp [invalid]
        · have firstValid : lowerHead (bytes value.val)[0]! := by
            rw [firstAt]
            unfold lowerHead
            scalar_tac
          unfold kernel.lower_token_valid_loop
          apply loop.spec_decr_nat
            (measure := fun index => value.val.length - index.val)
            (inv := fun index => index.val ≤ value.val.length ∧ ∀ byte ∈ value.val.take index.val, lowerTail byte.val)
          · intro index processed
            unfold kernel.lower_token_valid_loop.body
            dsimp only
            split <;> rename_i within
            · have inside : index.val < value.val.length := by simpa using within
              step as ⟨byte, byteAt⟩
              step with lower_tail_exact as ⟨allowed, allowedMeaning⟩
              cases allowed
              · simp only [Bool.false_eq_true, ↓reduceIte, spec_ok]
                have invalid : ¬ lowerValid (bytes value.val) maximum.val := by
                  intro valid
                  have member : byte.val ∈ bytes value.val := by
                    apply List.mem_map.mpr
                    exact ⟨byte, by rw [byteAt]; exact List.getElem_mem inside, rfl⟩
                  have bound := valid.2.2.2 byte.val member
                  simp [bound] at allowedMeaning
                simp [invalid]
              · simp only [↓reduceIte]
                step as ⟨next, nextEq⟩
                have permitted : lowerTail byte.val := by simpa using allowedMeaning.symm
                refine ⟨by omega, ?_, by omega⟩
                rw [nextEq, List.take_succ_eq_append_getElem inside]
                simp only [List.mem_append, List.mem_cons, List.not_mem_nil, or_false]
                intro current member
                rcases member with earlier | rfl
                · exact processed.2 current earlier
                · simpa only [← byteAt] using permitted
            · simp only [spec_ok]
              have atEnd : value.val.length ≤ index.val := by simpa using within
              have complete : ∀ byte ∈ value.val, lowerTail byte.val := by
                simpa only [List.take_of_length_le atEnd] using processed.2
              have valid : lowerValid (bytes value.val) maximum.val := by
                refine ⟨by simpa using nonempty, by simpa using fits, firstValid, ?_⟩
                intro byte member
                obtain ⟨native, nativeMember, rfl⟩ := List.mem_map.mp member
                exact complete native nativeMember
              simp [valid]
          · exact ⟨by simp, by simp⟩
  · simp only [↓reduceIte, spec_ok]
    have emptyList : value.val = [] := by simpa [Slice.length] using emptyMeaning.symm
    simp [lowerValid, bytes, emptyList]


theorem source_lower_earns_no_nul (value : Slice Std.U8) (maximum : Std.Usize) :
    kernel.lower_token_valid value maximum ⦃ actual => actual = true → 0 ∉ bytes value.val ⦄ := by
  step with lower_valid_exact as ⟨actual, exactMeaning⟩
  rename_i accepted
  rw [accepted] at exactMeaning
  have valid : lowerValid (bytes value.val) maximum.val := by simpa using exactMeaning.symm
  exact lower_has_no_nul _ _ valid

theorem source_graphic_earns_no_nul (value : Slice Std.U8) (maximum : Std.Usize) :
    kernel.ascii_graphic_valid value maximum ⦃ actual => actual = true → 0 ∉ bytes value.val ⦄ := by
  step with graphic_valid_exact as ⟨actual, exactMeaning⟩
  rename_i accepted
  rw [accepted] at exactMeaning
  have valid : graphicValid (bytes value.val) maximum.val := by simpa using exactMeaning.symm
  exact graphic_has_no_nul _ _ valid

theorem source_lower_earns_size_bound (value : Slice Std.U8) (maximum : Std.Usize) :
    kernel.lower_token_valid value maximum ⦃ actual => actual = true →
      value.val ≠ [] ∧ value.val.length ≤ maximum.val ⦄ := by
  step with lower_valid_exact as ⟨actual, exactMeaning⟩
  rename_i accepted
  rw [accepted] at exactMeaning
  have valid : lowerValid (bytes value.val) maximum.val := by simpa using exactMeaning.symm
  exact ⟨by simpa using valid.1, by simpa using valid.2.1⟩

theorem source_graphic_earns_size_bound (value : Slice Std.U8) (maximum : Std.Usize) :
    kernel.ascii_graphic_valid value maximum ⦃ actual => actual = true →
      value.val ≠ [] ∧ value.val.length ≤ maximum.val ⦄ := by
  step with graphic_valid_exact as ⟨actual, exactMeaning⟩
  rename_i accepted
  rw [accepted] at exactMeaning
  have valid : graphicValid (bytes value.val) maximum.val := by simpa using exactMeaning.symm
  exact ⟨by simpa using valid.1, by simpa using valid.2.1⟩
end Auths.Product.ConnectionBytes.Refinement


