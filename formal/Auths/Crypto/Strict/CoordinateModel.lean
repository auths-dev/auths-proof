import Auths.Crypto.Encoding.Encoded
open Aeneas Aeneas.Std
open Auths.Crypto.Encoding.Encoded
namespace Auths.Crypto.CoordinateModel

def digits (input : Input) : List Nat :=
  (input.val.take 31).map UScalar.val ++ [(last input).val % 128]

theorem digits_length (input : Input) : (digits input).length = 32 := by
  simp [digits, input_length]

theorem digits_bound (input : Input) : ∀ byte ∈ digits input, byte < 256 := by
  intro byte member
  simp only [digits, List.mem_append, List.mem_map, List.mem_singleton] at member
  rcases member with mapped | lastByte
  · rcases mapped with ⟨original, _, rfl⟩; scalar_tac
  · subst byte
    have bounded := Nat.mod_lt (last input).val (by decide : 0 < 128)
    omega

theorem coordinate_prefix (input : Input) : input.val.take 31 = first input :: middle input := by
  cases values : input.val with
  | nil => have bound := input_length input; simp [values] at bound
  | cons head tail => simp [first, middle, values]

theorem digits_value (input : Input) : Nat.ofDigits 256 (digits input) = ordinate input := by
  unfold digits ordinate topValue
  rw [coordinate_prefix]
  simp only [List.map_cons, List.cons_append]

theorem ordinate_eq_iff (input expected : Input) :
    ordinate input = ordinate expected ↔
      input.val.take 31 = expected.val.take 31 ∧ (last input).val % 128 = (last expected).val % 128 := by
  rw [← digits_value, ← digits_value]
  constructor
  · intro same
    have equalDigits : digits input = digits expected :=
      Nat.ofDigits_inj_of_len_eq (by decide) (by rw [digits_length, digits_length])
        (digits_bound input) (digits_bound expected) same
    have pieces := List.append_inj equalDigits (by simp [input_length])
    refine ⟨?_, ?_⟩
    · apply (List.map_injective_iff.mpr (show Function.Injective (fun byte : Std.U8 => byte.val) from by
        intro left right equal; scalar_tac))
      exact pieces.1
    · simpa using pieces.2
  · rintro ⟨samePrefix, sameLast⟩
    apply congrArg (Nat.ofDigits 256)
    simp [digits, samePrefix, sameLast]

end Auths.Crypto.CoordinateModel
