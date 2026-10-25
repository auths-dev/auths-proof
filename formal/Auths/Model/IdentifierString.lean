import Auths.Model.IdentifierSemantics
import Mathlib.Tactic.SplitIfs
namespace Auths.Model.Identifier

theorem character_bound (character : Char) : character.toNat ≤ 1114111 := by
  have valid := character.valid
  change character.val.toNat < 55296 ∨
    57343 < character.val.toNat ∧ character.val.toNat < 1114112 at valid
  change character.val.toNat ≤ 1114111
  omega

theorem character_encoding (character : Char) :
    (String.utf8EncodeChar character).map UInt8.toNat = utf8 character.toNat := by
  have bounded := character_bound character
  simp only [← Char.toNat_val] at bounded ⊢
  simp only [String.utf8EncodeChar, utf8]
  split_ifs <;> simp_all only [List.map_cons, List.map_nil, UInt8.toNat_ofNat', List.cons.injEq]
  all_goals simp only [Nat.reducePow, and_true]
  all_goals omega

theorem byte_array_list (bytes : ByteArray) : bytes.toList = bytes.data.toList := by
  have loop_eq : ∀ (position : Nat) (accumulator : List UInt8),
      ByteArray.toList.loop bytes position accumulator =
        accumulator.reverse ++ bytes.data.toList.drop position := by
    intro position accumulator
    fun_induction ByteArray.toList.loop bytes position accumulator with
    | case1 position accumulator within ih =>
      rw [ih]
      have bound : position < bytes.data.toList.length := by simpa using within
      rw [List.drop_eq_getElem_cons bound]
      simp [List.reverse_cons, List.append_assoc, ByteArray.get!, within]
      rfl
    | case2 position accumulator atEnd =>
      have bound : bytes.data.toList.length ≤ position := by simpa using Nat.le_of_not_lt atEnd
      simp [List.drop_eq_nil_of_le bound]
  simpa only [ByteArray.toList, List.reverse_nil, List.drop_zero, List.nil_append]
    using loop_eq 0 []

theorem string_encoding (value : String) :
    value.toByteArray.toList.map UInt8.toNat =
      value.toList.flatMap (fun character => utf8 character.toNat) := by
  rw [byte_array_list, ← String.utf8Encode_toList]
  simp only [List.utf8Encode, List.toList_data_toByteArray, List.map_flatMap]
  simp only [character_encoding]

end Auths.Model.Identifier
