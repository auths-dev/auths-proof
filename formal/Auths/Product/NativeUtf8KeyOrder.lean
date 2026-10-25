import Auths.Product.NativeCompilerValues
import Init.Data.String.Lemmas.StringOrder
import Init.Data.Char.Lemmas
import Init.Data.ByteArray.Lemmas
import Init.Data.List.Lex
import Lean.Elab.Tactic.Omega

/-!
Unicode scalar order and complete UTF-8 byte order. The ordinary native String
model compares Lean Strings by scalar lists; the body compiler consumes byte
lists. UTF-8 preserves that order even across encoding-width boundaries and
with arbitrary suffixes. No ASCII restriction, normalization or locale is used.
This is NOT the UTF-16 key order of the canonical JSON serializer.
-/
namespace Auths.Product.NativeUtf8KeyOrder
open NativeCompiler

set_option maxHeartbeats 6000000

/-- Nat view of the actual UTF-8 encoding, with no modulo narrowing. -/
def scalar (value : Nat) : List Nat :=
  if value ≤ 127 then [value]
  else if value ≤ 2047 then [192 + value / 64, 128 + value % 64]
  else if value ≤ 65535 then
    [224 + value / 4096, 128 + (value / 64) % 64, 128 + value % 64]
  else
    [240 + value / 262144, 128 + (value / 4096) % 64,
      128 + (value / 64) % 64, 128 + value % 64]

def characters (input : List Char) : List Nat :=
  input.flatMap (fun character => scalar character.val.toNat)

theorem scalar_never_empty (value : Nat) : scalar value ≠ [] := by
  unfold scalar
  repeat' split <;> simp

theorem character_scalar_bounded (character : Char) : character.val.toNat ≤ 1114111 := by
  have valid := character.valid
  unfold UInt32.isValidChar Nat.isValidChar at valid
  omega

/-- Distinct ordered scalars differ before either encoded prefix ends, so
the order does not depend on the contents of the following byte sequences. -/
theorem scalar_prefix_preserves_order (left right : Nat)
    (leftBound : left ≤ 1114111) (rightBound : right ≤ 1114111)
    (ordered : left < right) (leftTail rightTail : List Nat) :
    scalar left ++ leftTail < scalar right ++ rightTail := by
  unfold scalar
  repeat' split
  all_goals
    simp only [List.cons_append, List.nil_append, List.cons_lt_cons_iff]
    omega

/-- Agreement with Lean's actual original UTF-8 bytes, not an alternative
encoder assumed to implement the standard. Every UInt8 conversion is proved
to retain the complete byte, including the four-byte scalar case. -/
theorem character_bytes_exact (character : Char) :
    (String.utf8EncodeChar character).map UInt8.toNat = scalar character.val.toNat := by
  have scalarBound := character_scalar_bounded character
  unfold String.utf8EncodeChar scalar
  repeat' split
  all_goals
    simp_all only [List.map_cons, List.map_nil, List.cons.injEq, UInt8.toNat_ofNat']
    omega

theorem characters_preserve_order {left right : List Char} (ordered : left < right) :
    characters left < characters right := by
  change List.Lex (· < ·) left right at ordered
  induction ordered with
  | @nil character rest =>
      have nonempty : scalar character.val.toNat ≠ [] := scalar_never_empty _
      cases encoded : scalar character.val.toNat with
      | nil => exact False.elim (nonempty encoded)
      | cons byte bytes => simpa [characters, encoded] using List.nil_lt_cons byte (bytes ++ characters rest)
  | @rel first leftTail second rightTail firstBefore =>
      have nativeBefore : first.val.toNat < second.val.toNat := by
        simpa only [Char.lt_def, UInt32.lt_iff_toNat_lt] using firstBefore
      simpa only [characters, List.flatMap_cons] using scalar_prefix_preserves_order
        first.val.toNat second.val.toNat (character_scalar_bounded first) (character_scalar_bounded second)
        nativeBefore (characters leftTail) (characters rightTail)
  | @cons character leftTail rightTail previous ih =>
      simpa only [characters, List.flatMap_cons] using List.append_left_lt (l₁ := scalar character.val.toNat) ih

theorem text_bytes_are_complete_encoding (text : String) : textBytes text = characters text.toList := by
  change text.toByteArray.data.toList.map UInt8.toNat = characters text.toList
  rw [← String.utf8Encode_toList]
  simp only [List.utf8Encode, List.toList_data_toByteArray, List.map_flatMap, character_bytes_exact, characters]

theorem native_string_order_earns_byte_order (left right : String) (ordered : left < right) :
    textBytes left < textBytes right := by
  have scalarOrder : left.toList < right.toList := ordered
  simpa only [text_bytes_are_complete_encoding] using characters_preserve_order scalarOrder

theorem native_string_byte_order_iff (left right : String) :
    left < right ↔ textBytes left < textBytes right := by
  constructor
  · exact native_string_order_earns_byte_order left right
  · intro byteOrder
    by_contra noOrder
    by_cases reversed : right < left
    · exact List.lt_asymm byteOrder (native_string_order_earns_byte_order right left reversed)
    · have leftAtMost : left ≤ right := String.not_lt.mp reversed
      have rightAtMost : right ≤ left := String.not_lt.mp noOrder
      have same : left = right := String.le_antisymm leftAtMost rightAtMost
      rw [same] at byteOrder
      exact List.lt_irrefl _ byteOrder

theorem ordered_native_keys_earn_byte_keys {T : Type} (members : List (String × T))
    (ordered : members.Pairwise (fun left right => left.1 < right.1)) :
    (members.map (fun member => textBytes member.1)).Pairwise (· < ·) := by
  induction members with
  | nil => simp
  | cons first rest ih =>
      obtain ⟨before, tail⟩ := List.pairwise_cons.mp ordered
      apply List.pairwise_cons.mpr
      refine ⟨?_, ih tail⟩
      intro key member
      obtain ⟨original, originalMember, rfl⟩ := List.mem_map.mp member
      exact native_string_order_earns_byte_order first.1 original.1 (before original originalMember)

end Auths.Product.NativeUtf8KeyOrder
