import Auths.Product.NativeUtf8KeyOrder
import Auths.Product.JcsUtf16Keys

/-!
Independent string-byte specification for the pinned JCS formatter. This is
complete Unicode text, not serialized sorting-key order. The formatter leaves
solidus, non-ASCII text and U+2028/U+2029 unescaped; it escapes quote, reverse
solidus and controls. Native serde fragment/escape dispatch and writer stack
adequacy are still required to connect these bytes to the shipping formatter.
-/
namespace Auths.Product.JcsStringEncoding

def hex (nibble : Nat) : Nat := if nibble < 10 then 48 + nibble else 87 + nibble

def scalar (value : Nat) : List Nat :=
  if value = 34 then [92, 34]
  else if value = 92 then [92, 92]
  else if value = 8 then [92, 98]
  else if value = 9 then [92, 116]
  else if value = 10 then [92, 110]
  else if value = 12 then [92, 102]
  else if value = 13 then [92, 114]
  else if value < 32 then [92, 117, 48, 48, hex (value / 16), hex (value % 16)]
  else NativeUtf8KeyOrder.scalar value

def characters (input : List Char) : List Nat := input.flatMap (fun character => scalar character.toNat)

def quoted (input : String) : List Nat := 34 :: (characters input.toList ++ [34])

theorem hex_is_lowercase_digit (nibble : Nat) (bounded : nibble < 16) :
    (48 ≤ hex nibble ∧ hex nibble ≤ 57) ∨ (97 ≤ hex nibble ∧ hex nibble ≤ 102) := by
  unfold hex
  split <;> omega

theorem scalar_never_empty (value : Nat) : scalar value ≠ [] := by
  unfold scalar NativeUtf8KeyOrder.scalar
  repeat' split <;> simp

theorem scalar_bytes_bounded (value : Nat) (valid : JcsUtf16Keys.ValidScalar value) :
    ∀ byte ∈ scalar value, byte < 256 := by
  have upper : value ≤ 1114111 := by
    rcases valid with first | second <;> omega
  unfold scalar NativeUtf8KeyOrder.scalar hex
  repeat' split
  all_goals
    intro byte member
    simp only [List.mem_cons, List.not_mem_nil, or_false] at member
    omega

theorem scalar_length_bound (value : Nat) : (scalar value).length ≤ 6 := by
  unfold scalar NativeUtf8KeyOrder.scalar
  repeat' split <;> simp

/-- Bound against original UTF-8 bytes, rather than assuming one byte per
character. This is an output-size bound for one string, not aggregate writer
allocation/time or a whole-source serialization bound. -/
theorem scalar_length_relative_to_utf8 (value : Nat) :
    (scalar value).length ≤ 6 * (NativeUtf8KeyOrder.scalar value).length := by
  unfold scalar NativeUtf8KeyOrder.scalar
  repeat' split <;> simp

theorem characters_append (left right : List Char) :
    characters (left ++ right) = characters left ++ characters right := by
  simp only [characters, List.flatMap_append]

theorem characters_length_bound (input : List Char) : (characters input).length ≤ 6 * input.length := by
  induction input with
  | nil => simp [characters]
  | cons first rest ih =>
      have head := scalar_length_bound first.toNat
      simp only [characters, List.flatMap_cons, List.length_append, List.length_cons] at *
      omega

theorem characters_length_relative_to_utf8 (input : List Char) :
    (characters input).length ≤ 6 * (NativeUtf8KeyOrder.characters input).length := by
  induction input with
  | nil => simp [characters, NativeUtf8KeyOrder.characters]
  | cons first rest ih =>
      have head := scalar_length_relative_to_utf8 first.toNat
      simp only [characters, NativeUtf8KeyOrder.characters, List.flatMap_cons, List.length_append] at *
      omega

theorem characters_bytes_bounded (input : List Char) : ∀ byte ∈ characters input, byte < 256 := by
  intro byte member
  obtain ⟨character, _, inScalar⟩ := List.mem_flatMap.mp member
  exact scalar_bytes_bounded _ (JcsUtf16Keys.character_is_valid character) byte inScalar

theorem quoted_keeps_entire_content (input : String) :
    quoted input = [34] ++ characters input.toList ++ [34] := rfl

theorem quoted_bytes_bounded (input : String) : ∀ byte ∈ quoted input, byte < 256 := by
  intro byte member
  simp only [quoted, List.mem_cons, List.mem_append, List.mem_singleton] at member
  rcases member with rfl | member | rfl
  · decide
  · exact characters_bytes_bounded _ byte member
  · decide

theorem quoted_length_relative_to_original_bytes (input : String) :
    (quoted input).length ≤ 6 * (NativeCompiler.textBytes input).length + 2 := by
  have content := characters_length_relative_to_utf8 input.toList
  rw [NativeUtf8KeyOrder.text_bytes_are_complete_encoding]
  simp only [quoted, List.length_cons, List.length_append, List.length_singleton]
  omega

end Auths.Product.JcsStringEncoding
