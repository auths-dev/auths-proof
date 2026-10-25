import Auths.Product.JcsWriterFrames

/-!
The pinned serde_json 1.0.151 ESCAPE table and its scalar dispatch meaning.
The table below retains every original byte slot, including all zero entries.
Its equality to the reviewed native initializer/checksum remains a final
ordinary-library evidence obligation. No Auths Serialize body is opaque.
-/
namespace Auths.Product.JcsStringDispatch
open JcsWriterFrames

def byteEscape (byte : Nat) : Option Escape :=
  if byte = 34 then some .quote
  else if byte = 92 then some .reverseSolidus
  else if byte = 8 then some .backspace
  else if byte = 9 then some .tab
  else if byte = 10 then some .lineFeed
  else if byte = 12 then some .formFeed
  else if byte = 13 then some .carriageReturn
  else if control : byte < 32 then some (.asciiControl ⟨byte, by omega⟩)
  else none

def escapeCode : Option Escape → Nat
  | none => 0
  | some .quote => 34
  | some .reverseSolidus => 92
  | some .solidus => 47
  | some .backspace => 98
  | some .tab => 116
  | some .lineFeed => 110
  | some .formFeed => 102
  | some .carriageReturn => 114
  | some (.asciiControl _) => 117

def pinnedTable : List Nat := [
  117, 117, 117, 117, 117, 117, 117, 117, 98, 116, 110, 117, 102, 114, 117, 117,
  117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117,
  0, 0, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 92, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
]

theorem pinned_table_has_all_byte_slots : pinnedTable.length = 256 := by decide

theorem pinned_table_matches_dispatch : ∀ byte : Fin 256,
    pinnedTable[byte.val]? = some (escapeCode (byteEscape byte.val)) := by decide

theorem pinned_table_has_only_handled_codes (byte : Fin 256) :
    ∃ code, pinnedTable[byte.val]? = some code ∧ code ∈ [0, 98, 116, 110, 102, 114, 34, 92, 117] := by
  refine ⟨escapeCode (byteEscape byte.val), pinned_table_matches_dispatch byte, ?_⟩
  unfold byteEscape
  repeat' split <;> simp [escapeCode]

theorem escape_trigger_is_ascii (byte : Nat) (escape : Escape) (selected : byteEscape byte = some escape) :
    byte < 128 := by
  unfold byteEscape at selected
  repeat' split at selected <;> simp_all <;> omega

theorem high_byte_never_escapes (byte : Nat) (high : 128 ≤ byte) : byteEscape byte = none := by
  unfold byteEscape
  repeat' split <;> first | rfl | omega

/-- UTF-8 non-ASCII scalars contain no byte that the escape table selects.
Thus an ASCII escape boundary cannot split one of their multibyte encodings. -/
theorem nonascii_utf8_bytes_never_escape (character : Char) (nonascii : 128 ≤ character.toNat) :
    ∀ byte ∈ NativeUtf8KeyOrder.scalar character.toNat, byteEscape byte = none := by
  intro byte member
  apply high_byte_never_escapes
  unfold NativeUtf8KeyOrder.scalar at member
  repeat' split at member
  all_goals
    simp only [List.mem_cons, List.not_mem_nil, or_false] at member
    omega

end Auths.Product.JcsStringDispatch
