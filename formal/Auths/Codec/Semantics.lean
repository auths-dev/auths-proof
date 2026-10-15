import Std.Tactic

/-!
# Definite CBOR head semantics

These definitions describe the byte grammar independently of the Rust
cursor. A head is only a major tag and an unsigned argument; interpreting
that argument as a length or a protocol field belongs to the object decoder.
The raw parser permits wider integer arguments, just like the shipping
reader. Canonical object acceptance additionally compares the complete
encoding with the input.
-/

namespace Auths.Codec

structure Head where
  major : Nat
  argument : Nat
  deriving DecidableEq, Repr

def Head.Valid (head : Head) : Prop :=
  head.major < 8 ∧ head.argument < 2 ^ 64

def BytesValid (bytes : List Nat) : Prop :=
  ∀ byte ∈ bytes, byte < 256

/-- Fixed-width big-endian digits, most significant first. -/
def bigEndian : Nat → Nat → List Nat
  | 0, _ => []
  | width + 1, value => bigEndian width (value / 256) ++ [value % 256]

/-- The positional value of big-endian digits. -/
def unsigned : List Nat → Nat
  | [] => 0
  | byte :: rest => byte * 256 ^ rest.length + unsigned rest

/-- Left-to-right positional interpretation, with an explicit initial value. -/
def accumulate : Nat → List Nat → Nat
  | value, [] => value
  | value, byte :: rest => accumulate (value * 256 + byte) rest

theorem accumulate_ge_initial (value : Nat) (bytes : List Nat) :
    value ≤ accumulate value bytes := by
  induction bytes generalizing value with
  | nil => exact Nat.le_refl _
  | cons byte rest ih =>
    exact Nat.le_trans (by omega) (ih (value * 256 + byte))

theorem accumulate_eq (value : Nat) (bytes : List Nat) :
    accumulate value bytes = value * 256 ^ bytes.length + unsigned bytes := by
  induction bytes generalizing value with
  | nil => simp [accumulate, unsigned]
  | cons byte rest ih =>
    simp only [accumulate, ih, unsigned, List.length_cons, Nat.pow_succ]
    simp [Nat.add_mul, Nat.mul_assoc, Nat.mul_comm, Nat.add_assoc]

def argumentWidth (value : Nat) : Nat :=
  if value < 24 then 0
  else if value < 256 then 1
  else if value < 65536 then 2
  else if value < 4294967296 then 4
  else 8

def additionalTag (value : Nat) : Nat :=
  if value < 24 then value
  else if value < 256 then 24
  else if value < 65536 then 25
  else if value < 4294967296 then 26
  else 27

def encodeHead (head : Head) : List Nat :=
  (head.major * 32 + additionalTag head.argument) ::
    bigEndian (argumentWidth head.argument) head.argument

def readArgument (width : Nat) (bytes : List Nat) : Option (Nat × List Nat) :=
  if width ≤ bytes.length then
    some (unsigned (bytes.take width), bytes.drop width)
  else none

def readHead : List Nat → Option (Head × List Nat)
  | [] => none
  | first :: rest =>
    if first < 256 then
      let additional := first % 32
      let major := first / 32
      if additional < 24 then some (⟨major, additional⟩, rest)
      else
        let argument :=
          if additional = 24 then readArgument 1 rest
          else if additional = 25 then readArgument 2 rest
          else if additional = 26 then readArgument 4 rest
          else if additional = 27 then readArgument 8 rest
          else none
        argument.map fun (value, tail) => (⟨major, value⟩, tail)
    else none

theorem bigEndian_length (width value : Nat) :
    (bigEndian width value).length = width := by
  induction width generalizing value with
  | zero => rfl
  | succ width ih => simp [bigEndian, ih]

theorem bigEndian_bytes_valid (width value : Nat) :
    BytesValid (bigEndian width value) := by
  induction width generalizing value with
  | zero => simp [BytesValid, bigEndian]
  | succ width ih =>
    simp only [bigEndian, BytesValid, List.mem_append, List.mem_singleton]
    intro byte member
    rcases member with member | rfl
    · exact ih _ _ member
    · exact Nat.mod_lt _ (by decide)

theorem unsigned_append_singleton (bytes : List Nat) (byte : Nat) :
    unsigned (bytes ++ [byte]) = unsigned bytes * 256 + byte := by
  induction bytes with
  | nil => simp [unsigned]
  | cons first rest ih =>
    simp only [List.cons_append, unsigned, List.length_append, List.length_singleton,
      Nat.pow_succ, ih]
    simp [Nat.add_mul, Nat.mul_assoc, Nat.add_assoc]

theorem unsigned_lt_power (bytes : List Nat) (valid : BytesValid bytes) :
    unsigned bytes < 256 ^ bytes.length := by
  induction bytes with
  | nil => simp [unsigned]
  | cons byte rest ih =>
    have digit : byte ≤ 255 := by
      have := valid byte (by simp)
      omega
    have restValid : BytesValid rest := by
      intro value member
      exact valid value (by simp [member])
    have tailBound := ih restValid
    have scaled := Nat.mul_le_mul_right (256 ^ rest.length) digit
    simp only [unsigned, List.length_cons, Nat.pow_succ]
    omega

theorem unsigned_take_drop_succ (bytes : List Nat) (position width : Nat)
    (fits : position + (width + 1) ≤ bytes.length) :
    unsigned ((bytes.drop position).take (width + 1)) =
      bytes[position]'(by omega) * 256 ^ width +
        unsigned ((bytes.drop (position + 1)).take width) := by
  have atByte : position < bytes.length := by omega
  have restFits : width ≤ (bytes.drop (position + 1)).length := by
    simp only [List.length_drop]
    omega
  calc
    _ = unsigned (bytes[position] :: (bytes.drop (position + 1)).take width) := by
      apply congrArg unsigned
      rw [List.drop_eq_getElem_cons atByte]
      rfl
    _ = _ := by
      rw [unsigned, List.length_take, Nat.min_eq_left restFits]

theorem unsigned_bigEndian (width value : Nat) (fits : value < 256 ^ width) :
    unsigned (bigEndian width value) = value := by
  induction width generalizing value with
  | zero =>
    have : value = 0 := by simpa using fits
    simp [this, bigEndian, unsigned]
  | succ width ih =>
    have smaller : value / 256 < 256 ^ width := by
      apply (Nat.div_lt_iff_lt_mul (by decide : 0 < 256)).2
      simpa [Nat.pow_succ, Nat.mul_comm] using fits
    rw [bigEndian, unsigned_append_singleton, ih _ smaller]
    omega

theorem readArgument_bigEndian (width value : Nat)
    (fits : value < 256 ^ width) (tail : List Nat) :
    readArgument width (bigEndian width value ++ tail) = some (value, tail) := by
  simp [readArgument, bigEndian_length, unsigned_bigEndian _ _ fits]

theorem encodeHead_length_le_nine (head : Head) :
    (encodeHead head).length ≤ 9 := by
  simp only [encodeHead, List.length_cons, bigEndian_length, argumentWidth]
  split <;> (try split) <;> (try split) <;> (try split) <;> omega

theorem readHead_inline (major value : Nat) (tail : List Nat)
    (tagBound : major < 8) (inline : value < 24) :
    readHead ((major * 32 + value) :: tail) = some (⟨major, value⟩, tail) := by
  have firstBound : major * 32 + value < 256 := by omega
  have div : (major * 32 + value) / 32 = major := by omega
  have mod : (major * 32 + value) % 32 = value := by omega
  simp [readHead, firstBound, div, mod, inline]

theorem readHead_extended (major tag width value : Nat) (tail : List Nat)
    (tagBound : major < 8)
    (widthTag : (tag = 24 ∧ width = 1) ∨ (tag = 25 ∧ width = 2) ∨
      (tag = 26 ∧ width = 4) ∨ (tag = 27 ∧ width = 8))
    (fits : value < 256 ^ width) :
    readHead ((major * 32 + tag) :: (bigEndian width value ++ tail)) =
      some (⟨major, value⟩, tail) := by
  have tagLt : tag < 32 := by omega
  have firstBound : major * 32 + tag < 256 := by omega
  have div : (major * 32 + tag) / 32 = major := by omega
  have mod : (major * 32 + tag) % 32 = tag := by omega
  rcases widthTag with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;>
    simp [readHead, firstBound, div, mod, readArgument_bigEndian _ _ fits]

theorem readHead_encodeHead (head : Head) (valid : head.Valid) (tail : List Nat) :
    readHead (encodeHead head ++ tail) = some (head, tail) := by
  rcases head with ⟨major, value⟩
  rcases valid with ⟨tagBound, valueBound⟩
  by_cases inline : value < 24
  · simpa [encodeHead, argumentWidth, additionalTag, inline, bigEndian] using
      readHead_inline major value tail tagBound inline
  · by_cases one : value < 256
    · simpa [encodeHead, argumentWidth, additionalTag, inline, one] using
        readHead_extended major 24 1 value tail tagBound (Or.inl ⟨rfl, rfl⟩) one
    · by_cases two : value < 65536
      · simpa [encodeHead, argumentWidth, additionalTag, inline, one, two] using
          readHead_extended major 25 2 value tail tagBound
            (Or.inr (Or.inl ⟨rfl, rfl⟩)) two
      · by_cases four : value < 4294967296
        · simpa [encodeHead, argumentWidth, additionalTag, inline, one, two, four] using
            readHead_extended major 26 4 value tail tagBound
              (Or.inr (Or.inr (Or.inl ⟨rfl, rfl⟩))) four
        · simpa [encodeHead, argumentWidth, additionalTag, inline, one, two, four] using
            readHead_extended major 27 8 value tail tagBound
              (Or.inr (Or.inr (Or.inr ⟨rfl, rfl⟩))) valueBound

end Auths.Codec
