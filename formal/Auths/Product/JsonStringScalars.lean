import Auths.Product.JcsUtf16Keys
import Auths.Product.NativeUtf8KeyOrder

/-!
Concrete scalar readers for the canonicalizer's JSON-string key reparse.
Consumed carries a complete original prefix/suffix decomposition; successful
reads consume at least one byte. Hex escapes and UTF-8 use full Nat values,
reject invalid encodings and construct a Char only after scalar validity.
This is an independent byte-language reference, not native serde adequacy.
-/
namespace Auths.Product.JsonStringScalars

abbrev Bytes := List Nat

structure Consumed (input : Bytes) (T : Type) where
  value : T
  prefix : Bytes
  rest : Bytes
  original : input = prefix ++ rest
  nonempty : prefix ≠ []

theorem consumed_keeps_original {input : Bytes} {T : Type} (read : Consumed input T) :
    input = read.prefix ++ read.rest := read.original

theorem consumed_strict_progress {input : Bytes} {T : Type} (read : Consumed input T) :
    read.rest.length < input.length := by
  have lengths := congrArg List.length read.original
  have positive : 0 < read.prefix.length := by
    cases prefixAt : read.prefix with
    | nil => exact False.elim (read.nonempty prefixAt)
    | cons first rest => simp
  simp only [List.length_append] at lengths
  omega

def Consumed.map {input : Bytes} {T U : Type} (read : Consumed input T) (transform : T → U) : Consumed input U :=
  ⟨transform read.value, read.prefix, read.rest, read.original, read.nonempty⟩

def Consumed.prepend {input : Bytes} {T : Type} (read : Consumed input T) (byte : Nat) :
    Consumed (byte :: input) T :=
  ⟨read.value, byte :: read.prefix, read.rest, by simp only [read.original, List.cons_append], by simp⟩

def Consumed.chain {input : Bytes} {T U : Type} (first : Consumed input T)
    (second : Consumed first.rest U) : Consumed input (T × U) :=
  ⟨(first.value, second.value), first.prefix ++ second.prefix, second.rest,
    by rw [first.original, second.original, List.append_assoc],
    by intro empty; exact first.nonempty (List.append_eq_nil.mp empty).1⟩

def hexDigit (byte : Nat) : Except Unit (Fin 16) :=
  if digit : 48 ≤ byte ∧ byte ≤ 57 then .ok ⟨byte - 48, by omega⟩
  else if upper : 65 ≤ byte ∧ byte ≤ 70 then .ok ⟨byte - 55, by omega⟩
  else if lower : 97 ≤ byte ∧ byte ≤ 102 then .ok ⟨byte - 87, by omega⟩
  else .error ()

def hex4 : (input : Bytes) → Except Unit (Consumed input (Fin 65536))
  | first :: second :: third :: fourth :: rest => do
      let a ← hexDigit first
      let b ← hexDigit second
      let c ← hexDigit third
      let d ← hexDigit fourth
      pure ⟨⟨4096 * a.val + 256 * b.val + 16 * c.val + d.val, by
        have := a.isLt; have := b.isLt; have := c.isLt; have := d.isLt; omega⟩,
        [first, second, third, fourth], rest, rfl, by simp⟩
  | _ => .error ()

def slashU : (input : Bytes) → Except Unit (Consumed input Unit)
  | 92 :: 117 :: rest => .ok ⟨(), [92, 117], rest, rfl, by simp⟩
  | _ => .error ()

def unicodeEscape (input : Bytes) : Except Unit (Consumed input Char) := do
  let first ← hex4 input
  let upper := first.value.val
  if high : 55296 ≤ upper ∧ upper < 56320 then
    let marker ← slashU first.rest
    let second ← hex4 marker.rest
    let lower := second.value.val
    if low : 56320 ≤ lower ∧ lower < 57344 then
      let scalar := 65536 + (upper - 55296) * 1024 + (lower - 56320)
      have valid : scalar.isValidChar := by
        unfold scalar Nat.isValidChar
        right
        constructor <;> omega
      pure ((first.chain (marker.chain second)).map (fun _ => Char.ofNatAux scalar valid))
    else .error ()
  else if low : 56320 ≤ upper ∧ upper < 57344 then .error ()
  else
    have valid : upper.isValidChar := by
      have bounded := first.value.isLt
      unfold Nat.isValidChar
      omega
    pure (first.map (fun _ => Char.ofNatAux upper valid))

def escape : (input : Bytes) → Except Unit (Consumed input Char)
  | 34 :: rest => .ok ⟨'"', [34], rest, rfl, by simp⟩
  | 92 :: rest => .ok ⟨'\\', [92], rest, rfl, by simp⟩
  | 47 :: rest => .ok ⟨'/', [47], rest, rfl, by simp⟩
  | 98 :: rest => .ok ⟨Char.ofNat 8, [98], rest, rfl, by simp⟩
  | 102 :: rest => .ok ⟨Char.ofNat 12, [102], rest, rfl, by simp⟩
  | 110 :: rest => .ok ⟨Char.ofNat 10, [110], rest, rfl, by simp⟩
  | 114 :: rest => .ok ⟨Char.ofNat 13, [114], rest, rfl, by simp⟩
  | 116 :: rest => .ok ⟨Char.ofNat 9, [116], rest, rfl, by simp⟩
  | 117 :: rest => do
      let read ← unicodeEscape rest
      pure (read.prepend 117)
  | _ => .error ()

def continuation (byte : Nat) : Prop := 128 ≤ byte ∧ byte < 192
instance (byte : Nat) : Decidable (continuation byte) := inferInstanceAs (Decidable (_ ∧ _))

def utf8 : (input : Bytes) → Except Unit (Consumed input Char)
  | [] => .error ()
  | first :: rest =>
      if ascii : first < 128 then
        .ok ⟨Char.ofNatAux first (Or.inl (by omega)), [first], rest, rfl, by simp⟩
      else if two : 194 ≤ first ∧ first < 224 then
        match rest with
        | second :: tail =>
            if next : continuation second then
              let scalar := (first - 192) * 64 + (second - 128)
              have valid : scalar.isValidChar := Or.inl (by unfold scalar continuation at *; omega)
              .ok ⟨Char.ofNatAux scalar valid, [first, second], tail, rfl, by simp⟩
            else .error ()
        | [] => .error ()
      else if three : 224 ≤ first ∧ first < 240 then
        match rest with
        | second :: third :: tail =>
            if next : continuation second ∧ continuation third then
              let scalar := (first - 224) * 4096 + (second - 128) * 64 + (third - 128)
              if valid : 2048 ≤ scalar ∧ scalar.isValidChar then
                .ok ⟨Char.ofNatAux scalar valid.2, [first, second, third], tail, rfl, by simp⟩
              else .error ()
            else .error ()
        | _ => .error ()
      else if four : 240 ≤ first ∧ first < 245 then
        match rest with
        | second :: third :: fourth :: tail =>
            if next : continuation second ∧ continuation third ∧ continuation fourth then
              let scalar := (first - 240) * 262144 + (second - 128) * 4096 + (third - 128) * 64 + (fourth - 128)
              if valid : 65536 ≤ scalar ∧ scalar.isValidChar then
                .ok ⟨Char.ofNatAux scalar valid.2, [first, second, third, fourth], tail, rfl, by simp⟩
              else .error ()
            else .error ()
        | _ => .error ()
      else .error ()

def scalarResult {input : Bytes} (read : Except Unit (Consumed input Char)) : Except Unit (Char × Bytes) :=
  read.map (fun result => (result.value, result.rest))

/-- One JSON string content character. The quote terminator is handled by
the enclosing reader; raw controls/quotes are refused here. -/
def stringScalar : (input : Bytes) → Except Unit (Consumed input Char)
  | [] => .error ()
  | first :: rest =>
      if first = 92 then do
        let decoded ← escape rest
        pure (decoded.prepend first)
      else if first < 32 ∨ first = 34 then .error () else utf8 (first :: rest)

theorem scalar_result_earns_original_read {input : Bytes} (parser : Except Unit (Consumed input Char))
    (character : Char) (rest : Bytes) (read : scalarResult parser = .ok (character, rest)) :
    ∃ parsed, parser = .ok parsed ∧ parsed.value = character ∧ parsed.rest = rest := by
  cases parser with
  | error error => simp [scalarResult] at read
  | ok parsed =>
      simp [scalarResult] at read
      exact ⟨parsed, rfl, read.1, read.2⟩

theorem hex_digit_value_bounded (input : Nat) (output : Fin 16) (read : hexDigit input = .ok output) :
    output.val < 16 := output.isLt

theorem hex_word_value_bounded (input : Bytes) (output : Consumed input (Fin 65536))
    (read : hex4 input = .ok output) : output.value.val < 65536 := output.value.isLt

theorem unicode_escape_consumes_original (input : Bytes) (output : Consumed input Char)
    (read : unicodeEscape input = .ok output) : input = output.prefix ++ output.rest := output.original

theorem utf8_consumes_original (input : Bytes) (output : Consumed input Char)
    (read : utf8 input = .ok output) : input = output.prefix ++ output.rest := output.original

theorem utf8_strict_progress (input : Bytes) (output : Consumed input Char)
    (read : utf8 input = .ok output) : output.rest.length < input.length := consumed_strict_progress output

theorem escape_strict_progress (input : Bytes) (output : Consumed input Char)
    (read : escape input = .ok output) : output.rest.length < input.length := consumed_strict_progress output

end Auths.Product.JsonStringScalars
