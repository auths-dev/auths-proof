import Auths.Product.SerdeIntegerStage

/-!
Closed decimal-stage composition after the caller's dot. Exact checked digit
accumulation earns the negative fractional exponent counter and continuation
arguments. An overflowing FIRST fractional digit reaches decimal-overflow
conversion before the empty-fraction check, still unread. No float bits or
successful floating helper are supplied or fabricated. Native read/loop/i32/
floating/helper/visitor and complete parser adequacy remain outer obligations.
-/
namespace Auths.Product.SerdeDecimalStage
abbrev Bytes := List Nat

inductive Next where
  | eofNoDigits | invalidNoDigits
  | decimalOverflow (positive : Bool) (significand : Nat) (exponent : Int) (remaining : Bytes)
  | exponent (positive : Bool) (significand : Nat) (exponent : Int) (remaining : Bytes)
  | fromParts (positive : Bool) (significand : Nat) (exponent : Int) (remaining : Bytes)
  deriving DecidableEq

def afterCounter {initial : Nat} {input : Bytes} (loop : SerdeUnsignedDigits.Scanned initial input) : Int :=
  -Int.ofNat loop.prefix.length

def choose {initial : Nat} {input : Bytes} (positive : Bool) (before : Int)
    (loop : SerdeUnsignedDigits.Scanned initial input) : Next :=
  let exponent := before + afterCounter loop
  match loop.mode with
  | .overflow => .decimalOverflow positive loop.value exponent loop.rest
  | .stopped =>
      if loop.prefix = [] then if loop.rest = [] then .eofNoDigits else .invalidNoDigits
      else if loop.rest.head? = some 69 ∨ loop.rest.head? = some 101 then .exponent positive loop.value exponent loop.rest
      else .fromParts positive loop.value exponent loop.rest

structure Read (positive : Bool) (initial : Nat) (before : Int) (inputAfterDot : Bytes) where
  loop : SerdeUnsignedDigits.Scanned initial inputAfterDot
  next : Next
  selected : next = choose positive before loop
  scanned : ∀ bounded : initial ≤ SerdeUnsignedDigits.maximum,
    loop = SerdeUnsignedDigits.scan initial bounded inputAfterDot

def parse (positive : Bool) (initial : Nat) (bounded : initial ≤ SerdeUnsignedDigits.maximum)
    (before : Int) (inputAfterDot : Bytes) : Read positive initial before inputAfterDot :=
  let loop := SerdeUnsignedDigits.scan initial bounded inputAfterDot
  ⟨loop, choose positive before loop, rfl, by intro other; rfl⟩

def view (positive : Bool) (initial : Nat) (bounded : initial ≤ SerdeUnsignedDigits.maximum)
    (before : Int) (inputAfterDot : Bytes) : Bytes × Bytes × Next :=
  let read := parse positive initial bounded before inputAfterDot
  (46 :: read.loop.prefix, read.loop.rest, read.next)

theorem decimal_read_keeps_complete_original {positive : Bool} {initial : Nat} {before : Int} {input : Bytes}
    (read : Read positive initial before input) :
    46 :: input = (46 :: read.loop.prefix) ++ read.loop.rest ∧ read.loop.rest.length < (46 :: input).length :=
  SerdeUnsignedDigits.loop_after_original_first_byte_earns_progress 46 read.loop

theorem decimal_read_earns_original_loop {positive : Bool} {initial : Nat} {before : Int} {input : Bytes}
    (read : Read positive initial before input) (bounded : initial ≤ SerdeUnsignedDigits.maximum) :
    read.loop = SerdeUnsignedDigits.scan initial bounded input := read.scanned bounded

theorem fractional_prefix_earns_exact_word_and_counter {positive : Bool} {initial : Nat} {before : Int} {input : Bytes}
    (read : Read positive initial before input) :
    read.loop.value ≤ SerdeUnsignedDigits.maximum ∧
      read.loop.value = SerdeUnsignedDigits.accumulate initial read.loop.prefix ∧
      afterCounter read.loop = -Int.ofNat read.loop.prefix.length := ⟨read.loop.bounded, read.loop.meaning, rfl⟩

theorem fractional_counter_has_original_input_bounds {positive : Bool} {initial : Nat} {before : Int} {input : Bytes}
    (read : Read positive initial before input) :
    -Int.ofNat input.length ≤ afterCounter read.loop ∧ afterCounter read.loop ≤ 0 := by
  have lengths := congrArg List.length read.loop.original
  simp only [List.length_append] at lengths
  unfold afterCounter
  omega

theorem bounded_original_fraction_counters_fit_i32 {positive : Bool} {initial : Nat} {before : Int} {input : Bytes}
    (read : Read positive initial before input) (inputBound : input.length ≤ 65536) (beforeBound : 0 ≤ before ∧ before ≤ 65536) :
    (-2147483648 ≤ afterCounter read.loop ∧ afterCounter read.loop ≤ 2147483647) ∧
      (-2147483648 ≤ before + afterCounter read.loop ∧ before + afterCounter read.loop ≤ 2147483647) := by
  have fractional := fractional_counter_has_original_input_bounds read
  omega

theorem every_completed_fraction_counter_fits_i32 {positive : Bool} {initial : Nat} {before : Int} {input : Bytes}
    (read : Read positive initial before input) (inputBound : input.length ≤ 65536) (beforeBound : 0 ≤ before ∧ before ≤ 65536)
    (consumed : Nat) (prefixBound : consumed ≤ read.loop.prefix.length) :
    (-2147483648 ≤ -Int.ofNat consumed ∧ -Int.ofNat consumed ≤ 2147483647) ∧
      (-2147483648 ≤ before - Int.ofNat consumed ∧ before - Int.ofNat consumed ≤ 2147483647) := by
  have lengths := congrArg List.length read.loop.original
  simp only [List.length_append] at lengths
  omega

theorem overflow_precedes_empty_fraction_check {positive : Bool} {initial : Nat} {before : Int} {input : Bytes}
    (read : Read positive initial before input) (overflowed : read.loop.mode = .overflow) :
    read.next = .decimalOverflow positive read.loop.value (before + afterCounter read.loop) read.loop.rest := by
  rw [read.selected]
  simp only [choose, overflowed]

theorem overflow_keeps_original_digit_and_partial_word {positive : Bool} {initial : Nat} {before : Int} {input : Bytes}
    (read : Read positive initial before input) (overflowed : read.loop.mode = .overflow) :
    ∃ byte rest, read.loop.rest = byte :: rest ∧ JsonNumberLexeme.digit byte = true ∧
      SerdeUnsignedDigits.maximum < read.loop.value * 10 + (byte - 48) ∧ input = read.loop.prefix ++ byte :: rest :=
  SerdeUnsignedDigits.overflow_keeps_original_unconsumed_digit read.loop overflowed

theorem empty_fraction_has_precise_initial_refusal {positive : Bool} {initial : Nat} {before : Int} {input : Bytes}
    (read : Read positive initial before input) (stopped : read.loop.mode = .stopped) (empty : read.loop.prefix = []) :
    read.next = if read.loop.rest = [] then .eofNoDigits else .invalidNoDigits := by
  rw [read.selected]
  simp only [choose, stopped, empty, if_pos rfl]

theorem exponent_handoff_keeps_original_arguments {positive : Bool} {initial : Nat} {before : Int} {input : Bytes}
    (read : Read positive initial before input) (stopped : read.loop.mode = .stopped) (nonempty : read.loop.prefix ≠ [])
    (marker : read.loop.rest.head? = some 69 ∨ read.loop.rest.head? = some 101) :
    read.next = .exponent positive read.loop.value (before + afterCounter read.loop) read.loop.rest := by
  rw [read.selected]
  simp only [choose, stopped, if_neg nonempty, if_pos marker]

theorem parts_handoff_keeps_original_arguments {positive : Bool} {initial : Nat} {before : Int} {input : Bytes}
    (read : Read positive initial before input) (stopped : read.loop.mode = .stopped) (nonempty : read.loop.prefix ≠ [])
    (notExponent : ¬ (read.loop.rest.head? = some 69 ∨ read.loop.rest.head? = some 101)) :
    read.next = .fromParts positive read.loop.value (before + afterCounter read.loop) read.loop.rest := by
  rw [read.selected]
  simp only [choose, stopped, if_neg nonempty, if_neg notExponent]

structure FromInteger (positive : Bool) (input : Bytes) where
  integer : SerdeIntegerStage.Read input
  integerParsed : SerdeIntegerStage.parse input = integer
  significand : Nat
  afterDot : Bytes
  remaining : integer.rest = 46 :: afterDot
  called : SerdeIntegerStage.continueNumber positive integer = .decimal positive significand 0 (46 :: afterDot)
  decimal : Read positive significand 0 afterDot

def fromInteger (positive : Bool) (input : Bytes) : Option (FromInteger positive input) :=
  let integer := SerdeIntegerStage.parse input
  match numberAt : integer.outcome with
  | .number significand =>
      match restAt : integer.rest with
      | 46 :: afterDot =>
          have bounded : significand ≤ SerdeUnsignedDigits.maximum :=
            (SerdeIntegerStage.successful_stage_earns_exact_partial_word integer significand (Or.inl numberAt)).1
          some ⟨integer, rfl, significand, afterDot, restAt,
            by simp [SerdeIntegerStage.continueNumber, numberAt, restAt], parse positive significand bounded 0 afterDot⟩
      | _ => none
  | _ => none

theorem composed_integer_decimal_keeps_original_call {positive : Bool} {input : Bytes} (read : FromInteger positive input) :
    SerdeIntegerStage.parse input = read.integer ∧
      SerdeIntegerStage.continueNumber positive read.integer = .decimal positive read.significand 0 (46 :: read.afterDot) :=
  ⟨read.integerParsed, read.called⟩

theorem composed_integer_decimal_keeps_complete_original {positive : Bool} {input : Bytes} (read : FromInteger positive input) :
    input = read.integer.prefix ++ (46 :: read.decimal.loop.prefix) ++ read.decimal.loop.rest ∧
      read.decimal.loop.rest.length < input.length := by
  have decimalOriginal := decimal_read_keeps_complete_original read.decimal
  have lengths := congrArg List.length read.integer.original
  simp only [read.remaining, List.length_append, List.length_cons] at lengths
  refine ⟨?_, by have progress := decimalOriginal.2; simp only [List.length_cons] at progress; omega⟩
  calc
    input = read.integer.prefix ++ read.integer.rest := read.integer.original
    _ = read.integer.prefix ++ (46 :: read.afterDot) := by rw [read.remaining]
    _ = read.integer.prefix ++ ((46 :: read.decimal.loop.prefix) ++ read.decimal.loop.rest) :=
      congrArg (fun rest => read.integer.prefix ++ rest) decimalOriginal.1
    _ = read.integer.prefix ++ (46 :: read.decimal.loop.prefix) ++ read.decimal.loop.rest := by rw [List.append_assoc]

theorem composed_original_input_bound_earns_all_fraction_i32_counters {positive : Bool} {input : Bytes}
    (read : FromInteger positive input) (inputBound : input.length ≤ 65536)
    (consumed : Nat) (prefixBound : consumed ≤ read.decimal.loop.prefix.length) :
    -2147483648 ≤ -Int.ofNat consumed ∧ -Int.ofNat consumed ≤ 2147483647 := by
  have integerLengths := congrArg List.length read.integer.original
  have decimalLengths := congrArg List.length read.decimal.loop.original
  simp only [read.remaining, List.length_append, List.length_cons] at integerLengths
  simp only [List.length_append] at decimalLengths
  omega

end Auths.Product.SerdeDecimalStage
