import Auths.Product.SerdeExponentStage
import Auths.Product.SerdeDecimalStage

/-!
Actual closed-model caller composition. These optional direct lanes do not
classify absence as a whole-number parse refusal; long-number helpers remain
separate. Every exponent read is computed from the original caller remainder.
No successful native decoding, floating helper, or expected float is assumed.
-/
namespace Auths.Product.SerdeExponentComposition
abbrev Bytes := List Nat

structure FromInteger (positive : Bool) (input : Bytes) where
  integer : SerdeIntegerStage.Read input
  integerParsed : SerdeIntegerStage.parse input = integer
  significand : Nat
  marker : Nat
  afterMarker : Bytes
  valid : marker = 69 ∨ marker = 101
  remaining : integer.rest = marker :: afterMarker
  called : SerdeIntegerStage.continueNumber positive integer = .exponent positive significand 0 (marker :: afterMarker)

def fromInteger (positive : Bool) (input : Bytes) : Option (FromInteger positive input) :=
  let integer := SerdeIntegerStage.parse input
  match numberAt : integer.outcome with
  | .number significand =>
      match restAt : integer.rest with
      | marker :: afterMarker =>
          if valid : marker = 69 ∨ marker = 101 then
            some ⟨integer, rfl, significand, marker, afterMarker, valid, restAt,
              by rcases valid with upper | lower
                 · simp [SerdeIntegerStage.continueNumber, numberAt, restAt, upper]
                 · simp [SerdeIntegerStage.continueNumber, numberAt, restAt, lower]⟩
          else none
      | [] => none
  | _ => none

def runInteger {positive : Bool} {input : Bytes} (call : FromInteger positive input) : SerdeExponentStage.Read call.afterMarker :=
  SerdeExponentStage.parse positive call.significand 0 call.afterMarker

theorem integer_call_earns_actual_original_continuation {positive : Bool} {input : Bytes} (call : FromInteger positive input) :
    SerdeIntegerStage.parse input = call.integer ∧
      SerdeIntegerStage.continueNumber positive call.integer = .exponent positive call.significand 0 (call.marker :: call.afterMarker) ∧
      runInteger call = SerdeExponentStage.parse positive call.significand 0 call.afterMarker :=
  ⟨call.integerParsed, call.called, rfl⟩

theorem integer_exponent_keeps_complete_original {positive : Bool} {input : Bytes} (call : FromInteger positive input) :
    input = call.integer.prefix ++ (call.marker :: (runInteger call).prefix) ++ (runInteger call).rest ∧
      (runInteger call).rest.length < input.length := by
  have original : input = call.integer.prefix ++ (call.marker :: (runInteger call).prefix) ++ (runInteger call).rest := by
    calc
      input = call.integer.prefix ++ call.integer.rest := call.integer.original
      _ = call.integer.prefix ++ (call.marker :: call.afterMarker) := by rw [call.remaining]
      _ = call.integer.prefix ++ (call.marker :: ((runInteger call).prefix ++ (runInteger call).rest)) := by
        rw [← (runInteger call).original]
      _ = call.integer.prefix ++ (call.marker :: (runInteger call).prefix) ++ (runInteger call).rest := by
        simp only [List.cons_append, List.append_assoc]
  have lengths := congrArg List.length original
  simp only [List.length_append, List.length_cons] at lengths
  exact ⟨original, by omega⟩

structure FromDecimal {positive : Bool} {initial : Nat} {before : Int} {input : Bytes}
    (decimal : SerdeDecimalStage.Read positive initial before input) where
  marker : Nat
  afterMarker : Bytes
  valid : marker = 69 ∨ marker = 101
  remaining : decimal.loop.rest = marker :: afterMarker
  called : decimal.next = .exponent positive decimal.loop.value (before + SerdeDecimalStage.afterCounter decimal.loop) (marker :: afterMarker)

def fromDecimal {positive : Bool} {initial : Nat} {before : Int} {input : Bytes}
    (decimal : SerdeDecimalStage.Read positive initial before input) : Option (FromDecimal decimal) :=
  if stopped : decimal.loop.mode = .stopped then
    if nonempty : decimal.loop.prefix ≠ [] then
      match restAt : decimal.loop.rest with
      | marker :: afterMarker =>
          if valid : marker = 69 ∨ marker = 101 then
            have markerAt : decimal.loop.rest.head? = some 69 ∨ decimal.loop.rest.head? = some 101 := by
              rcases valid with upper | lower
              · simp [restAt, upper]
              · simp [restAt, lower]
            some ⟨marker, afterMarker, valid, restAt,
              by simpa only [restAt] using SerdeDecimalStage.exponent_handoff_keeps_original_arguments decimal stopped nonempty markerAt⟩
          else none
      | [] => none
    else none
  else none

def runDecimal {positive : Bool} {initial : Nat} {before : Int} {input : Bytes}
    {decimal : SerdeDecimalStage.Read positive initial before input} (call : FromDecimal decimal) : SerdeExponentStage.Read call.afterMarker :=
  SerdeExponentStage.parse positive decimal.loop.value (before + SerdeDecimalStage.afterCounter decimal.loop) call.afterMarker

theorem decimal_call_earns_actual_original_continuation {positive : Bool} {initial : Nat} {before : Int} {input : Bytes}
    {decimal : SerdeDecimalStage.Read positive initial before input} (call : FromDecimal decimal)
    (bounded : initial ≤ SerdeUnsignedDigits.maximum) :
    decimal.loop = SerdeUnsignedDigits.scan initial bounded input ∧
      decimal.next = .exponent positive decimal.loop.value (before + SerdeDecimalStage.afterCounter decimal.loop) (call.marker :: call.afterMarker) ∧
      runDecimal call = SerdeExponentStage.parse positive decimal.loop.value
        (before + SerdeDecimalStage.afterCounter decimal.loop) call.afterMarker :=
  ⟨decimal.scanned bounded, call.called, rfl⟩

theorem decimal_exponent_keeps_complete_original {positive : Bool} {initial : Nat} {before : Int} {input : Bytes}
    {decimal : SerdeDecimalStage.Read positive initial before input} (call : FromDecimal decimal) :
    46 :: input = (46 :: decimal.loop.prefix) ++ (call.marker :: (runDecimal call).prefix) ++ (runDecimal call).rest ∧
      (runDecimal call).rest.length < (46 :: input).length := by
  have original : 46 :: input = (46 :: decimal.loop.prefix) ++ (call.marker :: (runDecimal call).prefix) ++ (runDecimal call).rest := by
    calc
      46 :: input = (46 :: decimal.loop.prefix) ++ decimal.loop.rest := (SerdeDecimalStage.decimal_read_keeps_complete_original decimal).1
      _ = (46 :: decimal.loop.prefix) ++ (call.marker :: call.afterMarker) := by rw [call.remaining]
      _ = (46 :: decimal.loop.prefix) ++ (call.marker :: ((runDecimal call).prefix ++ (runDecimal call).rest)) := by
        rw [← (runDecimal call).original]
      _ = (46 :: decimal.loop.prefix) ++ (call.marker :: (runDecimal call).prefix) ++ (runDecimal call).rest := by
        simp only [List.cons_append, List.append_assoc]
  have lengths := congrArg List.length original
  simp only [List.length_append, List.length_cons] at lengths
  exact ⟨original, by omega⟩

theorem integer_fraction_exponent_keeps_complete_original {positive : Bool} {input : Bytes}
    (fraction : SerdeDecimalStage.FromInteger positive input) (call : FromDecimal fraction.decimal) :
    input = fraction.integer.prefix ++ ((46 :: fraction.decimal.loop.prefix) ++
      (call.marker :: (runDecimal call).prefix)) ++ (runDecimal call).rest ∧
      (runDecimal call).rest.length < input.length := by
  have fractionOriginal := (SerdeDecimalStage.composed_integer_decimal_keeps_complete_original fraction).1
  have original : input = fraction.integer.prefix ++ ((46 :: fraction.decimal.loop.prefix) ++
      (call.marker :: (runDecimal call).prefix)) ++ (runDecimal call).rest := by
    calc
      input = fraction.integer.prefix ++ (46 :: fraction.decimal.loop.prefix) ++ fraction.decimal.loop.rest := fractionOriginal
      _ = fraction.integer.prefix ++ (46 :: fraction.decimal.loop.prefix) ++ (call.marker :: call.afterMarker) := by rw [call.remaining]
      _ = fraction.integer.prefix ++ (46 :: fraction.decimal.loop.prefix) ++
          (call.marker :: ((runDecimal call).prefix ++ (runDecimal call).rest)) := by rw [← (runDecimal call).original]
      _ = fraction.integer.prefix ++ ((46 :: fraction.decimal.loop.prefix) ++
          (call.marker :: (runDecimal call).prefix)) ++ (runDecimal call).rest := by
        simp only [List.cons_append, List.append_assoc]
  have lengths := congrArg List.length original
  simp only [List.length_append, List.length_cons] at lengths
  exact ⟨original, by omega⟩

end Auths.Product.SerdeExponentComposition
