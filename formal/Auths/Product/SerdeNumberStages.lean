import Auths.Product.SerdeLongNumberStage

/-!
Composed number-helper control flow for the pinned non-arbitrary-precision,
float_roundtrip path. Every integer/fraction/exponent/long-helper lane is run
from its original caller input. Floating leaves retain all original conversion
arguments and stay pending; this is not native floating success, the enclosing
JSON value visitor, document EOF/error precedence, or serde decoding adequacy.
-/
namespace Auths.Product.SerdeNumberStages
abbrev Bytes := List Nat

inductive Error where
  | eof | invalidInitial | leadingZero | invalidFraction | invalidExponent | numberOutOfRange
  deriving DecidableEq

inductive Next where
  | error (reason : Error)
  | unsigned (value : Nat)
  | signed (value : Int)
  | negativeCast (originalUnsigned : Nat)
  | conciseParts (positive : Bool) (significand : Nat) (exponent : Int) (remaining : Bytes)
  | truncatedParts (positive : Bool) (scratch : Bytes) (integerEnd : Nat) (exponent : Int) (remaining : Bytes)
  | signedZero (positive : Bool)
  deriving DecidableEq

structure Read (input : Bytes) where
  prefix : Bytes
  rest : Bytes
  next : Next
  original : input = prefix ++ rest

def prepend (prefix : Bytes) {input : Bytes} (read : Read input) : Read (prefix ++ input) :=
  ⟨prefix ++ read.prefix, read.rest, read.next, by rw [read.original, List.append_assoc]⟩

def follow {input remaining : Bytes} (prefix : Bytes) (original : input = prefix ++ remaining)
    (read : Read remaining) : Read input :=
  ⟨prefix ++ read.prefix, read.rest, read.next, by rw [original, read.original, List.append_assoc]⟩

def exponentNext : SerdeExponentStage.Next → Next
  | .eofNoDigits => .error .eof
  | .invalidFirstDigit => .error .invalidExponent
  | .fromParts positive significand exponent remaining => .conciseParts positive significand exponent remaining
  | .numberOutOfRange => .error .numberOutOfRange
  | .signedZero positive => .signedZero positive

def fromExponent {input : Bytes} (read : SerdeExponentStage.Read input) : Read input :=
  ⟨read.prefix, read.rest, exponentNext read.next, read.original⟩

def longNext : SerdeLongNumberStage.Next → Next
  | .eofNoDigits => .error .eof
  | .invalidFirstExponentDigit => .error .invalidExponent
  | .invalidNoFractionDigit => .error .invalidFraction
  | .numberOutOfRange => .error .numberOutOfRange
  | .signedZero positive => .signedZero positive
  | .fromParts positive scratch integerEnd exponent remaining => .truncatedParts positive scratch integerEnd exponent remaining

def fromLong {input : Bytes} (read : SerdeLongNumberStage.Read input) : Read input :=
  ⟨read.prefix, read.rest, longNext read.next, read.original⟩

def wordNext (positive : Bool) (value : Nat) : Next :=
  if positive then .unsigned value else
    match SerdeSignedWord.dispatch value with
    | .signed negative => .signed negative
    | .floatingMagnitude original => .negativeCast original

def afterDecimal (positive : Bool) (initial : Nat) (bounded : initial ≤ SerdeUnsignedDigits.maximum)
    (inputAfterDot : Bytes) : Read inputAfterDot :=
  let decimal := SerdeDecimalStage.parse positive initial bounded 0 inputAfterDot
  match decimal.loop.mode with
  | .overflow =>
      follow decimal.loop.prefix decimal.loop.original (fromLong
        (SerdeLongNumberStage.decimalOverflow positive decimal.loop.value decimal.loop.prefix.length decimal.loop.rest))
  | .stopped =>
      if decimal.loop.prefix = [] then
        ⟨decimal.loop.prefix, decimal.loop.rest,
          if decimal.loop.rest = [] then .error .eof else .error .invalidFraction, decimal.loop.original⟩
      else
        match restAt : decimal.loop.rest with
        | marker :: afterMarker =>
            if marker = 69 ∨ marker = 101 then
              let suffix := fromExponent (SerdeExponentStage.parse positive decimal.loop.value (SerdeDecimalStage.afterCounter decimal.loop) afterMarker)
              ⟨decimal.loop.prefix ++ (marker :: suffix.prefix), suffix.rest, suffix.next,
                by rw [decimal.loop.original, restAt, suffix.original]; simp only [List.cons_append, List.append_assoc]⟩
            else
              ⟨decimal.loop.prefix, decimal.loop.rest,
                .conciseParts positive decimal.loop.value (SerdeDecimalStage.afterCounter decimal.loop) decimal.loop.rest, decimal.loop.original⟩
        | [] =>
            ⟨decimal.loop.prefix, decimal.loop.rest,
              .conciseParts positive decimal.loop.value (SerdeDecimalStage.afterCounter decimal.loop) decimal.loop.rest, decimal.loop.original⟩

def afterWord (positive : Bool) (value : Nat) (bounded : value ≤ SerdeUnsignedDigits.maximum) : (remaining : Bytes) → Read remaining
  | [] => ⟨[], [], wordNext positive value, rfl⟩
  | marker :: rest =>
      if marker = 46 then prepend [marker] (afterDecimal positive value bounded rest)
      else if marker = 69 ∨ marker = 101 then prepend [marker] (fromExponent (SerdeExponentStage.parse positive value 0 rest))
      else ⟨[], marker :: rest, wordNext positive value, rfl⟩

def parse (positive : Bool) (inputAfterMinus : Bytes) : Read inputAfterMinus :=
  let integer := SerdeIntegerStage.parse inputAfterMinus
  match selected : integer.outcome with
  | .eof => ⟨integer.prefix, integer.rest, .error .eof, integer.original⟩
  | .invalidStart => ⟨integer.prefix, integer.rest, .error .invalidInitial, integer.original⟩
  | .leadingZero => ⟨integer.prefix, integer.rest, .error .leadingZero, integer.original⟩
  | .number value =>
      have bounded := (SerdeIntegerStage.successful_stage_earns_exact_partial_word integer value (Or.inl selected)).1
      follow integer.prefix integer.original (afterWord positive value bounded integer.rest)
  | .longInteger partial =>
      follow integer.prefix integer.original (fromLong (SerdeLongNumberStage.integer positive partial integer.rest))

def signed (input : Bytes) : Read input :=
  match input with
  | 45 :: rest => prepend [45] (parse false rest)
  | _ => parse true input

def view (input : Bytes) : Bytes × Bytes × Next :=
  let read := signed input
  (read.prefix, read.rest, read.next)

/-- Relative helper error position; the enclosing JSON reader's global line,
whitespace, value-dispatch and document error ordering remain separate. -/
def errorOffset {input : Bytes} (read : Read input) : Nat :=
  if read.next = .error .leadingZero ∨ read.next = .error .invalidFraction then
    min input.length (read.prefix.length + 1)
  else read.prefix.length

theorem composed_number_keeps_complete_original (positive : Bool) (input : Bytes) :
    input = (parse positive input).prefix ++ (parse positive input).rest := (parse positive input).original

theorem original_minus_is_preserved (input : Bytes) :
    (signed (45 :: input)).prefix = 45 :: (parse false input).prefix ∧
      (signed (45 :: input)).rest = (parse false input).rest ∧ (signed (45 :: input)).next = (parse false input).next := by
  simp only [signed, prepend, List.singleton_append, and_self]

theorem signed_number_keeps_complete_original (input : Bytes) :
    input = (signed input).prefix ++ (signed input).rest := (signed input).original

theorem original_input_bounds_every_consumed_and_remaining_byte (input : Bytes) :
    (signed input).prefix.length + (signed input).rest.length = input.length := by
  simpa only [List.length_append] using (congrArg List.length (signed input).original).symm

theorem ordinary_exponent_leaf_keeps_original_conversion (positive : Bool) (significand : Nat) (exponent : Int) (remaining : Bytes) :
    exponentNext (.fromParts positive significand exponent remaining) = .conciseParts positive significand exponent remaining := rfl

theorem long_exponent_leaf_keeps_full_scratch_and_split (positive : Bool) (scratch : Bytes) (integerEnd : Nat) (exponent : Int) (remaining : Bytes) :
    longNext (.fromParts positive scratch integerEnd exponent remaining) = .truncatedParts positive scratch integerEnd exponent remaining := rfl

theorem negative_word_cast_keeps_original_unsigned (value original : Nat) (selected : wordNext false value = .negativeCast original) : original = value := by
  unfold wordNext at selected
  simp only [Bool.false_eq_true, ↓reduceIte] at selected
  cases actual : SerdeSignedWord.dispatch value with
  | signed negative => simp [actual] at selected
  | floatingMagnitude magnitude =>
      have originalValue := SerdeSignedWord.dispatch_floating_keeps_unsigned_magnitude value magnitude actual
      simp only [actual, Next.negativeCast.injEq] at selected
      omega

theorem negative_zero_retains_original_cast_magnitude : wordNext false 0 = .negativeCast 0 := by decide

theorem finite_word_outcome_does_not_consume_original_delimiter (positive : Bool) (value : Nat)
    (bounded : value ≤ SerdeUnsignedDigits.maximum) (marker : Nat) (rest : Bytes)
    (notDot : marker ≠ 46) (notExponent : ¬ (marker = 69 ∨ marker = 101)) :
    (afterWord positive value bounded (marker :: rest)).prefix = [] ∧
      (afterWord positive value bounded (marker :: rest)).rest = marker :: rest ∧
      (afterWord positive value bounded (marker :: rest)).next = wordNext positive value := by
  simp only [afterWord, if_neg notDot, if_neg notExponent, and_self]

end Auths.Product.SerdeNumberStages
