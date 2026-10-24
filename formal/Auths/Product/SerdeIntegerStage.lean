import Auths.Product.SerdeUnsignedDigits
import Auths.Product.SerdeSignedWord

/-!
Closed initial-integer stage and numeric continuation reference. The caller
has already consumed an optional minus. Empty/invalid starts and leading zero
retain their distinct original consumed/rest snapshots. Fraction/exponent and
long-integer continuations carry their ORIGINAL callee input and partial word;
they are not successful floating results. Native read/cursor/primitive/helper/
visitor adequacy, diagnostics and complete serde correspondence remain open.
-/
namespace Auths.Product.SerdeIntegerStage
abbrev Bytes := List Nat

inductive Outcome where
  | eof | invalidStart | leadingZero | number (value : Nat) | longInteger (partialWord : Nat)
  deriving DecidableEq

def firstIsDigit : Bytes → Bool
  | [] => false
  | byte :: _ => JsonNumberLexeme.digit byte

def fromDigits : SerdeUnsignedDigits.Mode → Nat → Outcome
  | .stopped, value => .number value
  | .overflow, value => .longInteger value

def Payload : Outcome → Bytes → Prop
  | .number value, prefix | .longInteger value, prefix =>
      value ≤ SerdeUnsignedDigits.maximum ∧ value = SerdeUnsignedDigits.accumulate 0 prefix
  | _, _ => True

def Boundary : Outcome → Bytes → Bytes → Prop
  | .eof, prefix, rest => prefix = [] ∧ rest = []
  | .invalidStart, prefix, _ => ∃ byte, prefix = [byte] ∧ byte ≠ 48 ∧ ¬ (49 ≤ byte ∧ byte ≤ 57)
  | .leadingZero, prefix, rest => prefix = [48] ∧ firstIsDigit rest = true
  | .number value, _, rest => SerdeUnsignedDigits.Boundary .stopped value rest
  | .longInteger value, _, rest => SerdeUnsignedDigits.Boundary .overflow value rest

structure Read (input : Bytes) where
  prefix : Bytes
  rest : Bytes
  outcome : Outcome
  original : input = prefix ++ rest
  nonempty : outcome ≠ .eof → prefix ≠ []
  payload : Payload outcome prefix
  boundary : Boundary outcome prefix rest

def parse : (input : Bytes) → Read input
  | [] => ⟨[], [], .eof, rfl, by intro impossible; exact False.elim (impossible rfl), trivial, ⟨rfl, rfl⟩⟩
  | byte :: rest =>
      if zero : byte = 48 then
        if repeated : firstIsDigit rest = true then
          ⟨[byte], rest, .leadingZero, rfl, by intro _; simp, trivial, ⟨by simp [zero], repeated⟩⟩
        else
          have stopped : SerdeUnsignedDigits.Boundary .stopped 0 rest := by
            cases rest <;> simp_all [firstIsDigit, SerdeUnsignedDigits.Boundary]
          ⟨[byte], rest, .number 0, rfl, by intro _; simp,
            by simp [Payload, zero, SerdeUnsignedDigits.accumulate, SerdeUnsignedDigits.maximum], stopped⟩
      else if nonzero : 49 ≤ byte ∧ byte ≤ 57 then
        let loop := SerdeUnsignedDigits.scan (byte - 48) (by unfold SerdeUnsignedDigits.maximum; omega) rest
        ⟨byte :: loop.prefix, loop.rest, fromDigits loop.mode loop.value,
          by rw [loop.original]; rfl,
          by intro _; simp,
          by
            have meaning : loop.value = SerdeUnsignedDigits.accumulate 0 (byte :: loop.prefix) := by
              simpa only [SerdeUnsignedDigits.accumulate, List.foldl_cons, Nat.zero_mul, Nat.zero_add] using loop.meaning
            cases loop.mode <;> exact ⟨loop.bounded, meaning⟩,
          by cases original : loop.mode <;> simpa only [fromDigits, Boundary, original] using loop.boundary⟩
      else
        ⟨[byte], rest, .invalidStart, rfl, by intro _; simp, trivial, ⟨byte, rfl, zero, nonzero⟩⟩

def view (input : Bytes) : Bytes × Bytes × Outcome :=
  let read := parse input
  (read.prefix, read.rest, read.outcome)

inductive Continuation where
  | error (reason : Outcome)
  | decimal (positive : Bool) (significand : Nat) (exponent : Int) (remaining : Bytes)
  | exponent (positive : Bool) (significand : Nat) (exponent : Int) (remaining : Bytes)
  | longInteger (positive : Bool) (partialWord : Nat) (remaining : Bytes)
  | unsigned (value : Nat)
  | signed (value : Int)
  | negativeFloatCast (originalUnsigned : Nat)
  deriving DecidableEq

def wordContinuation (positive : Bool) (value : Nat) : Continuation :=
  if positive then .unsigned value else
    match SerdeSignedWord.dispatch value with
    | .signed negative => .signed negative
    | .floatingMagnitude original => .negativeFloatCast original

def continueNumber {input : Bytes} (positive : Bool) (read : Read input) : Continuation :=
  match read.outcome with
  | .eof => .error .eof
  | .invalidStart => .error .invalidStart
  | .leadingZero => .error .leadingZero
  | .longInteger partialWord => .longInteger positive partialWord read.rest
  | .number value =>
      if read.rest.head? = some 46 then .decimal positive value 0 read.rest
      else if read.rest.head? = some 69 ∨ read.rest.head? = some 101 then .exponent positive value 0 read.rest
      else wordContinuation positive value

theorem initial_stage_keeps_complete_original (input : Bytes) : input = (parse input).prefix ++ (parse input).rest :=
  (parse input).original

theorem non_eof_stage_earns_progress {input : Bytes} (read : Read input) (present : read.outcome ≠ .eof) :
    read.rest.length < input.length := by
  have original := congrArg List.length read.original
  have nonempty := read.nonempty present
  have positive : 0 < read.prefix.length := by cases prefixAt : read.prefix <;> simp_all
  simp only [List.length_append] at original
  omega

theorem leading_zero_retains_original_offending_digit {input : Bytes} (read : Read input)
    (refused : read.outcome = .leadingZero) :
    ∃ byte rest, read.prefix = [48] ∧ read.rest = byte :: rest ∧ JsonNumberLexeme.digit byte = true ∧ input = 48 :: byte :: rest := by
  have edge : read.prefix = [48] ∧ firstIsDigit read.rest = true := by simpa only [refused, Boundary] using read.boundary
  cases original : read.rest with
  | nil => simp [original, firstIsDigit] at edge
  | cons byte rest =>
      refine ⟨byte, rest, edge.1, original, by simpa only [original, firstIsDigit] using edge.2, ?_⟩
      simpa only [edge.1, original, List.singleton_append] using read.original

/-- Relative byte offset for these initial-stage error cases. Leading zero
uses the capped peek position; consumed-start/EOF errors use the consumed
position. Original leading whitespace/minus and line/column mapping are outer
reader concerns. This does not model deferred floating-helper errors. -/
def errorOffset {input : Bytes} (read : Read input) : Nat :=
  if read.outcome = .leadingZero then min input.length (read.prefix.length + 1) else read.prefix.length

theorem leading_zero_earns_distinct_consumed_and_peek_offsets {input : Bytes} (read : Read input)
    (refused : read.outcome = .leadingZero) : read.prefix.length = 1 ∧ errorOffset read = 2 := by
  obtain ⟨byte, rest, prefixAt, remainingAt, digitAt, inputAt⟩ := leading_zero_retains_original_offending_digit read refused
  simp only [prefixAt, List.length_singleton, errorOffset, refused, if_pos rfl, inputAt, List.length_cons]
  omega

theorem successful_stage_earns_exact_partial_word {input : Bytes} (read : Read input) (value : Nat)
    (number : read.outcome = .number value ∨ read.outcome = .longInteger value) :
    value ≤ SerdeUnsignedDigits.maximum ∧ value = SerdeUnsignedDigits.accumulate 0 read.prefix := by
  rcases number with accepted | overflowed
  · simpa only [accepted, Payload] using read.payload
  · simpa only [overflowed, Payload] using read.payload

theorem long_integer_continuation_keeps_original_arguments {input : Bytes} (read : Read input) (positive : Bool) (partialWord : Nat)
    (overflowed : read.outcome = .longInteger partialWord) :
    continueNumber positive read = .longInteger positive partialWord read.rest := by simp [continueNumber, overflowed]

theorem decimal_continuation_keeps_original_arguments {input : Bytes} (read : Read input) (positive : Bool) (value : Nat)
    (number : read.outcome = .number value) (dot : read.rest.head? = some 46) :
    continueNumber positive read = .decimal positive value 0 read.rest := by simp [continueNumber, number, dot]

theorem exponent_continuation_keeps_original_arguments {input : Bytes} (read : Read input) (positive : Bool) (value : Nat)
    (number : read.outcome = .number value) (notDot : read.rest.head? ≠ some 46)
    (marker : read.rest.head? = some 69 ∨ read.rest.head? = some 101) :
    continueNumber positive read = .exponent positive value 0 read.rest := by simp [continueNumber, number, notDot, marker]

theorem negative_float_cast_keeps_original_unsigned (value original : Nat)
    (selected : wordContinuation false value = .negativeFloatCast original) : original = value := by
  cases chosen : SerdeSignedWord.dispatch value with
  | signed negative => simp [wordContinuation, chosen] at selected
  | floatingMagnitude magnitude =>
      have same : magnitude = original := by simpa [wordContinuation, chosen] using selected
      exact same.symm.trans (SerdeSignedWord.dispatch_floating_keeps_unsigned_magnitude value magnitude chosen)

end Auths.Product.SerdeIntegerStage
