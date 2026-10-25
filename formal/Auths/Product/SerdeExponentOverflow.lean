import Auths.Product.SerdeExponentMath

/-!
Closed overflow-helper control flow after the triggering exponent digit has
already been consumed. Positive exponent/nonzero significand refuses without
consuming the remaining digits. Other paths consume the complete digit suffix
and return the source's signed-zero case. No arbitrary float conversion/bit
result or helper success is supplied; native cursor/primitive/helper adequacy
and exact literal floating representation remain separate requirements.
-/
namespace Auths.Product.SerdeExponentOverflow
abbrev Bytes := List Nat

def Stopped : Bytes → Prop
  | [] => True
  | byte :: _ => JsonNumberLexeme.digit byte = false

structure Digits (input : Bytes) where
  prefix : Bytes
  rest : Bytes
  original : input = prefix ++ rest
  each : ∀ byte ∈ prefix, JsonNumberLexeme.digit byte = true
  stopped : Stopped rest

def skipDigits : (input : Bytes) → Digits input
  | [] => ⟨[], [], rfl, by simp, trivial⟩
  | byte :: rest =>
      if decimal : JsonNumberLexeme.digit byte = true then
        let suffix := skipDigits rest
        ⟨byte :: suffix.prefix, suffix.rest, by rw [suffix.original]; rfl,
          by intro next present; rcases List.mem_cons.mp present with rfl | later
             · exact decimal
             · exact suffix.each next later,
          suffix.stopped⟩
      else
        have stopped : JsonNumberLexeme.digit byte = false := by cases selected : JsonNumberLexeme.digit byte <;> simp_all
        ⟨[], byte :: rest, rfl, by simp, stopped⟩

inductive Outcome where
  | numberOutOfRange
  | signedZero (positive : Bool)
  deriving DecidableEq

structure Read (input : Bytes) where
  prefix : Bytes
  rest : Bytes
  outcome : Outcome
  original : input = prefix ++ rest

def parse (positive zeroSignificand positiveExponent : Bool) (input : Bytes) : Read input :=
  if zeroSignificand = false ∧ positiveExponent = true then
    ⟨[], input, .numberOutOfRange, rfl⟩
  else
    let suffix := skipDigits input
    ⟨suffix.prefix, suffix.rest, .signedZero positive, suffix.original⟩

def view (positive zeroSignificand positiveExponent : Bool) (input : Bytes) : Bytes × Bytes × Outcome :=
  let read := parse positive zeroSignificand positiveExponent input
  (read.prefix, read.rest, read.outcome)

theorem skipped_digits_keep_complete_original (input : Bytes) :
    input = (skipDigits input).prefix ++ (skipDigits input).rest ∧
      (∀ byte ∈ (skipDigits input).prefix, JsonNumberLexeme.digit byte = true) ∧ Stopped (skipDigits input).rest :=
  ⟨(skipDigits input).original, (skipDigits input).each, (skipDigits input).stopped⟩

theorem positive_nonzero_overflow_refuses_before_remaining_digits (positive : Bool) (input : Bytes) :
    (parse positive false true input).prefix = [] ∧ (parse positive false true input).rest = input ∧
      (parse positive false true input).outcome = .numberOutOfRange := by simp [parse]

theorem zero_or_negative_exponent_consumes_exact_digits (positive zeroSignificand positiveExponent : Bool)
    (input : Bytes) (allowed : ¬ (zeroSignificand = false ∧ positiveExponent = true)) :
    (parse positive zeroSignificand positiveExponent input).prefix = (skipDigits input).prefix ∧
      (parse positive zeroSignificand positiveExponent input).rest = (skipDigits input).rest ∧
      (parse positive zeroSignificand positiveExponent input).outcome = .signedZero positive := by
  simp [parse, allowed]

theorem overflow_helper_keeps_original_slice (positive zeroSignificand positiveExponent : Bool) (input : Bytes) :
    input = (parse positive zeroSignificand positiveExponent input).prefix ++ (parse positive zeroSignificand positiveExponent input).rest :=
  (parse positive zeroSignificand positiveExponent input).original

theorem overflow_helper_range_refusal_exact (positive zeroSignificand positiveExponent : Bool) (input : Bytes) :
    (parse positive zeroSignificand positiveExponent input).outcome = .numberOutOfRange ↔
      zeroSignificand = false ∧ positiveExponent = true := by
  unfold parse
  split <;> simp_all

end Auths.Product.SerdeExponentOverflow
