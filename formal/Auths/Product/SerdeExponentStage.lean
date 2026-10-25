import Auths.Product.SerdeExponentOverflow

/-!
The exponent helper after its caller consumes e/E. Optional sign, mandatory
first digit, checked i32 loop, saturation and overflow-helper control flow all
retain the original input. The from-parts continuation is an argument record,
not a successful float conversion. SignedZero records the source branch only;
native float bits, primitives, cursor/read and visitor adequacy remain open.
-/
namespace Auths.Product.SerdeExponentStage
abbrev Bytes := List Nat

structure Sign (input : Bytes) where
  prefix : Bytes
  rest : Bytes
  positive : Bool
  original : input = prefix ++ rest

def readSign : (input : Bytes) → Sign input
  | 43 :: rest => ⟨[43], rest, true, rfl⟩
  | 45 :: rest => ⟨[45], rest, false, rfl⟩
  | input => ⟨[], input, true, rfl⟩

inductive Next where
  | eofNoDigits
  | invalidFirstDigit
  | fromParts (positive : Bool) (significand : Nat) (exponent : Int) (remaining : Bytes)
  | numberOutOfRange
  | signedZero (positive : Bool)
  deriving DecidableEq

def overflowNext : SerdeExponentOverflow.Outcome → Next
  | .numberOutOfRange => .numberOutOfRange
  | .signedZero positive => .signedZero positive

structure Read (input : Bytes) where
  prefix : Bytes
  rest : Bytes
  next : Next
  original : input = prefix ++ rest

def prepend (prefix : Bytes) {input : Bytes} (read : Read input) : Read (prefix ++ input) :=
  ⟨prefix ++ read.prefix, read.rest, read.next, by rw [read.original, List.append_assoc]⟩

def afterDigits {initial : Nat} {input : Bytes} (positive : Bool) (significand : Nat)
    (before : Int) (positiveExponent : Bool) (loop : SerdeExponentDigits.Scanned initial input) : Read input :=
  match loop.trigger with
  | none =>
      ⟨SerdeExponentDigits.consumed loop, loop.rest,
        .fromParts positive significand (SerdeExponentMath.combine before positiveExponent loop.value) loop.rest,
        loop.original⟩
  | some _ =>
      let helper := SerdeExponentOverflow.parse positive (decide (significand = 0)) positiveExponent loop.rest
      ⟨SerdeExponentDigits.consumed loop ++ helper.prefix, helper.rest, overflowNext helper.outcome,
        by rw [loop.original, helper.original, List.append_assoc]⟩

def afterSign (positive : Bool) (significand : Nat) (before : Int) (positiveExponent : Bool) :
    (input : Bytes) → Read input
  | [] => ⟨[], [], .eofNoDigits, rfl⟩
  | first :: rest =>
      if decimal : JsonNumberLexeme.digit first = true then
        have bounded : first - 48 ≤ SerdeExponentDigits.maximum := by
          have ascii : 48 ≤ first ∧ first ≤ 57 := by
            simpa only [JsonNumberLexeme.digit, decide_eq_true_eq] using decimal
          unfold SerdeExponentDigits.maximum
          omega
        prepend [first] (afterDigits positive significand before positiveExponent
          (SerdeExponentDigits.scan (first - 48) bounded rest))
      else
        ⟨[first], rest, .invalidFirstDigit, rfl⟩

def parse (positive : Bool) (significand : Nat) (before : Int) (inputAfterMarker : Bytes) : Read inputAfterMarker :=
  let sign := readSign inputAfterMarker
  let suffix := afterSign positive significand before sign.positive sign.rest
  ⟨sign.prefix ++ suffix.prefix, suffix.rest, suffix.next,
    by rw [sign.original, suffix.original, List.append_assoc]⟩

def view (positive : Bool) (significand : Nat) (before : Int) (inputAfterMarker : Bytes) : Bytes × Bytes × Next :=
  let read := parse positive significand before inputAfterMarker
  (read.prefix, read.rest, read.next)

theorem optional_sign_keeps_original (input : Bytes) :
    input = (readSign input).prefix ++ (readSign input).rest := (readSign input).original

theorem explicit_exponent_signs_keep_exact_suffix (rest : Bytes) :
    (readSign (43 :: rest)).positive = true ∧ (readSign (43 :: rest)).rest = rest ∧
      (readSign (45 :: rest)).positive = false ∧ (readSign (45 :: rest)).rest = rest := by
  simp only [readSign, and_self]

theorem exponent_read_keeps_complete_original (positive : Bool) (significand : Nat) (before : Int) (input : Bytes) :
    input = (parse positive significand before input).prefix ++ (parse positive significand before input).rest :=
  (parse positive significand before input).original

theorem consumed_marker_earns_exponent_progress (marker : Nat) (positive : Bool) (significand : Nat) (before : Int) (input : Bytes) :
    marker :: input = (marker :: (parse positive significand before input).prefix) ++ (parse positive significand before input).rest ∧
      (parse positive significand before input).rest.length < (marker :: input).length := by
  have original := exponent_read_keeps_complete_original positive significand before input
  have lengths := congrArg List.length original
  simp only [List.length_append] at lengths
  exact ⟨congrArg (List.cons marker) original, by simp only [List.length_cons]; omega⟩

theorem absent_first_exponent_digit_refuses (positive : Bool) (significand : Nat) (before : Int) (positiveExponent : Bool) :
    (afterSign positive significand before positiveExponent []).prefix = [] ∧
      (afterSign positive significand before positiveExponent []).next = .eofNoDigits := by simp [afterSign]

theorem invalid_first_exponent_digit_is_consumed (positive : Bool) (significand : Nat) (before : Int)
    (positiveExponent : Bool) (first : Nat) (rest : Bytes) (invalid : JsonNumberLexeme.digit first ≠ true) :
    (afterSign positive significand before positiveExponent (first :: rest)).prefix = [first] ∧
      (afterSign positive significand before positiveExponent (first :: rest)).rest = rest ∧
      (afterSign positive significand before positiveExponent (first :: rest)).next = .invalidFirstDigit := by
  simp only [afterSign, dif_neg invalid, and_self]

theorem mandatory_digit_uses_original_checked_loop (positive : Bool) (significand : Nat) (before : Int)
    (positiveExponent : Bool) (first : Nat) (rest : Bytes) (decimal : JsonNumberLexeme.digit first = true)
    (bounded : first - 48 ≤ SerdeExponentDigits.maximum) :
    afterSign positive significand before positiveExponent (first :: rest) =
      prepend [first] (afterDigits positive significand before positiveExponent
        (SerdeExponentDigits.scan (first - 48) bounded rest)) := by
  simp only [afterSign, dif_pos decimal]

theorem ordinary_exponent_keeps_original_parts {initial : Nat} {input : Bytes} (positive : Bool) (significand : Nat)
    (before : Int) (positiveExponent : Bool) (loop : SerdeExponentDigits.Scanned initial input) (ordinary : loop.trigger = none) :
    (afterDigits positive significand before positiveExponent loop).prefix = SerdeExponentDigits.consumed loop ∧
      (afterDigits positive significand before positiveExponent loop).rest = loop.rest ∧
      (afterDigits positive significand before positiveExponent loop).next =
        .fromParts positive significand (SerdeExponentMath.combine before positiveExponent loop.value) loop.rest := by
  simp only [afterDigits, ordinary, and_self]

theorem ordinary_exponent_earns_i32_continuation {initial : Nat} {input : Bytes} (before : Int) (positiveExponent : Bool)
    (loop : SerdeExponentDigits.Scanned initial input) :
    -2147483648 ≤ SerdeExponentMath.combine before positiveExponent loop.value ∧
      SerdeExponentMath.combine before positiveExponent loop.value ≤ 2147483647 :=
  SerdeExponentMath.combined_exponent_always_has_i32_range before positiveExponent loop.value

theorem overflowing_exponent_calls_exact_helper {initial : Nat} {input : Bytes} (positive : Bool) (significand : Nat)
    (before : Int) (positiveExponent : Bool) (loop : SerdeExponentDigits.Scanned initial input)
    (trigger : Nat) (blocked : loop.trigger = some trigger) :
    let helper := SerdeExponentOverflow.parse positive (decide (significand = 0)) positiveExponent loop.rest
    (afterDigits positive significand before positiveExponent loop).prefix = SerdeExponentDigits.consumed loop ++ helper.prefix ∧
      (afterDigits positive significand before positiveExponent loop).rest = helper.rest ∧
      (afterDigits positive significand before positiveExponent loop).next = overflowNext helper.outcome := by
  simp only [afterDigits, blocked, and_self]

theorem positive_nonzero_exponent_overflow_stops_after_trigger {initial : Nat} {input : Bytes} (positive : Bool)
    (significand : Nat) (before : Int) (loop : SerdeExponentDigits.Scanned initial input)
    (trigger : Nat) (blocked : loop.trigger = some trigger) (nonzero : significand ≠ 0) :
    (afterDigits positive significand before true loop).prefix = SerdeExponentDigits.consumed loop ∧
      (afterDigits positive significand before true loop).rest = loop.rest ∧
      (afterDigits positive significand before true loop).next = .numberOutOfRange := by
  simp [afterDigits, blocked, SerdeExponentOverflow.parse, nonzero, overflowNext]

theorem zero_or_negative_overflow_consumes_only_digit_suffix {initial : Nat} {input : Bytes} (positive : Bool)
    (significand : Nat) (before : Int) (positiveExponent : Bool) (loop : SerdeExponentDigits.Scanned initial input)
    (trigger : Nat) (blocked : loop.trigger = some trigger) (allowed : significand = 0 ∨ positiveExponent = false) :
    (afterDigits positive significand before positiveExponent loop).prefix =
        SerdeExponentDigits.consumed loop ++ (SerdeExponentOverflow.skipDigits loop.rest).prefix ∧
      (afterDigits positive significand before positiveExponent loop).rest = (SerdeExponentOverflow.skipDigits loop.rest).rest ∧
      (afterDigits positive significand before positiveExponent loop).next = .signedZero positive := by
  rcases allowed with zero | negative
  · simp [afterDigits, blocked, SerdeExponentOverflow.parse, zero, overflowNext]
  · simp [afterDigits, blocked, SerdeExponentOverflow.parse, negative, overflowNext]

end Auths.Product.SerdeExponentStage
