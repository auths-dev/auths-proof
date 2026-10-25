import Auths.Product.SerdeLongScratch

/-!
Closed float_roundtrip long-number control flow. All original scratch bytes,
split positions and remaining input reach their actual model continuations.
The long exponent tests every scratch digit for zero; it never substitutes a
rounded or truncated significand. FromParts is the original lexical call's
arguments, not successful conversion. Native read/cursor/loop/formatting/usize/
lexical/float/visitor and feature adequacy remain separate requirements.
-/
namespace Auths.Product.SerdeLongNumberStage
abbrev Bytes := List Nat
abbrev Parts := SerdeLongScratch.Parts

inductive Next where
  | eofNoDigits
  | invalidFirstExponentDigit
  | invalidNoFractionDigit
  | numberOutOfRange
  | signedZero (positive : Bool)
  | fromParts (positive : Bool) (scratch : Bytes) (integerEnd : Nat) (exponent : Int) (remaining : Bytes)
  deriving DecidableEq

structure Read (input : Bytes) where
  prefix : Bytes
  rest : Bytes
  next : Next
  original : input = prefix ++ rest

def prepend (prefix : Bytes) {input : Bytes} (read : Read input) : Read (prefix ++ input) :=
  ⟨prefix ++ read.prefix, read.rest, read.next, by rw [read.original, List.append_assoc]⟩

def zeroSignificand (scratch : Bytes) : Bool := scratch.all (fun byte => decide (byte = 48))

def signedExponent (positiveExponent : Bool) (magnitude : Nat) : Int :=
  if positiveExponent then Int.ofNat magnitude else -Int.ofNat magnitude

def overflowNext : SerdeExponentOverflow.Outcome → Next
  | .numberOutOfRange => .numberOutOfRange
  | .signedZero positive => .signedZero positive

def exponentAfterDigits {initial : Nat} {input : Bytes} (positive : Bool) (parts : Parts)
    (positiveExponent : Bool) (loop : SerdeExponentDigits.Scanned initial input) : Read input :=
  match loop.trigger with
  | none =>
      ⟨SerdeExponentDigits.consumed loop, loop.rest,
        .fromParts positive parts.scratch parts.integerEnd (signedExponent positiveExponent loop.value) loop.rest, loop.original⟩
  | some _ =>
      let helper := SerdeExponentOverflow.parse positive (zeroSignificand parts.scratch) positiveExponent loop.rest
      ⟨SerdeExponentDigits.consumed loop ++ helper.prefix, helper.rest, overflowNext helper.outcome,
        by rw [loop.original, helper.original, List.append_assoc]⟩

def exponentAfterSign (positive : Bool) (parts : Parts) (positiveExponent : Bool) : (input : Bytes) → Read input
  | [] => ⟨[], [], .eofNoDigits, rfl⟩
  | first :: rest =>
      if decimal : JsonNumberLexeme.digit first = true then
        have bounded : first - 48 ≤ SerdeExponentDigits.maximum := by
          have ascii : 48 ≤ first ∧ first ≤ 57 := by
            simpa only [JsonNumberLexeme.digit, decide_eq_true_eq] using decimal
          unfold SerdeExponentDigits.maximum
          omega
        prepend [first] (exponentAfterDigits positive parts positiveExponent (SerdeExponentDigits.scan (first - 48) bounded rest))
      else ⟨[first], rest, .invalidFirstExponentDigit, rfl⟩

def exponent (positive : Bool) (parts : Parts) (inputAfterMarker : Bytes) : Read inputAfterMarker :=
  let sign := SerdeExponentStage.readSign inputAfterMarker
  let suffix := exponentAfterSign positive parts sign.positive sign.rest
  ⟨sign.prefix ++ suffix.prefix, suffix.rest, suffix.next,
    by rw [sign.original, suffix.original, List.append_assoc]⟩

def appendFraction (parts : Parts) (digits : Bytes) : Parts :=
  ⟨parts.scratch ++ digits, parts.integerEnd, by
    have bounded := parts.bounded
    simp only [List.length_append]
    omega⟩

def fractionPresent (parts : Parts) (digits : Bytes) : Bool :=
  decide (parts.integerEnd < parts.scratch.length ∨ digits ≠ [])

def decimal (positive : Bool) (parts : Parts) (inputAfterDot : Bytes) : Read inputAfterDot :=
  let digits := SerdeExponentOverflow.skipDigits inputAfterDot
  let appended := appendFraction parts digits.prefix
  if fractionPresent parts digits.prefix = true then
    match restAt : digits.rest with
    | marker :: afterMarker =>
        if marker = 69 ∨ marker = 101 then
          let suffix := exponent positive appended afterMarker
          ⟨digits.prefix ++ (marker :: suffix.prefix), suffix.rest, suffix.next,
            by rw [digits.original, restAt, suffix.original]; simp only [List.cons_append, List.append_assoc]⟩
        else
          ⟨digits.prefix, digits.rest, .fromParts positive appended.scratch appended.integerEnd 0 digits.rest, digits.original⟩
    | [] =>
        ⟨digits.prefix, digits.rest, .fromParts positive appended.scratch appended.integerEnd 0 digits.rest, digits.original⟩
  else
    ⟨digits.prefix, digits.rest, if digits.rest = [] then .eofNoDigits else .invalidNoFractionDigit, digits.original⟩

def integer (positive : Bool) (partial : Nat) (input : Bytes) : Read input :=
  let prepared := SerdeLongScratch.integer partial input
  match restAt : prepared.loop.rest with
  | marker :: afterMarker =>
      if marker = 46 then
        let suffix := decimal positive prepared.parts afterMarker
        ⟨prepared.loop.prefix ++ (marker :: suffix.prefix), suffix.rest, suffix.next,
          by rw [prepared.loop.original, restAt, suffix.original]; simp only [List.cons_append, List.append_assoc]⟩
      else if marker = 69 ∨ marker = 101 then
        let suffix := exponent positive prepared.parts afterMarker
        ⟨prepared.loop.prefix ++ (marker :: suffix.prefix), suffix.rest, suffix.next,
          by rw [prepared.loop.original, restAt, suffix.original]; simp only [List.cons_append, List.append_assoc]⟩
      else
        ⟨prepared.loop.prefix, prepared.loop.rest,
          .fromParts positive prepared.parts.scratch prepared.parts.integerEnd 0 prepared.loop.rest, prepared.loop.original⟩
  | [] =>
      ⟨prepared.loop.prefix, prepared.loop.rest,
        .fromParts positive prepared.parts.scratch prepared.parts.integerEnd 0 prepared.loop.rest, prepared.loop.original⟩

def decimalOverflow (positive : Bool) (significand fractionDigits : Nat) (input : Bytes) : Read input :=
  decimal positive (SerdeLongScratch.decimal significand fractionDigits) input

def exponentView (positive : Bool) (parts : Parts) (input : Bytes) : Bytes × Bytes × Next :=
  let read := exponent positive parts input
  (read.prefix, read.rest, read.next)

def decimalView (positive : Bool) (parts : Parts) (input : Bytes) : Bytes × Bytes × Next :=
  let read := decimal positive parts input
  (read.prefix, read.rest, read.next)

def integerView (positive : Bool) (partial : Nat) (input : Bytes) : Bytes × Bytes × Next :=
  let read := integer positive partial input
  (read.prefix, read.rest, read.next)

theorem scratch_zero_test_visits_every_original_digit (scratch : Bytes) :
    zeroSignificand scratch = true ↔ ∀ byte ∈ scratch, byte = 48 := by
  simp [zeroSignificand, List.all_eq_true]

theorem any_original_nonzero_digit_prevents_zero_branch (scratch : Bytes) (byte : Nat) (present : byte ∈ scratch) (nonzero : byte ≠ 48) :
    zeroSignificand scratch = false := by
  cases selected : zeroSignificand scratch with
  | false => rfl
  | true => exact False.elim (nonzero ((scratch_zero_test_visits_every_original_digit scratch).mp selected byte present))

theorem signed_long_exponent_fits_source_i32 (positiveExponent : Bool) (magnitude : Nat) (bounded : magnitude ≤ SerdeExponentDigits.maximum) :
    -2147483647 ≤ signedExponent positiveExponent magnitude ∧ signedExponent positiveExponent magnitude ≤ 2147483647 := by
  unfold signedExponent SerdeExponentDigits.maximum at *
  cases positiveExponent <;> simp only [Bool.false_eq_true, ↓reduceIte] <;> omega

theorem ordinary_long_exponent_keeps_complete_conversion_arguments {initial : Nat} {input : Bytes} (positive : Bool) (parts : Parts)
    (positiveExponent : Bool) (loop : SerdeExponentDigits.Scanned initial input) (ordinary : loop.trigger = none) :
    (exponentAfterDigits positive parts positiveExponent loop).next =
      .fromParts positive parts.scratch parts.integerEnd (signedExponent positiveExponent loop.value) loop.rest ∧
      parts.integer ++ parts.fraction = parts.scratch := by
  exact ⟨by simp only [exponentAfterDigits, ordinary], (SerdeLongScratch.original_parts_keep_entire_scratch parts).1⟩

theorem overflowing_long_exponent_uses_original_scratch_zero_test {initial : Nat} {input : Bytes} (positive : Bool) (parts : Parts)
    (positiveExponent : Bool) (loop : SerdeExponentDigits.Scanned initial input) (trigger : Nat) (blocked : loop.trigger = some trigger) :
    let helper := SerdeExponentOverflow.parse positive (zeroSignificand parts.scratch) positiveExponent loop.rest
    (exponentAfterDigits positive parts positiveExponent loop).prefix = SerdeExponentDigits.consumed loop ++ helper.prefix ∧
      (exponentAfterDigits positive parts positiveExponent loop).rest = helper.rest ∧
      (exponentAfterDigits positive parts positiveExponent loop).next = overflowNext helper.outcome := by
  simp only [exponentAfterDigits, blocked, and_self]

theorem long_exponent_keeps_complete_original (positive : Bool) (parts : Parts) (input : Bytes) :
    input = (exponent positive parts input).prefix ++ (exponent positive parts input).rest := (exponent positive parts input).original

theorem appended_fraction_keeps_all_original_parts (parts : Parts) (digits : Bytes) :
    (appendFraction parts digits).scratch = parts.scratch ++ digits ∧
      (appendFraction parts digits).integerEnd = parts.integerEnd ∧
      (appendFraction parts digits).integer ++ (appendFraction parts digits).fraction = parts.scratch ++ digits := by
  exact ⟨rfl, rfl, (SerdeLongScratch.original_parts_keep_entire_scratch (appendFraction parts digits)).1⟩

theorem original_or_new_fraction_digit_earns_presence (parts : Parts) (digits : Bytes) :
    fractionPresent parts digits = true ↔ parts.integerEnd < parts.scratch.length ∨ digits ≠ [] := by
  simp only [fractionPresent, decide_eq_true_eq]

theorem absent_original_and_new_fraction_has_precise_refusal (positive : Bool) (parts : Parts) (input : Bytes)
    (noOriginal : parts.integerEnd = parts.scratch.length) (noNew : (SerdeExponentOverflow.skipDigits input).prefix = []) :
    (decimal positive parts input).prefix = [] ∧ (decimal positive parts input).rest = input ∧
      (decimal positive parts input).next = if input = [] then .eofNoDigits else .invalidNoFractionDigit := by
  have original : (SerdeExponentOverflow.skipDigits input).rest = input := by
    simpa only [noNew, List.nil_append] using (SerdeExponentOverflow.skipDigits input).original.symm
  simp [decimal, fractionPresent, noOriginal, noNew, original]

theorem long_decimal_keeps_complete_original (positive : Bool) (parts : Parts) (input : Bytes) :
    input = (decimal positive parts input).prefix ++ (decimal positive parts input).rest := (decimal positive parts input).original

theorem long_integer_keeps_complete_original (positive : Bool) (partial : Nat) (input : Bytes) :
    input = (integer positive partial input).prefix ++ (integer positive partial input).rest := (integer positive partial input).original

theorem bounded_append_has_original_input_size (parts : Parts) (input : Bytes) :
    (appendFraction parts (SerdeExponentOverflow.skipDigits input).prefix).scratch.length ≤ parts.scratch.length + input.length := by
  have originalLengths := congrArg List.length (SerdeExponentOverflow.skipDigits input).original
  simp only [List.length_append] at originalLengths
  simp only [appendFraction, List.length_append]
  omega

theorem positive_nonzero_long_exponent_overflow_refuses_after_trigger {initial : Nat} {input : Bytes}
    (positive : Bool) (parts : Parts) (loop : SerdeExponentDigits.Scanned initial input) (trigger : Nat)
    (blocked : loop.trigger = some trigger) (nonzero : zeroSignificand parts.scratch = false) :
    (exponentAfterDigits positive parts true loop).prefix = SerdeExponentDigits.consumed loop ∧
      (exponentAfterDigits positive parts true loop).rest = loop.rest ∧
      (exponentAfterDigits positive parts true loop).next = .numberOutOfRange := by
  simp [exponentAfterDigits, blocked, nonzero, SerdeExponentOverflow.parse, overflowNext]

theorem negative_long_exponent_overflow_consumes_all_remaining_digits {initial : Nat} {input : Bytes}
    (positive : Bool) (parts : Parts) (loop : SerdeExponentDigits.Scanned initial input) (trigger : Nat)
    (blocked : loop.trigger = some trigger) :
    (exponentAfterDigits positive parts false loop).prefix =
        SerdeExponentDigits.consumed loop ++ (SerdeExponentOverflow.skipDigits loop.rest).prefix ∧
      (exponentAfterDigits positive parts false loop).rest = (SerdeExponentOverflow.skipDigits loop.rest).rest ∧
      (exponentAfterDigits positive parts false loop).next = .signedZero positive := by
  simp [exponentAfterDigits, blocked, SerdeExponentOverflow.parse, overflowNext]

private theorem overflowing_partial_is_nonzero (value : Nat) (rest : Bytes)
    (boundary : SerdeUnsignedDigits.Boundary .overflow value rest) : value ≠ 0 := by
  cases rest with
  | nil => exact False.elim boundary
  | cons byte tail =>
      change JsonNumberLexeme.digit byte = true ∧ SerdeUnsignedDigits.overflow value (byte - 48) = true at boundary
      have ascii : 48 ≤ byte ∧ byte ≤ 57 := by
        simpa only [JsonNumberLexeme.digit, decide_eq_true_eq] using boundary.1
      have exceeds := (SerdeUnsignedDigits.overflow_earns_exact_arithmetic value (byte - 48) (by omega)).mp boundary.2
      unfold SerdeUnsignedDigits.maximum at exceeds
      intro zero
      subst value
      omega

private theorem all_zero_digits_have_zero_value (bytes : Bytes) (allZero : ∀ byte ∈ bytes, byte = 48) :
    DecimalProjection.readDigits bytes = 0 := by
  revert allZero
  induction bytes with
  | nil => intro _; rfl
  | cons byte rest ih =>
      intro allZero
      have first := allZero byte (by simp)
      have remaining : ∀ next ∈ rest, next = 48 := by intro next present; exact allZero next (List.mem_cons_of_mem byte present)
      simp only [DecimalProjection.readDigits, first, Nat.sub_self, Nat.zero_mul, Nat.zero_add]
      exact ih remaining

private theorem rendered_nonzero_prevents_zero_test (value : Nat) (prefix suffix : Bytes) (nonzero : value ≠ 0) :
    zeroSignificand (prefix ++ JcsIntegerDecimal.unsigned value ++ suffix) = false := by
  cases selected : zeroSignificand (prefix ++ JcsIntegerDecimal.unsigned value ++ suffix) with
  | false => rfl
  | true =>
      have allZero := (scratch_zero_test_visits_every_original_digit _).mp selected
      have renderedZero : ∀ byte ∈ JcsIntegerDecimal.unsigned value, byte = 48 := by
        intro byte present
        exact allZero byte (List.mem_append_left suffix (List.mem_append_right prefix present))
      have original := (JcsIntegerDecimal.unsigned_realizes_original_decimal value).2.2.1
      have zeroValue := all_zero_digits_have_zero_value (JcsIntegerDecimal.unsigned value) renderedZero
      exact False.elim (nonzero (by omega))

theorem integer_overflow_scratch_earns_nonzero_test {positive : Bool} {input : Bytes} (call : SerdeLongScratch.IntegerCall positive input) :
    zeroSignificand (SerdeLongScratch.prepareInteger call).parts.scratch = false := by
  have boundary : SerdeUnsignedDigits.Boundary .overflow call.partial call.read.rest := by
    simpa only [call.overflowed, SerdeIntegerStage.Boundary] using call.read.boundary
  have nonzero := overflowing_partial_is_nonzero call.partial call.read.rest boundary
  rw [(SerdeLongScratch.prepareInteger call).scratchSource]
  simpa only [List.nil_append] using rendered_nonzero_prevents_zero_test call.partial [] (SerdeLongScratch.prepareInteger call).loop.prefix nonzero

theorem decimal_overflow_scratch_earns_nonzero_test {positive : Bool} {initial : Nat} {input : Bytes}
    {read : SerdeDecimalStage.Read positive initial 0 input} (call : SerdeLongScratch.DecimalCall read) :
    zeroSignificand (SerdeLongScratch.prepareDecimal call).scratch = false := by
  have boundary : SerdeUnsignedDigits.Boundary .overflow read.loop.value read.loop.rest := by
    simpa only [call.overflowed] using read.loop.boundary
  have nonzero := overflowing_partial_is_nonzero read.loop.value read.loop.rest boundary
  change zeroSignificand (SerdeLongScratch.decimalBytes read.loop.value read.loop.prefix.length) = false
  rw [SerdeLongScratch.decimal_scratch_keeps_exact_padding]
  simpa only [List.append_nil] using rendered_nonzero_prevents_zero_test read.loop.value
    (List.replicate (read.loop.prefix.length - (JcsIntegerDecimal.unsigned read.loop.value).length) 48) [] nonzero

theorem appending_fraction_preserves_original_nonzero_test (parts : Parts) (digits : Bytes) (nonzero : zeroSignificand parts.scratch = false) :
    zeroSignificand (appendFraction parts digits).scratch = false := by
  change zeroSignificand (parts.scratch ++ digits) = false
  simp only [zeroSignificand, List.all_append] at *
  rw [nonzero]
  rfl

theorem decimal_overflow_append_has_single_original_source_bound {positive : Bool} {initial : Nat} {input : Bytes}
    {read : SerdeDecimalStage.Read positive initial 0 input} (call : SerdeLongScratch.DecimalCall read) :
    (appendFraction (SerdeLongScratch.prepareDecimal call) (SerdeExponentOverflow.skipDigits read.loop.rest).prefix).scratch.length ≤ 20 + input.length := by
  have width := SerdeLongScratch.full_word_decimal_width_is_bounded read.loop.value read.loop.bounded
  have preparedLength := SerdeLongScratch.decimal_scratch_has_exact_length read.loop.value read.loop.prefix.length
  have originalLengths := congrArg List.length read.loop.original
  have remainingLengths := congrArg List.length (SerdeExponentOverflow.skipDigits read.loop.rest).original
  simp only [List.length_append] at originalLengths remainingLengths
  change (SerdeLongScratch.decimalBytes read.loop.value read.loop.prefix.length ++
    (SerdeExponentOverflow.skipDigits read.loop.rest).prefix).length ≤ 20 + input.length
  simp only [List.length_append]
  omega

def runIntegerCall {positive : Bool} {input : Bytes} (call : SerdeLongScratch.IntegerCall positive input) : Read call.read.rest :=
  integer positive call.partial call.read.rest

theorem composed_integer_overflow_keeps_complete_original {positive : Bool} {input : Bytes} (call : SerdeLongScratch.IntegerCall positive input) :
    input = call.read.prefix ++ (runIntegerCall call).prefix ++ (runIntegerCall call).rest := by
  rw [call.read.original, (runIntegerCall call).original, List.append_assoc]

def runDecimalCall {positive : Bool} {initial : Nat} {input : Bytes}
    {read : SerdeDecimalStage.Read positive initial 0 input} (_call : SerdeLongScratch.DecimalCall read) : Read read.loop.rest :=
  decimalOverflow positive read.loop.value read.loop.prefix.length read.loop.rest

theorem composed_decimal_overflow_keeps_complete_original {positive : Bool} {initial : Nat} {input : Bytes}
    {read : SerdeDecimalStage.Read positive initial 0 input} (call : SerdeLongScratch.DecimalCall read) :
    46 :: input = (46 :: read.loop.prefix) ++ (runDecimalCall call).prefix ++ (runDecimalCall call).rest := by
  have original := (SerdeDecimalStage.decimal_read_keeps_complete_original read).1
  rw [original, (runDecimalCall call).original, List.append_assoc]

end Auths.Product.SerdeLongNumberStage
