import Auths.Product.SerdeExponentComposition

/-!
Closed scratch preparation for the enabled float_roundtrip long-number path.
Decimal overflow restores fractional leading zeroes lost by u64 accumulation,
then splits at the original decimal position. Integer overflow extends the
original partial word with every remaining integer digit. Decimal formatting,
native checked_sub/usize/allocation and lexical floating conversion adequacy
are separate: these are expected complete buffer/argument laws, not float bits.
-/
namespace Auths.Product.SerdeLongScratch
abbrev Bytes := List Nat

def checkedPadding (width fractionDigits : Nat) : Nat :=
  if width + 1 ≤ fractionDigits then (fractionDigits - (width + 1)) + 1 else 0

def decimalBytes (significand fractionDigits : Nat) : Bytes :=
  List.replicate (checkedPadding (JcsIntegerDecimal.unsigned significand).length fractionDigits) 48 ++
    JcsIntegerDecimal.unsigned significand

def decimalEnd (significand fractionDigits : Nat) : Nat :=
  (decimalBytes significand fractionDigits).length - fractionDigits

structure Parts where
  scratch : Bytes
  integerEnd : Nat
  bounded : integerEnd ≤ scratch.length

def Parts.integer (parts : Parts) : Bytes := parts.scratch.take parts.integerEnd
def Parts.fraction (parts : Parts) : Bytes := parts.scratch.drop parts.integerEnd

def decimal (significand fractionDigits : Nat) : Parts :=
  ⟨decimalBytes significand fractionDigits, decimalEnd significand fractionDigits, Nat.sub_le _ _⟩

theorem source_checked_padding_is_exact (width fractionDigits : Nat) :
    checkedPadding width fractionDigits = fractionDigits - width := by
  unfold checkedPadding
  split <;> omega

theorem full_word_decimal_width_is_bounded (significand : Nat) (bounded : significand ≤ SerdeUnsignedDigits.maximum) :
    (JcsIntegerDecimal.unsigned significand).length ≤ 20 := by
  simp only [JcsIntegerDecimal.unsigned, List.length_map]
  apply JcsIntegerDecimal.digits_length_bounded_by_power 20 significand (by decide)
  have maximumSmall : SerdeUnsignedDigits.maximum < 10 ^ 20 := by decide
  omega

theorem decimal_scratch_keeps_exact_padding (significand fractionDigits : Nat) :
    decimalBytes significand fractionDigits =
      List.replicate (fractionDigits - (JcsIntegerDecimal.unsigned significand).length) 48 ++ JcsIntegerDecimal.unsigned significand := by
  simp only [decimalBytes, source_checked_padding_is_exact]

theorem decimal_scratch_has_exact_length (significand fractionDigits : Nat) :
    (decimalBytes significand fractionDigits).length = max fractionDigits (JcsIntegerDecimal.unsigned significand).length := by
  rw [decimal_scratch_keeps_exact_padding]
  simp only [List.length_append, List.length_replicate]
  omega

theorem original_decimal_split_never_underflows (significand fractionDigits : Nat) :
    fractionDigits ≤ (decimalBytes significand fractionDigits).length ∧
      decimalEnd significand fractionDigits = (JcsIntegerDecimal.unsigned significand).length - fractionDigits := by
  have size := decimal_scratch_has_exact_length significand fractionDigits
  unfold decimalEnd
  omega

theorem original_parts_keep_entire_scratch (parts : Parts) :
    parts.integer ++ parts.fraction = parts.scratch ∧ parts.integer.length = parts.integerEnd := by
  exact ⟨List.take_append_drop _ _, by simpa only [Parts.integer, List.length_take] using Nat.min_eq_left parts.bounded⟩

theorem decimal_parts_keep_exact_fraction_count (significand fractionDigits : Nat) :
    (decimal significand fractionDigits).fraction.length = fractionDigits ∧
      (decimal significand fractionDigits).integer.length = (JcsIntegerDecimal.unsigned significand).length - fractionDigits := by
  have enough := original_decimal_split_never_underflows significand fractionDigits
  have size := decimal_scratch_has_exact_length significand fractionDigits
  simp only [decimal, Parts.fraction, Parts.integer, List.length_drop, List.length_take, decimalEnd]
  omega

private theorem zero_padding_keeps_value (count : Nat) (bytes : Bytes) :
    DecimalProjection.readDigits (List.replicate count 48 ++ bytes) = DecimalProjection.readDigits bytes := by
  induction count with
  | zero => rfl
  | succ count ih =>
      simpa only [List.replicate_succ, List.cons_append, DecimalProjection.readDigits, Nat.sub_self, Nat.zero_mul, Nat.zero_add] using ih

theorem decimal_scratch_keeps_original_partial_word (significand fractionDigits : Nat) :
    DecimalProjection.readDigits (decimalBytes significand fractionDigits) = significand := by
  rw [decimalBytes, zero_padding_keeps_value]
  exact (JcsIntegerDecimal.unsigned_realizes_original_decimal significand).2.2.1

theorem bounded_source_fraction_earns_scratch_size (significand fractionDigits : Nat)
    (wordBound : significand ≤ SerdeUnsignedDigits.maximum) (inputBound : fractionDigits ≤ 65536) :
    (decimalBytes significand fractionDigits).length ≤ 65536 ∧ decimalEnd significand fractionDigits ≤ 20 := by
  have width := full_word_decimal_width_is_bounded significand wordBound
  have size := decimal_scratch_has_exact_length significand fractionDigits
  have split := original_decimal_split_never_underflows significand fractionDigits
  omega

structure IntegerRead (partial : Nat) (input : Bytes) where
  loop : SerdeExponentOverflow.Digits input
  scanned : loop = SerdeExponentOverflow.skipDigits input
  parts : Parts
  scratchSource : parts.scratch = JcsIntegerDecimal.unsigned partial ++ loop.prefix
  splitSource : parts.integerEnd = parts.scratch.length

def integer (partial : Nat) (input : Bytes) : IntegerRead partial input :=
  let loop := SerdeExponentOverflow.skipDigits input
  let scratch := JcsIntegerDecimal.unsigned partial ++ loop.prefix
  ⟨loop, rfl, ⟨scratch, scratch.length, Nat.le_refl _⟩, rfl, rfl⟩

theorem long_integer_keeps_original_digits_and_partial_word {partial : Nat} {input : Bytes} (read : IntegerRead partial input) :
    read.loop = SerdeExponentOverflow.skipDigits input ∧ input = read.loop.prefix ++ read.loop.rest ∧
      read.parts.scratch = JcsIntegerDecimal.unsigned partial ++ read.loop.prefix ∧
      read.parts.integerEnd = read.parts.scratch.length :=
  ⟨read.scanned, read.loop.original, read.scratchSource, read.splitSource⟩

theorem long_integer_has_no_invented_fraction {partial : Nat} {input : Bytes} (read : IntegerRead partial input) :
    read.parts.integer = read.parts.scratch ∧ read.parts.fraction = [] := by
  simp only [Parts.integer, Parts.fraction, read.splitSource, List.take_length, List.drop_length, and_self]

theorem long_integer_scratch_is_bounded_by_original_input {partial : Nat} {input : Bytes} (read : IntegerRead partial input)
    (wordBound : partial ≤ SerdeUnsignedDigits.maximum) :
    read.parts.scratch.length ≤ 20 + input.length := by
  have width := full_word_decimal_width_is_bounded partial wordBound
  have inputLengths := congrArg List.length read.loop.original
  have scratchLengths := congrArg List.length read.scratchSource
  simp only [List.length_append] at inputLengths scratchLengths
  omega

structure IntegerCall (positive : Bool) (input : Bytes) where
  read : SerdeIntegerStage.Read input
  parsed : SerdeIntegerStage.parse input = read
  partial : Nat
  overflowed : read.outcome = .longInteger partial

def fromInteger (positive : Bool) (input : Bytes) : Option (IntegerCall positive input) :=
  let read := SerdeIntegerStage.parse input
  match selected : read.outcome with
  | .longInteger partial => some ⟨read, rfl, partial, selected⟩
  | _ => none

def prepareInteger {positive : Bool} {input : Bytes} (call : IntegerCall positive input) : IntegerRead call.partial call.read.rest :=
  integer call.partial call.read.rest

theorem integer_overflow_earns_original_preparation_call {positive : Bool} {input : Bytes} (call : IntegerCall positive input) :
    SerdeIntegerStage.parse input = call.read ∧
      SerdeIntegerStage.continueNumber positive call.read = .longInteger positive call.partial call.read.rest ∧
      call.partial ≤ SerdeUnsignedDigits.maximum ∧ call.partial = SerdeUnsignedDigits.accumulate 0 call.read.prefix :=
  ⟨call.parsed, SerdeIntegerStage.long_integer_continuation_keeps_original_arguments call.read positive call.partial call.overflowed,
    SerdeIntegerStage.successful_stage_earns_exact_partial_word call.read call.partial (Or.inr call.overflowed)⟩

theorem integer_overflow_keeps_complete_original_input {positive : Bool} {input : Bytes} (call : IntegerCall positive input) :
    input = call.read.prefix ++ (prepareInteger call).loop.prefix ++ (prepareInteger call).loop.rest := by
  rw [call.read.original, (prepareInteger call).loop.original, List.append_assoc]

theorem integer_overflow_preparation_has_original_size_bound {positive : Bool} {input : Bytes} (call : IntegerCall positive input) :
    (prepareInteger call).parts.scratch.length ≤ 20 + input.length := by
  have wordBound := (SerdeIntegerStage.successful_stage_earns_exact_partial_word call.read call.partial (Or.inr call.overflowed)).1
  have scratchBound := long_integer_scratch_is_bounded_by_original_input (prepareInteger call) wordBound
  have inputLengths := congrArg List.length call.read.original
  simp only [List.length_append] at inputLengths
  omega

structure DecimalCall {positive : Bool} {initial : Nat} {input : Bytes}
    (read : SerdeDecimalStage.Read positive initial 0 input) where
  overflowed : read.loop.mode = .overflow

def fromDecimal {positive : Bool} {initial : Nat} {input : Bytes}
    (read : SerdeDecimalStage.Read positive initial 0 input) : Option (DecimalCall read) :=
  if selected : read.loop.mode = .overflow then some ⟨selected⟩ else none

def prepareDecimal {positive : Bool} {initial : Nat} {input : Bytes}
    {read : SerdeDecimalStage.Read positive initial 0 input} (_call : DecimalCall read) : Parts :=
  decimal read.loop.value read.loop.prefix.length

theorem decimal_overflow_earns_original_preparation_call {positive : Bool} {initial : Nat} {input : Bytes}
    {read : SerdeDecimalStage.Read positive initial 0 input} (call : DecimalCall read) :
    read.next = .decimalOverflow positive read.loop.value (-Int.ofNat read.loop.prefix.length) read.loop.rest ∧
      (prepareDecimal call).scratch = decimalBytes read.loop.value read.loop.prefix.length ∧
      (prepareDecimal call).fraction.length = read.loop.prefix.length := by
  refine ⟨?_, rfl, (decimal_parts_keep_exact_fraction_count read.loop.value read.loop.prefix.length).1⟩
  simpa only [SerdeDecimalStage.afterCounter, Int.zero_add] using
    SerdeDecimalStage.overflow_precedes_empty_fraction_check read call.overflowed

theorem decimal_overflow_preparation_has_original_size_bound {positive : Bool} {initial : Nat} {input : Bytes}
    {read : SerdeDecimalStage.Read positive initial 0 input} (call : DecimalCall read) (inputBound : input.length ≤ 65536) :
    (prepareDecimal call).scratch.length ≤ 65536 ∧ (prepareDecimal call).integerEnd ≤ 20 := by
  have inputLengths := congrArg List.length read.loop.original
  simp only [List.length_append] at inputLengths
  exact bounded_source_fraction_earns_scratch_size read.loop.value read.loop.prefix.length read.loop.bounded (by omega)

end Auths.Product.SerdeLongScratch
