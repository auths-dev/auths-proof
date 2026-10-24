import Auths.Product.JcsIntegerRounding
import Auths.Product.DecimalProjection
import Mathlib.Data.List.Basic

/-!
Closed decimal reference for admitted safe integers. The inverse validates
ASCII digits, no leading zero and no negative zero before reading a value.
This defines the expected plain decimal bytes in the admitted domain; it is
not an implementation proof for native Rust casts or ryu-js. In particular,
outside the safe domain an exact mathematical integer's decimal expansion
need not equal the shortest decimal printed for its rounded binary64 value.
-/
namespace Auths.Product.JcsIntegerDecimal

abbrev Bytes := List Nat

def digits (value : Nat) : List Nat :=
  if value < 10 then [value] else digits (value / 10) ++ [value % 10]
termination_by value
decreasing_by exact Nat.div_lt_self (by omega) (by decide)

def digitValue (digits : List Nat) : Nat := digits.foldl (fun previous digit => previous * 10 + digit) 0

def unsigned (value : Nat) : Bytes := (digits value).map (48 + ·)

def signed (value : Int) : Bytes :=
  if value < 0 then 45 :: unsigned value.natAbs else unsigned value.natAbs

def DigitLanguage : Bytes → Prop
  | [] => False
  | first :: rest => 48 ≤ first ∧ first ≤ 57 ∧ (first = 48 → rest = []) ∧
      ∀ byte ∈ rest, 48 ≤ byte ∧ byte ≤ 57

instance (bytes : Bytes) : Decidable (DigitLanguage bytes) := by
  cases bytes <;> unfold DigitLanguage <;> infer_instance

def readUnsigned (bytes : Bytes) : Option Nat :=
  if DigitLanguage bytes then some (digitValue (bytes.map (· - 48))) else none

def readSigned (bytes : Bytes) : Option Int :=
  if bytes.head? = some 45 then do
    let magnitude ← readUnsigned bytes.tail
    if magnitude = 0 then none else some (-Int.ofNat magnitude)
  else (readUnsigned bytes).map Int.ofNat

theorem digits_are_nonempty (value : Nat) : digits value ≠ [] := by
  rw [digits]
  split <;> simp

theorem every_digit_is_decimal (value : Nat) : ∀ digit ∈ digits value, digit < 10 := by
  rw [digits]
  split
  · rename_i small
    simpa only [List.mem_singleton, forall_eq] using small
  · intro digit present
    rcases List.mem_append.mp present with earlier | final
    · exact every_digit_is_decimal (value / 10) digit earlier
    · have same : digit = value % 10 := List.mem_singleton.mp final
      rw [same]
      exact Nat.mod_lt _ (by decide)
termination_by value
decreasing_by exact Nat.div_lt_self (by omega) (by decide)

theorem digits_read_original (value : Nat) : digitValue (digits value) = value := by
  rw [digits]
  split
  · simp [digitValue]
  · have previous := digits_read_original (value / 10)
    have splitValue := Nat.mod_add_div value 10
    simp only [digitValue, List.foldl_append, List.foldl_cons, List.foldl_nil]
    change digitValue (digits (value / 10)) * 10 + value % 10 = value
    rw [previous]
    omega
termination_by value
decreasing_by exact Nat.div_lt_self (by omega) (by decide)

theorem positive_value_has_positive_first_digit (value : Nat) (positive : 0 < value) :
    ∃ first rest, digits value = first :: rest ∧ 0 < first := by
  rw [digits]
  split
  · exact ⟨value, [], rfl, positive⟩
  · have quotient : 0 < value / 10 := by omega
    obtain ⟨first, rest, original, positiveFirst⟩ := positive_value_has_positive_first_digit (value / 10) quotient
    exact ⟨first, rest ++ [value % 10], by simp only [original, List.cons_append], positiveFirst⟩
termination_by value
decreasing_by exact Nat.div_lt_self positive (by decide)

theorem unsigned_bytes_are_decimal (value : Nat) : DigitLanguage (unsigned value) := by
  by_cases zero : value = 0
  · subst value
    simp [unsigned, digits, DigitLanguage]
  · obtain ⟨first, rest, original, positive⟩ := positive_value_has_positive_first_digit value (by omega)
    have firstBound := every_digit_is_decimal value first (by rw [original]; simp)
    rw [unsigned, original, List.map_cons]
    refine ⟨by omega, by omega, ?_, ?_⟩
    · intro impossible; omega
    · intro byte present
      obtain ⟨digit, member, rfl⟩ := List.mem_map.mp present
      have bounded := every_digit_is_decimal value digit (by rw [original]; exact List.mem_cons_of_mem _ member)
      omega

private theorem encoded_digits_inverse (values : List Nat) :
    ((values.map (48 + ·)).map (· - 48)) = values := by
  induction values with
  | nil => rfl
  | cons first rest ih => simp only [List.map_cons, Nat.add_sub_cancel_left, ih]

theorem unsigned_roundtrip (value : Nat) : readUnsigned (unsigned value) = some value := by
  rw [readUnsigned, if_pos (unsigned_bytes_are_decimal value)]
  simp only [unsigned, encoded_digits_inverse, digits_read_original]

theorem accumulator_agrees_with_positional_meaning (bytes : Bytes) (initial : Nat) :
    (bytes.map (· - 48)).foldl (fun previous digit => previous * 10 + digit) initial =
      initial * 10 ^ bytes.length + DecimalProjection.readDigits bytes := by
  induction bytes generalizing initial with
  | nil => simp [DecimalProjection.readDigits]
  | cons first rest ih =>
      simp only [List.map_cons, List.foldl_cons, List.length_cons, DecimalProjection.readDigits]
      rw [ih, Nat.pow_succ]
      ring

theorem digit_reader_agrees_with_positional_meaning (bytes : Bytes) :
    digitValue (bytes.map (· - 48)) = DecimalProjection.readDigits bytes := by
  simpa only [digitValue, Nat.zero_mul, Nat.zero_add] using accumulator_agrees_with_positional_meaning bytes 0

/-- The closed reader earns the existing independent positional decimal
grammar; it does not introduce a second definition of integer meaning. -/
theorem unsigned_reader_earns_original_decimal (bytes : Bytes) (value : Nat)
    (accepted : readUnsigned bytes = some value) : DecimalProjection.Decimal bytes value := by
  unfold readUnsigned at accepted
  split at accepted
  · rename_i language
    have original : digitValue (bytes.map (· - 48)) = value := Option.some.inj accepted
    have represented : DecimalProjection.readDigits bytes = value := by
      rw [← digit_reader_agrees_with_positional_meaning bytes]
      exact original
    cases bytes with
    | nil => exact False.elim language
    | cons first rest =>
        refine ⟨by simp, ?_, represented, ?_⟩
        · intro byte present
          rcases List.mem_cons.mp present with rfl | later
          · exact ⟨language.1, language.2.1⟩
          · exact language.2.2.2 byte later
        · by_cases zero : first = 48
          · left; rw [zero, language.2.2.1 zero]
          · right; exact ⟨first, rest, rfl, by have lower := language.1; omega⟩
  · simp at accepted

theorem unsigned_realizes_original_decimal (value : Nat) : DecimalProjection.Decimal (unsigned value) value :=
  unsigned_reader_earns_original_decimal _ value (unsigned_roundtrip value)

theorem signed_realizes_original_decimal (value : Int) : DecimalProjection.SignedDecimal (signed value) value := by
  by_cases negative : value < 0
  · simp only [signed, DecimalProjection.SignedDecimal, if_pos negative]
    exact ⟨unsigned value.natAbs, rfl, unsigned_realizes_original_decimal value.natAbs⟩
  · simpa only [signed, DecimalProjection.SignedDecimal, if_neg negative] using unsigned_realizes_original_decimal value.natAbs

theorem nonnegative_signed_bytes (value : Nat) : signed (Int.ofNat value) = unsigned value := by simp [signed]

theorem unsigned_bytes_do_not_start_with_minus (value : Nat) : (unsigned value).head? ≠ some 45 := by
  have language := unsigned_bytes_are_decimal value
  cases original : unsigned value with
  | nil => simp [original]
  | cons first rest =>
      rw [original] at language
      intro head
      have same : first = 45 := by simpa only [original, List.head?_cons, Option.some.injEq] using head
      change 48 ≤ first ∧ first ≤ 57 ∧ (first = 48 → rest = []) ∧ _ at language
      omega

theorem signed_roundtrip (value : Int) : readSigned (signed value) = some value := by
  unfold signed
  split
  · rename_i negative
    have nonzero : value.natAbs ≠ 0 := by
      cases value with
      | ofNat magnitude => omega
      | negSucc magnitude => simp
    simp only [readSigned, List.head?_cons, if_pos rfl, List.tail_cons, unsigned_roundtrip, Option.bind_some]
    rw [if_neg nonzero]
    congr 1
    simp [Int.natCast_natAbs, abs_of_neg negative]
  · rename_i nonnegative
    rw [readSigned, if_neg (unsigned_bytes_do_not_start_with_minus value.natAbs), unsigned_roundtrip]
    simp [Int.natCast_natAbs, abs_of_nonneg (by omega : 0 ≤ value)]

theorem unsigned_bytes_are_injective : Function.Injective unsigned := by
  intro first second same
  have parsed := congrArg readUnsigned same
  simpa only [unsigned_roundtrip, Option.some.injEq] using parsed

theorem signed_bytes_are_injective : Function.Injective signed := by
  intro first second same
  have parsed := congrArg readSigned same
  simpa only [signed_roundtrip, Option.some.injEq] using parsed

theorem unsigned_bytes_are_bounded (value : Nat) : ∀ byte ∈ unsigned value, byte < 256 := by
  intro byte present
  obtain ⟨digit, member, rfl⟩ := List.mem_map.mp present
  have bounded := every_digit_is_decimal value digit member
  omega

theorem signed_bytes_are_bounded (value : Int) : ∀ byte ∈ signed value, byte < 256 := by
  unfold signed
  split
  · intro byte present
    rcases List.mem_cons.mp present with rfl | later
    · decide
    · exact unsigned_bytes_are_bounded _ byte later
  · exact unsigned_bytes_are_bounded value.natAbs

theorem digits_length_bounded_by_power (width value : Nat) (positive : 0 < width) (small : value < 10 ^ width) :
    (digits value).length ≤ width := by
  induction width generalizing value with
  | zero => omega
  | succ width ih =>
      rw [digits]
      split
      · simp only [List.length_singleton]; omega
      · rename_i large
        have smaller : value / 10 < 10 ^ width := by
          rw [Nat.pow_succ] at small
          have original := Nat.mod_add_div value 10
          omega
        have widthPositive : 0 < width := by
          cases width with
          | zero => simp at small; omega
          | succ width => omega
        have previous := ih (value / 10) widthPositive smaller
        simp only [List.length_append, List.length_singleton]
        omega

theorem admitted_unsigned_length (value : Nat) (safe : value ≤ 9007199254740991) : (unsigned value).length ≤ 16 := by
  simp only [unsigned, List.length_map]
  apply digits_length_bounded_by_power 16 value (by decide)
  have endpoint : 9007199254740991 < 10 ^ 16 := by decide
  omega

theorem admitted_signed_length (value : Int)
    (safe : -9007199254740991 ≤ value ∧ value ≤ 9007199254740991) : (signed value).length ≤ 17 := by
  have absolute : value.natAbs ≤ 9007199254740991 := by
    cases value with
    | ofNat magnitude => change magnitude ≤ 9007199254740991; omega
    | negSucc magnitude => change magnitude + 1 ≤ 9007199254740991; omega
  have bounded := admitted_unsigned_length value.natAbs absolute
  unfold signed
  split <;> simp only [List.length_cons] <;> omega

/-- In the admitted domain conversion has no effect on these expected decimal
bytes. This does not identify the native cast or ryu output with the model. -/
theorem rounded_signed_keeps_original_decimal (value : Int)
    (safe : -9007199254740991 ≤ value ∧ value ≤ 9007199254740991) :
    signed (JcsIntegerRounding.integer value) = signed value := by
  rw [JcsIntegerRounding.integer_exact_in_safe_range value safe]

theorem rounded_unsigned_keeps_original_decimal (value : Nat) (safe : value ≤ 9007199254740991) :
    unsigned (JcsIntegerRounding.magnitude value) = unsigned value := by
  rw [JcsIntegerRounding.magnitude_exact_below_precision value (by unfold JcsIntegerRounding.precisionLimit; omega)]

end Auths.Product.JcsIntegerDecimal
