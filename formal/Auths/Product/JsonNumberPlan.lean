import Auths.Product.JcsIntegerDecimal
import Auths.Product.JsonNumberLexeme

/-!
Closed numeric-routing reference after complete lexical recognition. Whole
nonnegative u64 and strictly negative i64 words keep exact integer meaning.
Fractions/exponents, negative zero and word overflow retain the FULL original
token for native floating conversion. A floating plan is neither a finite
value nor successful conversion. This does not prove native serde integer
scanning, casts, wrapping arithmetic, float parsing or visitor dispatch.
-/
namespace Auths.Product.JsonNumberPlan
abbrev Bytes := List Nat

inductive Plan where
  | unsigned (value : Nat)
  | signed (value : Int)
  | floating (original : Bytes)
  deriving DecidableEq

def classify (input : Bytes) : Plan :=
  if input.head? = some 45 then
    match JcsIntegerDecimal.readUnsigned input.tail with
    | some magnitude =>
        if 0 < magnitude ∧ magnitude ≤ 9223372036854775808 then .signed (-Int.ofNat magnitude) else .floating input
    | none => .floating input
  else
    match JcsIntegerDecimal.readUnsigned input with
    | some magnitude => if magnitude ≤ 18446744073709551615 then .unsigned magnitude else .floating input
    | none => .floating input

private theorem leading_minus_is_original (input : Bytes) (minus : input.head? = some 45) : input = 45 :: input.tail := by
  cases input with
  | nil => simp at minus
  | cons first rest =>
      have same : first = 45 := by simpa using minus
      simp [same]

theorem unsigned_plan_earns_original_word (input : Bytes) (value : Nat) (planned : classify input = .unsigned value) :
    value ≤ 18446744073709551615 ∧ DecimalProjection.Decimal input value ∧ input.head? ≠ some 45 := by
  by_cases minus : input.head? = some 45
  · cases parsed : JcsIntegerDecimal.readUnsigned input.tail with
    | none => simp [classify, minus, parsed] at planned
    | some magnitude =>
        by_cases bounded : 0 < magnitude ∧ magnitude ≤ 9223372036854775808 <;>
          simp [classify, minus, parsed, bounded] at planned
  · cases parsed : JcsIntegerDecimal.readUnsigned input with
    | none => simp [classify, minus, parsed] at planned
    | some magnitude =>
        by_cases bounded : magnitude ≤ 18446744073709551615
        · have same : magnitude = value := by simpa [classify, minus, parsed, bounded] using planned
          cases same
          exact ⟨bounded, JcsIntegerDecimal.unsigned_reader_earns_original_decimal input magnitude parsed, minus⟩
        · simp [classify, minus, parsed, bounded] at planned

theorem signed_plan_earns_original_word (input : Bytes) (value : Int) (planned : classify input = .signed value) :
    (-9223372036854775808 ≤ value ∧ value < 0) ∧ DecimalProjection.SignedDecimal input value := by
  by_cases minus : input.head? = some 45
  · cases parsed : JcsIntegerDecimal.readUnsigned input.tail with
    | none => simp [classify, minus, parsed] at planned
    | some magnitude =>
        by_cases bounded : 0 < magnitude ∧ magnitude ≤ 9223372036854775808
        · have same : -Int.ofNat magnitude = value := by simpa [classify, minus, parsed, bounded] using planned
          cases same
          have negative : -Int.ofNat magnitude < 0 := by omega
          refine ⟨by omega, ?_⟩
          simp only [DecimalProjection.SignedDecimal, if_pos negative]
          refine ⟨input.tail, leading_minus_is_original input minus, ?_⟩
          simpa using JcsIntegerDecimal.unsigned_reader_earns_original_decimal input.tail magnitude parsed
        · simp [classify, minus, parsed, bounded] at planned
  · cases parsed : JcsIntegerDecimal.readUnsigned input with
    | none => simp [classify, minus, parsed] at planned
    | some magnitude =>
        by_cases bounded : magnitude ≤ 18446744073709551615 <;>
          simp [classify, minus, parsed, bounded] at planned

theorem floating_plan_keeps_complete_original (input token : Bytes) (planned : classify input = .floating token) : token = input := by
  unfold classify at planned
  split at planned
  · cases parsed : JcsIntegerDecimal.readUnsigned input.tail with
    | none => simp only [parsed] at planned; cases planned; rfl
    | some magnitude =>
        simp only [parsed] at planned
        split at planned <;> cases planned <;> rfl
  · cases parsed : JcsIntegerDecimal.readUnsigned input with
    | none => simp only [parsed] at planned; cases planned; rfl
    | some magnitude =>
        simp only [parsed] at planned
        split at planned <;> cases planned <;> rfl

theorem original_unsigned_decimal_earns_word_plan (value : Nat) (bounded : value ≤ 18446744073709551615) :
    classify (JcsIntegerDecimal.unsigned value) = .unsigned value := by
  rw [classify, if_neg (JcsIntegerDecimal.unsigned_bytes_do_not_start_with_minus value),
    JcsIntegerDecimal.unsigned_roundtrip, if_pos bounded]

theorem original_negative_decimal_earns_word_plan (magnitude : Nat)
    (bounded : 0 < magnitude ∧ magnitude ≤ 9223372036854775808) :
    classify (45 :: JcsIntegerDecimal.unsigned magnitude) = .signed (-Int.ofNat magnitude) := by
  simp [classify, JcsIntegerDecimal.unsigned_roundtrip, bounded]

theorem negative_zero_requires_floating : classify [45, 48] = .floating [45, 48] := by decide

end Auths.Product.JsonNumberPlan
