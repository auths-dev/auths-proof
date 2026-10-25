import Auths.Product.RequestConstruction
import Mathlib.Tactic

/-!
Decimal meaning is positional base ten, exact digit bytes and a single
canonical sign. It is independent of Rust formatting and JSON serialization.
The arithmetic emitter is a proof intermediate, not the specification of
what an integer means.
-/
namespace Auths.Product.DecimalProjection
open RequestConstruction

def readDigits : Bytes → Nat
  | [] => 0
  | digit :: rest => (digit - 48) * 10 ^ rest.length + readDigits rest

def Decimal (bytes : Bytes) (value : Nat) : Prop :=
  bytes ≠ [] ∧ (∀ byte ∈ bytes, 48 ≤ byte ∧ byte ≤ 57) ∧
    readDigits bytes = value ∧
      (bytes = [48] ∨ ∃ first rest, bytes = first :: rest ∧ 48 < first)

def SignedDecimal (bytes : Bytes) (value : Int) : Prop :=
  if value < 0 then ∃ digits, bytes = 45 :: digits ∧ Decimal digits value.natAbs
  else Decimal bytes value.natAbs

def emit (value divisor : Nat) : Bytes :=
  if divisor = 0 then []
  else (48 + value / divisor) :: emit (value % divisor) (divisor / 10)
termination_by divisor
decreasing_by omega

@[simp] theorem emit_zero (value : Nat) : emit value 0 = [] := by rw [emit]; simp

theorem power_positive (power : Nat) : 0 < 10 ^ power := by positivity

theorem power_step_div (power : Nat) : 10 ^ (power + 1) / 10 = 10 ^ power := by
  simp [Nat.pow_succ]

theorem emit_length (value power : Nat) : (emit value (10 ^ power)).length = power + 1 := by
  induction power generalizing value with
  | zero => simp [emit]
  | succ power ih =>
    have nonzero : 10 ^ (power + 1) ≠ 0 := Nat.ne_of_gt (power_positive _)
    rw [emit]
    simp only [nonzero, ↓reduceIte, List.length_cons, power_step_div]
    rw [ih]

theorem emit_digits (value power : Nat) (bounded : value < 10 ^ (power + 1)) :
    ∀ byte ∈ emit value (10 ^ power), 48 ≤ byte ∧ byte ≤ 57 := by
  induction power generalizing value with
  | zero =>
    have small : value < 10 := by simpa using bounded
    simp [emit]
    omega
  | succ power ih =>
    have positive := power_positive (power + 1)
    have nonzero : 10 ^ (power + 1) ≠ 0 := Nat.ne_of_gt positive
    have digitBound : value / 10 ^ (power + 1) < 10 := by
      apply (Nat.div_lt_iff_lt_mul positive).mpr
      simpa [Nat.pow_succ, Nat.mul_comm] using bounded
    have remainderBound : value % 10 ^ (power + 1) < 10 ^ (power + 1) := Nat.mod_lt _ positive
    rw [emit]
    simp only [nonzero, ↓reduceIte, power_step_div, List.mem_cons]
    intro byte member
    rcases member with same | member
    · omega
    · exact ih _ remainderBound byte member

theorem emit_value (value power : Nat) (bounded : value < 10 ^ (power + 1)) :
    readDigits (emit value (10 ^ power)) = value := by
  induction power generalizing value with
  | zero =>
    have small : value < 10 := by simpa using bounded
    simp [emit, readDigits]
  | succ power ih =>
    have positive := power_positive (power + 1)
    have nonzero : 10 ^ (power + 1) ≠ 0 := Nat.ne_of_gt positive
    have remainderBound : value % 10 ^ (power + 1) < 10 ^ (power + 1) := Nat.mod_lt _ positive
    rw [emit]
    simp only [nonzero, ↓reduceIte, power_step_div, readDigits, emit_length,
      Nat.add_sub_cancel_left]
    rw [ih _ remainderBound]
    simpa [Nat.mul_comm] using Nat.div_add_mod value (10 ^ (power + 1))

theorem emit_canonical (value power : Nat)
    (bounded : value < 10 ^ (power + 1)) (largest : 10 ^ power ≤ max 1 value) :
    Decimal (emit value (10 ^ power)) value := by
  refine ⟨?_, emit_digits value power bounded, emit_value value power bounded, ?_⟩
  · intro empty
    have size := emit_length value power
    rw [empty] at size
    simp at size
  · by_cases zero : value = 0
    · have divisorOne : 10 ^ power = 1 := by
        have positive := power_positive power
        simp [zero] at largest
        omega
      left
      simp [zero, divisorOne, emit]
    · have positive := power_positive power
      have within : 10 ^ power ≤ value := by
        simpa only [Nat.max_eq_right (Nat.one_le_iff_ne_zero.mpr zero)] using largest
      have leading : 0 < value / 10 ^ power := Nat.div_pos within positive
      right
      refine ⟨48 + value / 10 ^ power, emit (value % 10 ^ power) (10 ^ power / 10), ?_, by omega⟩
      rw [emit]
      simp [Nat.ne_of_gt positive]

theorem exponent_bound (value power limit : Nat)
    (largest : 10 ^ power ≤ max 1 value) (valueBound : max 1 value < 10 ^ limit) : power < limit := by
  by_contra notBefore
  have after : limit ≤ power := by omega
  have ordered : 10 ^ limit ≤ 10 ^ power := Nat.pow_le_pow_right (by decide) after
  omega

theorem word_digits_bounded (value power : Nat)
    (word : value ≤ 18446744073709551615) (largest : 10 ^ power ≤ max 1 value) :
    (emit value (10 ^ power)).length ≤ 20 := by
  have small : max 1 value < 10 ^ 20 := by norm_num; omega
  have exponent := exponent_bound value power 20 largest small
  rw [emit_length]
  omega

theorem json_digits_bounded (value power : Nat)
    (safe : value ≤ 9007199254740991) (largest : 10 ^ power ≤ max 1 value) :
    (emit value (10 ^ power)).length ≤ 16 := by
  have small : max 1 value < 10 ^ 16 := by norm_num; omega
  have exponent := exponent_bound value power 16 largest small
  rw [emit_length]
  omega

theorem signed_no_negative_zero (bytes : Bytes) (value : Int)
    (represented : SignedDecimal bytes value) (negative : value < 0) :
    ∃ digits, bytes = 45 :: digits ∧ readDigits digits = value.natAbs ∧ value.natAbs ≠ 0 := by
  simp only [SignedDecimal, negative, ↓reduceIte] at represented
  obtain ⟨digits, same, decimal⟩ := represented
  refine ⟨digits, same, decimal.2.2.1, ?_⟩
  intro zero
  have : value = 0 := Int.natAbs_eq_zero.mp zero
  omega

end Auths.Product.DecimalProjection
