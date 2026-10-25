import Auths.Product.NativeCompilerPrefixes
import Auths.Product.DecimalProjection
import Mathlib.Data.Nat.Log

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open DecimalProjection
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

@[step] theorem native_integer_value_exact (minimum maximum value : Std.I64) :
    AuthsNativeRecipe.auths_gateway_kernel.scalars.integer_value_valid minimum maximum value ⦃ actual =>
      actual = decide (ScalarProjection.IntegerValue minimum.val maximum.val value.val) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.scalars.integer_value_valid
  step with native_schema_integer_limits_exact minimum maximum as ⟨schema, schemaMeaning⟩
  repeat' split
  all_goals simp_all [ScalarProjection.IntegerValue, IScalar.le_equiv]

@[step] theorem native_magnitude_exact (value : Std.I64) :
    AuthsNativeRecipe.auths_gateway_kernel.scalars.magnitude value ⦃ actual =>
      actual.val = value.val.natAbs ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.scalars.magnitude
  by_cases negative : value.val < 0
  · have nativeNegative : value < 0#i64 := by scalar_tac
    simp only [nativeNegative, ↓reduceIte]
    step as ⟨offset, offsetMeaning⟩
    step as ⟨positive, positiveMeaning⟩
    step with IScalar.hcast_inBounds_spec .U64 positive (by scalar_tac) as ⟨converted, convertedMeaning⟩
    step as ⟨actual, exact⟩
    have absolute : (value.val.natAbs : Int) = -value.val := by
      rw [Int.natCast_natAbs, abs_of_neg negative]
    omega
  · have nativeNonnegative : ¬value < 0#i64 := by scalar_tac
    simp only [nativeNonnegative, ↓reduceIte]
    apply spec_mono (IScalar.hcast_inBounds_spec .U64 value (by scalar_tac))
    intro actual exact
    have absolute : (value.val.natAbs : Int) = value.val := by
      rw [Int.natCast_natAbs, abs_of_nonneg (by omega)]
    omega

private theorem native_divisor_suffix (value divisor : Std.U64) (power : Nat)
    (powerMeaning : divisor.val = 10 ^ power) (lower : divisor.val ≤ max 1 value.val) :
    AuthsNativeRecipe.auths_gateway_kernel.scalars.decimal_divisor_loop value divisor ⦃ actual =>
      ∃ actualPower, actual.val = 10 ^ actualPower ∧ actual.val ≤ max 1 value.val ∧
        value.val < 10 ^ (actualPower + 1) ⦄ := by
  generalize remaining : value.val - divisor.val = count
  induction count using Nat.strong_induction_on generalizing divisor power with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.scalars.decimal_divisor_loop
      have positive : 0 < divisor.val := by rw [powerMeaning]; positivity
      step as ⟨quotient, quotientMeaning⟩
      by_cases advance : 10 ≤ quotient.val
      · have nativeAdvance : quotient >= 10#u64 := by scalar_tac
        have product : divisor.val * 10 ≤ value.val := by
          calc
            divisor.val * 10 = 10 * divisor.val := Nat.mul_comm _ _
            _ ≤ (value.val / divisor.val) * divisor.val := Nat.mul_le_mul_right divisor.val (by omega)
            _ ≤ value.val := Nat.div_mul_le_self _ _
        simp only [nativeAdvance, ↓reduceIte]
        step as ⟨next, nextMeaning⟩
        have nextPower : next.val = 10 ^ (power + 1) := by
          simpa [Nat.pow_succ, powerMeaning] using nextMeaning
        have nextLower : next.val ≤ max 1 value.val := by omega
        exact ih _ (by omega) next (power + 1) nextPower nextLower rfl
      · have nativeFinished : ¬quotient >= 10#u64 := by scalar_tac
        have upper : value.val < 10 ^ (power + 1) := by
          have small : value.val / divisor.val < 10 := by omega
          have bound := (Nat.div_lt_iff_lt_mul positive).mp small
          simpa [Nat.pow_succ, powerMeaning, Nat.mul_comm] using bound
        simp only [nativeFinished, ↓reduceIte, spec_ok]
        exact ⟨power, powerMeaning, lower, upper⟩

@[step] theorem native_decimal_divisor_exact (value : Std.U64) :
    AuthsNativeRecipe.auths_gateway_kernel.scalars.decimal_divisor value ⦃ actual =>
      ∃ power, actual.val = 10 ^ power ∧ actual.val ≤ max 1 value.val ∧ value.val < 10 ^ (power + 1) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.scalars.decimal_divisor
  exact native_divisor_suffix value 1#u64 0 (by simp) (by simp)

private theorem native_decimal_zero (output : NativeVec Std.U8) (remaining : Std.U64) :
    AuthsNativeRecipe.auths_gateway_kernel.scalars.append_unsigned_decimal_loop output 0#u64 remaining = ok output := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.scalars.append_unsigned_decimal_loop
  simp

private theorem native_decimal_digits (initial : NativeVec Std.U8) (divisor remaining : Std.U64) (power : Nat)
    (powerMeaning : divisor.val = 10 ^ power) (bounded : remaining.val < 10 ^ (power + 1))
    (room : initial.val.length + power + 1 ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.scalars.append_unsigned_decimal_loop initial divisor remaining ⦃ actual =>
      bytes actual = bytes initial ++ emit remaining.val divisor.val ⦄ := by
  induction power generalizing initial divisor remaining with
  | zero =>
      have divisorOne : divisor = 1#u64 := UScalar.eq_of_val_eq (by simpa using powerMeaning)
      have small : remaining.val < 10 := by simpa using bounded
      subst divisor
      unfold AuthsNativeRecipe.auths_gateway_kernel.scalars.append_unsigned_decimal_loop
      simp only [↓reduceIte]
      step as ⟨quotient, quotientMeaning⟩
      step with UScalar.cast_inBounds_spec .U8 quotient (by scalar_tac) as ⟨digit, digitMeaning⟩
      step as ⟨ascii, asciiMeaning⟩
      step with native_push_exact initial ascii (by omega) as ⟨grown, grownMeaning⟩
      step as ⟨nextRemaining, remainderMeaning⟩
      step as ⟨nextDivisor, divisorMeaning⟩
      have finished : nextDivisor = 0#u64 := UScalar.eq_of_val_eq (by scalar_tac)
      simp [finished, native_decimal_zero, bytes, grownMeaning, asciiMeaning, digitMeaning,
        quotientMeaning, emit, List.map_append]
  | succ power ih =>
      have positive : 0 < divisor.val := by rw [powerMeaning]; positivity
      have nativePositive : divisor > 0#u64 := by scalar_tac
      have digitBound : remaining.val / divisor.val < 10 := by
        apply (Nat.div_lt_iff_lt_mul positive).mpr
        simpa [powerMeaning, Nat.pow_succ, Nat.mul_comm] using bounded
      unfold AuthsNativeRecipe.auths_gateway_kernel.scalars.append_unsigned_decimal_loop
      simp only [nativePositive, ↓reduceIte]
      step as ⟨quotient, quotientMeaning⟩
      step with UScalar.cast_inBounds_spec .U8 quotient (by scalar_tac) as ⟨digit, digitMeaning⟩
      step as ⟨ascii, asciiMeaning⟩
      step with native_push_exact initial ascii (by omega) as ⟨grown, grownMeaning⟩
      step as ⟨nextRemaining, remainderMeaning⟩
      step as ⟨nextDivisor, divisorMeaning⟩
      have nextPower : nextDivisor.val = 10 ^ power := by
        simpa [powerMeaning, power_step_div] using divisorMeaning
      have nextBound : nextRemaining.val < 10 ^ (power + 1) := by
        have remainderBound := Nat.mod_lt remaining.val positive
        simpa [remainderMeaning, powerMeaning] using remainderBound
      have nextRoom : grown.val.length + power + 1 ≤ Usize.max := by
        simp only [grownMeaning, List.length_append, List.length_singleton]
        omega
      apply spec_mono (ih grown nextDivisor nextRemaining nextPower nextBound nextRoom)
      intro actual exact
      rw [exact, emit]
      simp [Nat.ne_of_gt positive, bytes, grownMeaning, asciiMeaning, digitMeaning,
        quotientMeaning, remainderMeaning, divisorMeaning, List.map_append, List.append_assoc]

@[step] theorem native_unsigned_decimal_exact (initial : NativeVec Std.U8) (value : Std.U64)
    (room : initial.val.length + 20 ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.scalars.append_unsigned_decimal initial value ⦃ actual =>
      ∃ power, 10 ^ power ≤ max 1 value.val ∧ value.val < 10 ^ (power + 1) ∧
        bytes actual = bytes initial ++ emit value.val (10 ^ power) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.scalars.append_unsigned_decimal
  step with native_decimal_divisor_exact value as ⟨divisor, power, powerMeaning, largest, upper⟩
  have powerBound : power < 20 := exponent_bound value.val power 20
    (by simpa [powerMeaning] using largest) (by scalar_tac)
  apply spec_mono (native_decimal_digits initial divisor value power powerMeaning upper (by omega))
  intro actual exact
  exact ⟨power, by simpa [powerMeaning] using largest, upper, by simpa [powerMeaning] using exact⟩

private theorem native_signed_decimal (value : Std.I64) :
    AuthsNativeRecipe.auths_gateway_kernel.scalars.integer_bytes value ⦃ actual =>
      ∃ power, 10 ^ power ≤ max 1 value.val.natAbs ∧ value.val.natAbs < 10 ^ (power + 1) ∧
        bytes actual = (if value.val < 0 then [45] else []) ++ emit value.val.natAbs (10 ^ power) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.scalars.integer_bytes
  by_cases negative : value.val < 0
  · have nativeNegative : value < 0#i64 := by scalar_tac
    simp only [nativeNegative, ↓reduceIte]
    step with native_push_exact (AuthsNativeRecipe.alloc.vec.Vec.new Std.U8) 45#u8
      (by simp; scalar_tac) as ⟨prefix, prefixMeaning⟩
    step with native_magnitude_exact value as ⟨absolute, absoluteMeaning⟩
    apply spec_mono (native_unsigned_decimal_exact prefix absolute
      (by simp [prefixMeaning, native_empty_contents]; scalar_tac))
    rintro actual ⟨power, lower, upper, exact⟩
    exact ⟨power, by simpa [absoluteMeaning] using lower, by simpa [absoluteMeaning] using upper,
      by simpa [bytes, prefixMeaning, native_empty_contents, absoluteMeaning, negative] using exact⟩
  · have nativeNonnegative : ¬value < 0#i64 := by scalar_tac
    simp only [nativeNonnegative, ↓reduceIte, bind_tc_ok]
    step with native_magnitude_exact value as ⟨absolute, absoluteMeaning⟩
    apply spec_mono (native_unsigned_decimal_exact (AuthsNativeRecipe.alloc.vec.Vec.new Std.U8) absolute
      (by simp; scalar_tac))
    rintro actual ⟨power, lower, upper, exact⟩
    exact ⟨power, by simpa [absoluteMeaning] using lower, by simpa [absoluteMeaning] using upper,
      by simpa [bytes, native_empty_contents, absoluteMeaning, negative] using exact⟩

/-- One fixed, canonical model result for every signed word, including MIN.
The magnitude implementation avoids negating MIN directly. -/
@[step] theorem native_integer_literal_exact (value : Std.I64) :
    AuthsNativeRecipe.auths_gateway_kernel.scalars.integer_bytes value ⦃ actual =>
      bytes actual = TemplateAst.integerBytes value.val ⦄ := by
  apply spec_mono (native_signed_decimal value)
  rintro actual ⟨power, lower, upper, exact⟩
  have atLeastOne : 1 ≤ 10 ^ power := Nat.one_le_pow power (by decide)
  have upperMax : max 1 value.val.natAbs < 10 ^ (power + 1) := by
    rw [Nat.pow_succ] at *
    omega
  have logarithm : Nat.log 10 (max 1 value.val.natAbs) = power :=
    Nat.log_eq_of_pow_le_of_lt_pow lower upperMax
  simpa [TemplateAst.integerBytes, logarithm] using exact

theorem native_integer_literal_has_decimal_meaning (value : Std.I64) :
    AuthsNativeRecipe.auths_gateway_kernel.scalars.integer_bytes value ⦃ actual =>
      SignedDecimal (bytes actual) value.val ∧ actual.val.length ≤ 20 ⦄ := by
  apply spec_mono (native_signed_decimal value)
  rintro actual ⟨power, lower, upper, exact⟩
  have decimal := emit_canonical value.val.natAbs power upper lower
  have absoluteBound : value.val.natAbs ≤ 9223372036854775808 := by
    have interval : |value.val| ≤ (9223372036854775808 : Int) := by
      apply abs_le.mpr
      constructor <;> scalar_tac
    rw [← Int.natCast_natAbs] at interval
    exact_mod_cast interval
  have powerBound : power < 19 := exponent_bound value.val.natAbs power 19 lower (by norm_num; omega)
  constructor
  · by_cases negative : value.val < 0
    · simp only [SignedDecimal, negative, ↓reduceIte]
      exact ⟨emit value.val.natAbs (10 ^ power), by simpa [negative] using exact, decimal⟩
    · simpa [SignedDecimal, negative, exact] using decimal
  · have size := congrArg List.length exact
    simp only [bytes, List.length_map, List.length_append, emit_length] at size
    split_ifs at size <;> simp at size <;> omega

end Auths.Product.NativeCompiler.Refinement
