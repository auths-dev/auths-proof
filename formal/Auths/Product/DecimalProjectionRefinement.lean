import Auths.Product.ScalarProjectionRefinement

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway

namespace Auths.Product.DecimalProjection.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

@[step] theorem magnitude_exact (value : Std.I64) :
    scalars.magnitude value ⦃ actual => actual.val = value.val.natAbs ⦄ := by
  unfold scalars.magnitude
  by_cases negative : value.val < 0
  · have nativeNegative : value < 0#i64 := by scalar_tac
    simp only [nativeNegative, ↓reduceIte]
    step as ⟨offset, offsetValue⟩
    step as ⟨positive, positiveValue⟩
    step with (IScalar.hcast_inBounds_spec .U64 positive (by scalar_tac)) as ⟨converted, convertedValue⟩
    step as ⟨actual, actualValue⟩
    have absolute : (value.val.natAbs : Int) = -value.val := by
      rw [Int.natCast_natAbs, abs_of_neg negative]
    omega
  · have nativeNonnegative : ¬value < 0#i64 := by scalar_tac
    simp only [nativeNonnegative, ↓reduceIte]
    apply spec_mono (IScalar.hcast_inBounds_spec .U64 value (by scalar_tac))
    intro actual actualValue
    have absolute : (value.val.natAbs : Int) = value.val := by
      rw [Int.natCast_natAbs, abs_of_nonneg (by omega)]
    omega

/-- The actual divisor loop earns the power, maximality and upper bound for
every u64. Its multiplication never exceeds the original input. -/
@[step] theorem divisor_exact (value : Std.U64) :
    scalars.decimal_divisor value ⦃ actual => ∃ power,
      actual.val = 10 ^ power ∧ actual.val ≤ max 1 value.val ∧ value.val < 10 ^ (power + 1) ⦄ := by
  unfold scalars.decimal_divisor scalars.decimal_divisor_loop
  apply loop.spec_decr_nat
    (measure := fun divisor => value.val - divisor.val)
    (inv := fun divisor => ∃ power, divisor.val = 10 ^ power ∧ divisor.val ≤ max 1 value.val)
  · intro divisor invariant
    obtain ⟨power, powerValue, largest⟩ := invariant
    have positive : 0 < divisor.val := by rw [powerValue]; positivity
    unfold scalars.decimal_divisor_loop.body
    dsimp only
    step as ⟨quotient, quotientValue⟩
    split <;> rename_i keepGoing
    · have tenFit : 10 ≤ value.val / divisor.val := by scalar_tac
      have multiplication : divisor.val * 10 ≤ value.val := by
        calc
          divisor.val * 10 = 10 * divisor.val := Nat.mul_comm _ _
          _ ≤ (value.val / divisor.val) * divisor.val := Nat.mul_le_mul_right divisor.val tenFit
          _ ≤ value.val := Nat.div_mul_le_self _ _
      have productFits : divisor.val * 10 ≤ U64.max := by scalar_tac
      step as ⟨next, nextValue⟩
      refine ⟨⟨power + 1, ?_, ?_⟩, ?_⟩
      · simpa [Nat.pow_succ, powerValue] using nextValue
      · have belowInput : next.val ≤ value.val := by omega
        exact belowInput.trans (Nat.le_max_right _ _)
      · omega
    · simp only [spec_ok]
      refine ⟨power, powerValue, largest, ?_⟩
      have quotientSmall : value.val / divisor.val < 10 := by scalar_tac
      have upper := (Nat.div_lt_iff_lt_mul positive).mp quotientSmall
      simpa [Nat.pow_succ, powerValue, Nat.mul_comm] using upper
  · exact ⟨0, by simp, by simp⟩

private theorem render_done (output : alloc.vec.Vec Std.U8) (remaining : Std.U64) :
    scalars.append_unsigned_decimal_loop output 0#u64 remaining = ok output := by
  unfold scalars.append_unsigned_decimal_loop
  rw [loop.eq_def]
  simp [scalars.append_unsigned_decimal_loop.body]

/-- Actual rendering consumes successive quotients and remainders. The loop
copies no caller-supplied decimal text and each emitted digit is below ten. -/
@[step] theorem render_loop_exact (initial : alloc.vec.Vec Std.U8)
    (divisor remaining : Std.U64) (power : Nat)
    (powerValue : divisor.val = 10 ^ power)
    (bounded : remaining.val < 10 ^ (power + 1))
    (fits : initial.val.length + power + 1 < 2147483647) :
    scalars.append_unsigned_decimal_loop initial divisor remaining ⦃ actual =>
      vecBytes actual = vecBytes initial ++ emit remaining.val divisor.val ⦄ := by
  induction power generalizing initial divisor remaining with
  | zero =>
    have divisorOne : divisor = 1#u64 := UScalar.eq_of_val_eq (by simpa using powerValue)
    have small : remaining.val < 10 := by simpa using bounded
    subst divisor
    unfold scalars.append_unsigned_decimal_loop
    rw [loop.eq_def]
    simp only [scalars.append_unsigned_decimal_loop.body, ↓reduceIte]
    step as ⟨quotient, quotientValue⟩
    have digitFits : quotient.val ≤ U8.max := by scalar_tac
    step with (UScalar.cast_inBounds_spec .U8 quotient digitFits) as ⟨digit, digitValue⟩
    step as ⟨ascii, asciiValue⟩
    have room : initial.length < Usize.max := lt_usize_max (by change initial.val.length < _; omega)
    step as ⟨updated, updateValue⟩
    step as ⟨nextRemaining, remainderValue⟩
    step as ⟨nextDivisor, divisorValue⟩
    have finished : nextDivisor = 0#u64 := UScalar.eq_of_val_eq (by scalar_tac)
    simp only [finished, render_done, spec_ok]
    simp [vecBytes, byteList, updateValue, asciiValue, digitValue, quotientValue, emit]
  | succ power ih =>
    have positive : 0 < divisor.val := by rw [powerValue]; positivity
    have nativePositive : divisor > 0#u64 := by scalar_tac
    have digitBound : remaining.val / divisor.val < 10 := by
      apply (Nat.div_lt_iff_lt_mul positive).mpr
      simpa [powerValue, Nat.pow_succ, Nat.mul_comm] using bounded
    unfold scalars.append_unsigned_decimal_loop
    rw [loop.eq_def]
    simp only [scalars.append_unsigned_decimal_loop.body, nativePositive, ↓reduceIte]
    step as ⟨quotient, quotientValue⟩
    have digitFits : quotient.val ≤ U8.max := by scalar_tac
    step with (UScalar.cast_inBounds_spec .U8 quotient digitFits) as ⟨digit, digitValue⟩
    step as ⟨ascii, asciiValue⟩
    have room : initial.length < Usize.max := lt_usize_max (by change initial.val.length < _; omega)
    step as ⟨updated, updateValue⟩
    step as ⟨nextRemaining, remainderValue⟩
    step as ⟨nextDivisor, divisorValue⟩
    have nextPower : nextDivisor.val = 10 ^ power := by
      simpa [powerValue, power_step_div] using divisorValue
    have nextBound : nextRemaining.val < 10 ^ (power + 1) := by
      have remainderBound := Nat.mod_lt remaining.val positive
      simpa [remainderValue, powerValue] using remainderBound
    have nextFits : updated.val.length + power + 1 < 2147483647 := by
      simp [updateValue] at fits ⊢
      omega
    have recursive := ih updated nextDivisor nextRemaining nextPower nextBound nextFits
    apply spec_mono recursive
    intro actual actualValue
    rw [actualValue]
    rw [emit]
    simp [Nat.ne_of_gt positive, vecBytes, byteList, updateValue, asciiValue,
      digitValue, quotientValue, remainderValue, divisorValue, List.append_assoc]

@[step] theorem append_exact (initial : alloc.vec.Vec Std.U8) (value : Std.U64)
    (initialBound : initial.val.length ≤ 1) :
    scalars.append_unsigned_decimal initial value ⦃ actual => ∃ power,
      10 ^ power ≤ max 1 value.val ∧ value.val < 10 ^ (power + 1) ∧
        vecBytes actual = vecBytes initial ++ emit value.val (10 ^ power) ⦄ := by
  unfold scalars.append_unsigned_decimal
  step with divisor_exact as ⟨divisor, power, powerValue, largest, upper⟩
  have powerBound : power < 20 := exponent_bound value.val power 20 (by simpa [powerValue] using largest) (by scalar_tac)
  have fits : initial.val.length + power + 1 < 2147483647 := by omega
  apply spec_mono (render_loop_exact initial divisor value power powerValue upper fits)
  intro actual meaning
  exact ⟨power, by simpa [powerValue] using largest, upper, by simpa [powerValue] using meaning⟩

theorem append_represents_unsigned (initial : alloc.vec.Vec Std.U8) (value : Std.U64)
    (initialBound : initial.val.length ≤ 1) :
    scalars.append_unsigned_decimal initial value ⦃ actual => ∃ digits,
      vecBytes actual = vecBytes initial ++ digits ∧ Decimal digits value.val ∧ digits.length ≤ 20 ⦄ := by
  apply spec_mono (append_exact initial value initialBound)
  intro actual meaning
  obtain ⟨power, largest, upper, same⟩ := meaning
  exact ⟨emit value.val (10 ^ power), same, emit_canonical _ _ upper largest,
    word_digits_bounded value.val power (by scalar_tac) largest⟩

@[step] theorem integer_bytes_exact (value : Std.I64) :
    scalars.integer_bytes value ⦃ actual => ∃ power,
      10 ^ power ≤ max 1 value.val.natAbs ∧ value.val.natAbs < 10 ^ (power + 1) ∧
        vecBytes actual = (if value.val < 0 then [45] else []) ++ emit value.val.natAbs (10 ^ power) ⦄ := by
  unfold scalars.integer_bytes
  by_cases negative : value.val < 0
  · have nativeNegative : value < 0#i64 := by scalar_tac
    simp only [nativeNegative, ↓reduceIte]
    step as ⟨prefix, prefixValue⟩
    step with magnitude_exact as ⟨absolute, absoluteValue⟩
    step with append_exact as ⟨actual, power, largest, upper, same⟩
    exact ⟨power, by simpa [absoluteValue] using largest, by simpa [absoluteValue] using upper,
      by simpa [negative, prefixValue, vecBytes, byteList, absoluteValue] using same⟩
  · have nativeNonnegative : ¬value < 0#i64 := by scalar_tac
    simp only [nativeNonnegative, ↓reduceIte]
    step with magnitude_exact as ⟨absolute, absoluteValue⟩
    step with append_exact as ⟨actual, power, largest, upper, same⟩
    exact ⟨power, by simpa [absoluteValue] using largest, by simpa [absoluteValue] using upper,
      by simpa [negative, vecBytes, byteList, absoluteValue] using same⟩

theorem integer_bytes_semantics (value : Std.I64) :
    scalars.integer_bytes value ⦃ actual => SignedDecimal (vecBytes actual) value.val ∧ actual.val.length ≤ 20 ⦄ := by
  apply spec_mono (integer_bytes_exact value)
  intro actual meaning
  obtain ⟨power, largest, upper, same⟩ := meaning
  have canonical := emit_canonical value.val.natAbs power upper largest
  have absoluteBound : value.val.natAbs ≤ 9223372036854775808 := by
    have interval : |value.val| ≤ (9223372036854775808 : Int) := by
      apply abs_le.mpr
      constructor <;> scalar_tac
    rw [← Int.natCast_natAbs] at interval
    exact_mod_cast interval
  have powerBound : power < 19 := exponent_bound value.val.natAbs power 19 largest (by norm_num; omega)
  constructor
  · by_cases negative : value.val < 0
    · simp only [SignedDecimal, negative, ↓reduceIte]
      exact ⟨emit value.val.natAbs (10 ^ power), by simpa [negative] using same, canonical⟩
    · simpa [SignedDecimal, negative, same] using canonical
  · have size := congrArg List.length same
    simp only [vecBytes, byteList, List.length_map, List.length_append, emit_length] at size
    split_ifs at size <;> simp at size <;> omega

theorem safe_integer_bytes_bounded (value : Std.I64)
    (safe : -9007199254740991 ≤ value.val ∧ value.val ≤ 9007199254740991) :
    scalars.integer_bytes value ⦃ actual => actual.val.length ≤ 17 ⦄ := by
  apply spec_mono (integer_bytes_exact value)
  intro actual meaning
  obtain ⟨power, largest, upper, same⟩ := meaning
  have absoluteBound : value.val.natAbs ≤ 9007199254740991 := by
    have interval : |value.val| ≤ (9007199254740991 : Int) := abs_le.mpr safe
    rw [← Int.natCast_natAbs] at interval
    exact_mod_cast interval
  have digitsBound := json_digits_bounded value.val.natAbs power absoluteBound largest
  have size := congrArg List.length same
  simp only [vecBytes, byteList, List.length_map, List.length_append] at size
  split_ifs at size <;> simp at size <;> omega

end Auths.Product.DecimalProjection.Refinement
