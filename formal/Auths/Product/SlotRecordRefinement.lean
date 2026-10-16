import Auths.Product.SlotRecord
import Auths.Product.Refinement.ByteIdentity
open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.ByteIdentity
namespace Auths.Product.SlotRecord.Refinement
set_option maxHeartbeats 4000000

def bytes (values : List Std.U8) : List Nat := values.map (·.val)

theorem bytes_at (values : List Std.U8) (index : Nat) (inside : index < values.length) :
    (bytes values)[index]! = values[index].val := by
  rw [getElem!_pos (bytes values) index (by simpa [bytes] using inside)]
  simp [bytes]

theorem bytes_at_optional (values : List Std.U8) (index : Nat) (inside : index < values.length) :
    (bytes values)[index]? = some values[index].val := by
  rw [List.getElem?_eq_getElem (by simpa [bytes] using inside)]
  simp [bytes]

@[step] theorem counter_hex_matches_spec (stored : Slice Std.U8) (counter : Array Std.U8 32#usize) :
    slot_record.counter_hex_matches stored counter ⦃ actual =>
      actual = decide (hexMatches (bytes stored.val) (bytes counter.val)) ⦄ := by
  have counterSize : counter.val.length = 32 := by simp
  unfold slot_record.counter_hex_matches
  dsimp only
  split <;> rename_i sized
  · simp only [spec_ok]
    have notSized : stored.val.length ≠ 64 := by simp_all
    simp [hexMatches, bytes, counterSize, notSized]
  · have storedSize : stored.val.length = 64 := by simp_all
    unfold slot_record.counter_hex_matches_loop
    apply loop.spec_decr_nat
      (measure := fun position => 32 - position.val)
      (inv := fun position => position.val ≤ 32 ∧ pairsMatch (bytes stored.val) (bytes counter.val) position.val)
    · intro position processed
      unfold slot_record.counter_hex_matches_loop.body
      split <;> rename_i within
      · have inside : position.val < 32 := by simpa using within
        step as ⟨byte, byteAt⟩
        step as ⟨highIndex, highIndexEq⟩
        step as ⟨highStored, highStoredAt⟩
        step as ⟨high, highEq⟩
        step with hex_lower_exact as ⟨highDigit, highDigitEq⟩
        have counterAt : (bytes counter.val)[position.val]! = byte.val := by
          rw [bytes_at counter.val position.val (by omega), ← byteAt]
        have highAt : (bytes stored.val)[2 * position.val]? = some highStored.val := by
          have indexEq : 2 * position.val = highIndex.val := by omega
          rw [indexEq, bytes_at_optional stored.val highIndex.val (by omega), ← highStoredAt]
        split <;> rename_i highSame
        · simp only [spec_ok]
          have invalid : ¬ hexMatches (bytes stored.val) (bytes counter.val) := by
            intro valid
            have pair := valid.2 position.val (by simpa [bytes, counterSize] using inside)
            rw [counterAt, highAt] at pair
            have same : highStored.val = highDigit.val := by
              simpa only [Option.some.injEq, highDigitEq, highEq] using pair.1
            simp [same] at highSame
          simp [invalid]
        · step as ⟨lowIndex, lowIndexEq⟩
          step as ⟨lowStored, lowStoredAt⟩
          step as ⟨low, lowEq⟩
          step with hex_lower_exact as ⟨lowDigit, lowDigitEq⟩
          have lowAt : (bytes stored.val)[2 * position.val + 1]? = some lowStored.val := by
            have indexEq : 2 * position.val + 1 = lowIndex.val := by omega
            rw [indexEq, bytes_at_optional stored.val lowIndex.val (by omega), ← lowStoredAt]
          split <;> rename_i lowSame
          · simp only [spec_ok]
            have invalid : ¬ hexMatches (bytes stored.val) (bytes counter.val) := by
              intro valid
              have pair := valid.2 position.val (by simpa [bytes, counterSize] using inside)
              rw [counterAt, lowAt] at pair
              have same : lowStored.val = lowDigit.val := by
                simpa only [Option.some.injEq, lowDigitEq, lowEq] using pair.2
              simp [same] at lowSame
            simp [invalid]
          · step as ⟨next, nextEq⟩
            refine ⟨by omega, ?_, by omega⟩
            intro index before
            by_cases earlier : index < position.val
            · exact processed.2 index earlier
            · have current : index = position.val := by omega
              subst index
              rw [counterAt, highAt, lowAt]
              have highValue : highStored.val = highDigit.val := by simpa using highSame
              have lowValue : lowStored.val = lowDigit.val := by simpa using lowSame
              simp [highValue, lowValue, highDigitEq, lowDigitEq, highEq, lowEq]
      · simp only [spec_ok]
        have atEnd : position.val = 32 := by simpa using (show position.val = 32 by scalar_tac)
        have valid : hexMatches (bytes stored.val) (bytes counter.val) := by
          refine ⟨by simp [bytes, storedSize, counterSize], ?_⟩
          simpa [bytes, counterSize, atEnd] using processed.2
        simp [valid]
    · exact ⟨by simp, by simp [pairsMatch]⟩


theorem bytes_injective (left right : List Std.U8) : bytes left = bytes right ↔ left = right := by
  constructor
  · intro same
    induction left generalizing right with
    | nil => cases right <;> simp_all [bytes]
    | cons head tail ih =>
      cases right with
      | nil => simp [bytes] at same
      | cons other rest =>
        simp only [bytes, List.map_cons, List.cons.injEq] at same
        rw [(UScalar.eq_equiv _ _).mpr same.1, ih rest same.2]
  · intro same; rw [same]

def valuesView (value : slot_record.SumValues) : Values :=
  ⟨value.slot.val, value.amount.val, value.cumulative.val⟩

@[step] theorem validate_cumulative_exact (schema expectedSchema stored : Slice Std.U8)
    (counter : Array Std.U8 32#usize) (expectedSlot : Std.U64) (values : slot_record.SumValues) :
    slot_record.validate_cumulative schema expectedSchema stored counter expectedSlot values ⦃ actual =>
      actual.map UScalar.val = validate (bytes schema.val) (bytes expectedSchema.val)
        (bytes stored.val) (bytes counter.val) expectedSlot.val (valuesView values) ⦄ := by
  unfold slot_record.validate_cumulative
  step with field_name_equal_exact as ⟨sameSchema, schemaEq⟩
  cases sameSchema
  · simp only [Bool.false_eq_true, ↓reduceIte, spec_ok]
    have different : bytes schema.val ≠ bytes expectedSchema.val := by
      intro sameBytes
      have nativeSame := (bytes_injective schema.val expectedSchema.val).mp sameBytes
      simp [nativeSame] at schemaEq
    simp [validate, valid, different]
  · simp only [↓reduceIte]
    have same : bytes schema.val = bytes expectedSchema.val := by
      apply (bytes_injective schema.val expectedSchema.val).mpr
      simpa using schemaEq.symm
    step with counter_hex_matches_spec as ⟨sameCounter, counterEq⟩
    cases sameCounter
    · simp only [Bool.false_eq_true, ↓reduceIte, spec_ok]
      have different : ¬ hexMatches (bytes stored.val) (bytes counter.val) := by simpa using counterEq.symm
      simp [validate, valid, different]
    · simp only [↓reduceIte]
      have counterBound : hexMatches (bytes stored.val) (bytes counter.val) := by simpa using counterEq.symm
      split <;> rename_i sameSlot
      · simp only [spec_ok]
        have different : values.slot.val ≠ expectedSlot.val := by simpa using sameSlot
        simp [validate, valid, valuesView, different]
      · split <;> rename_i amountBound
        · simp only [spec_ok]
          have tooLarge : ¬ values.amount.val ≤ values.cumulative.val := by scalar_tac
          simp [validate, valid, valuesView, tooLarge]
        · simp only [spec_ok]
          have slotBound : values.slot.val = expectedSlot.val := by simpa using sameSlot
          have deltaBound : values.amount.val ≤ values.cumulative.val := by scalar_tac
          simp [validate, valid, valuesView, same, counterBound, slotBound, deltaBound]

theorem source_accepted_binds_record (schema expectedSchema stored : Slice Std.U8)
    (counter : Array Std.U8 32#usize) (expectedSlot : Std.U64) (values : slot_record.SumValues) :
    slot_record.validate_cumulative schema expectedSchema stored counter expectedSlot values ⦃ actual =>
      ∀ value, actual = some value →
        schema.val = expectedSchema.val ∧ hexMatches (bytes stored.val) (bytes counter.val) ∧
        values.slot.val = expectedSlot.val ∧ values.amount.val ≤ value.val ∧ value.val = values.cumulative.val ⦄ := by
  step with validate_cumulative_exact as ⟨actual, exactMeaning⟩
  rename_i value accepted
  rw [accepted] at exactMeaning
  have bound := accepted_binds_slot _ _ _ _ _ _ _ exactMeaning.symm
  exact ⟨(bytes_injective _ _).mp bound.1, bound.2⟩

theorem source_invalid_record_refused (schema expectedSchema stored : Slice Std.U8)
    (counter : Array Std.U8 32#usize) (expectedSlot : Std.U64) (values : slot_record.SumValues)
    (invalid : ¬ valid (bytes schema.val) (bytes expectedSchema.val) (bytes stored.val)
      (bytes counter.val) expectedSlot.val (valuesView values)) :
    slot_record.validate_cumulative schema expectedSchema stored counter expectedSlot values ⦃ actual => actual = none ⦄ := by
  step with validate_cumulative_exact as ⟨actual, exactMeaning⟩
  have empty : actual.map UScalar.val = none := by simpa [validate, invalid] using exactMeaning
  exact Option.map_eq_none_iff.mp empty

end Auths.Product.SlotRecord.Refinement
