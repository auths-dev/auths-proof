import Auths.Product.ReservationAdmission
import Auths.Product.Refinement
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_bounded_policy
open Auths.Product.Refinement
namespace Auths.Product.ReservationAdmission.Refinement
set_option maxHeartbeats 2000000

def codeView : kernel.ReservationCode → Code
  | .Admit => .admit
  | .WindowExhausted => .windowExhausted
  | .SumExhausted => .sumExhausted

@[step] theorem reservation_admission_exact
    (counts countCaps slots slotCaps totals sumCaps : Slice Std.U64) (amount : Std.U64) :
    kernel.reservation_admission counts countCaps slots slotCaps totals sumCaps amount ⦃ actual =>
      codeView actual = decideReservation (natList counts.val) (natList countCaps.val)
        (natList slots.val) (natList slotCaps.val) (natList totals.val) (natList sumCaps.val) amount.val ⦄ := by
  unfold kernel.reservation_admission
  step with translated_chain_counts_admit_refines_model as ⟨countsFit, countMeaning⟩
  cases countsFit
  · simp only [Bool.false_eq_true, ↓reduceIte, spec_ok]
    have noRoom : ¬ CountRoom (natList counts.val) (natList countCaps.val) := by
      intro room
      have admitted := (counts_admit_iff _ _).mpr room
      rw [← countMeaning] at admitted
      contradiction
    simp [codeView, decideReservation, noRoom]
  · simp only [↓reduceIte]
    have countRoom : CountRoom (natList counts.val) (natList countCaps.val) :=
      (counts_admit_iff _ _).mp countMeaning.symm
    step with translated_chain_counts_admit_refines_model as ⟨slotsFit, slotMeaning⟩
    cases slotsFit
    · simp only [Bool.false_eq_true, ↓reduceIte, spec_ok]
      have noRoom : ¬ CountRoom (natList slots.val) (natList slotCaps.val) := by
        intro room
        have admitted := (counts_admit_iff _ _).mpr room
        rw [← slotMeaning] at admitted
        contradiction
      simp [codeView, decideReservation, noRoom]
    · simp only [↓reduceIte]
      have slotRoom : CountRoom (natList slots.val) (natList slotCaps.val) :=
        (counts_admit_iff _ _).mp slotMeaning.symm
      step with translated_chain_sums_admit_refines_model as ⟨sumsFit, sumMeaning⟩
      cases sumsFit
      · simp only [Bool.false_eq_true, ↓reduceIte, spec_ok]
        have noRoom : ¬ SumRoom (natList totals.val) amount.val (natList sumCaps.val) := by
          intro room
          have admitted := (sums_admit_iff _ _ _).mpr room
          rw [← sumMeaning] at admitted
          contradiction
        simp [codeView, decideReservation, countRoom, slotRoom, noRoom]
      · simp only [↓reduceIte, spec_ok]
        have sumRoom : SumRoom (natList totals.val) amount.val (natList sumCaps.val) :=
          (sums_admit_iff _ _ _).mp sumMeaning.symm
        simp [codeView, decideReservation, countRoom, slotRoom, sumRoom]

theorem source_admission_earns_bounds
    (counts countCaps slots slotCaps totals sumCaps : Slice Std.U64) (amount : Std.U64) :
    kernel.reservation_admission counts countCaps slots slotCaps totals sumCaps amount ⦃ actual =>
      actual = .Admit →
        CountRoom (natList counts.val) (natList countCaps.val) ∧
        CountRoom (natList slots.val) (natList slotCaps.val) ∧
        SumRoom (natList totals.val) amount.val (natList sumCaps.val) ⦄ := by
  step with reservation_admission_exact as ⟨actual, exactMeaning⟩
  rename_i accepted
  rw [accepted] at exactMeaning
  exact (admitted_iff _ _ _ _ _ _ _).mp exactMeaning.symm

theorem source_window_refusal_precedes_sum
    (counts countCaps slots slotCaps totals sumCaps : Slice Std.U64) (amount : Std.U64)
    (exhausted : ¬ CountRoom (natList counts.val) (natList countCaps.val) ∨
      ¬ CountRoom (natList slots.val) (natList slotCaps.val)) :
    kernel.reservation_admission counts countCaps slots slotCaps totals sumCaps amount ⦃ actual =>
      actual = .WindowExhausted ⦄ := by
  step with reservation_admission_exact as ⟨actual, exactMeaning⟩
  rw [window_refusal_precedes_sum _ _ _ _ _ _ _ exhausted] at exactMeaning
  cases actual <;> simp_all [codeView]
theorem source_admitted_has_complete_vectors
    (counts countCaps slots slotCaps totals sumCaps : Slice Std.U64) (amount : Std.U64) :
    kernel.reservation_admission counts countCaps slots slotCaps totals sumCaps amount ⦃ actual =>
      actual = .Admit → counts.val.length = countCaps.val.length ∧
        slots.val.length = slotCaps.val.length ∧ totals.val.length = sumCaps.val.length ⦄ := by
  step with reservation_admission_exact as ⟨actual, exactMeaning⟩
  rename_i accepted
  rw [accepted] at exactMeaning
  simpa only [natList, List.length_map] using admitted_shapes _ _ _ _ _ _ _ exactMeaning.symm

theorem source_admitted_sums_do_not_overflow
    (counts countCaps slots slotCaps totals sumCaps : Slice Std.U64) (amount : Std.U64) :
    kernel.reservation_admission counts countCaps slots slotCaps totals sumCaps amount ⦃ actual =>
      actual = .Admit → ∀ index, index < totals.val.length →
        (natList totals.val)[index]! + amount.val ≤ U64.max ⦄ := by
  step with reservation_admission_exact as ⟨actual, exactMeaning⟩
  rename_i accepted index inside
  rw [accepted] at exactMeaning
  have shape := admitted_shapes _ _ _ _ _ _ _ exactMeaning.symm
  have capInside : index < sumCaps.val.length := by simpa only [natList, List.length_map] using (show index < (natList sumCaps.val).length by rw [← shape.2.2]; simpa [natList] using inside)
  have point := admitted_sum_at _ _ _ _ _ _ _ index exactMeaning.symm (by simpa [natList] using inside)
  rw [getElem!_pos (natList sumCaps.val) index (by simpa [natList] using capInside)] at point
  have capacityMax : sumCaps.val[index].val ≤ U64.max := by scalar_tac
  apply point.trans
  simpa only [natList, List.getElem_map] using capacityMax

end Auths.Product.ReservationAdmission.Refinement
