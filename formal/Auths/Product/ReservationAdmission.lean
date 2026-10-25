import Auths.Product.CeilingCount
import Mathlib.Data.List.Forall2
import Mathlib.Tactic
namespace Auths.Product.ReservationAdmission
open Auths.Product.CeilingCount

inductive Code where
  | admit
  | windowExhausted
  | sumExhausted
  deriving DecidableEq

abbrev CountRoom (frontiers capacities : List Nat) := List.Forall₂ (· < ·) frontiers capacities
abbrev SumRoom (totals : List Nat) (amount : Nat) (capacities : List Nat) :=
  List.Forall₂ (fun total cap => total + amount ≤ cap) totals capacities

def decideReservation (counts countCaps slots slotCaps totals sumCaps : List Nat) (amount : Nat) : Code :=
  if CountRoom counts countCaps ∧ CountRoom slots slotCaps then
    if SumRoom totals amount sumCaps then .admit else .sumExhausted
  else .windowExhausted

theorem counts_admit_iff (values capacities : List Nat) :
    countsAdmit values capacities = true ↔ CountRoom values capacities := by
  simp [countsAdmit, CountRoom, List.forall₂_iff_zip, List.all_eq_true, Prod.forall]

theorem sums_admit_iff (values capacities : List Nat) (amount : Nat) :
    sumsAdmit values amount capacities = true ↔ SumRoom values amount capacities := by
  simp [sumsAdmit, SumRoom, List.forall₂_iff_zip, List.all_eq_true, Prod.forall]

theorem admitted_iff (counts countCaps slots slotCaps totals sumCaps : List Nat) (amount : Nat) :
    decideReservation counts countCaps slots slotCaps totals sumCaps amount = .admit ↔
      CountRoom counts countCaps ∧ CountRoom slots slotCaps ∧ SumRoom totals amount sumCaps := by
  by_cases countRoom : CountRoom counts countCaps <;>
    by_cases slotRoom : CountRoom slots slotCaps <;>
    by_cases sumRoom : SumRoom totals amount sumCaps <;>
    simp [decideReservation, countRoom, slotRoom, sumRoom]

theorem admitted_shapes (counts countCaps slots slotCaps totals sumCaps : List Nat) (amount : Nat)
    (admitted : decideReservation counts countCaps slots slotCaps totals sumCaps amount = .admit) :
    counts.length = countCaps.length ∧ slots.length = slotCaps.length ∧ totals.length = sumCaps.length := by
  have room := (admitted_iff _ _ _ _ _ _ _).mp admitted
  exact ⟨room.1.length_eq, room.2.1.length_eq, room.2.2.length_eq⟩

theorem admitted_sum_at (counts countCaps slots slotCaps totals sumCaps : List Nat) (amount index : Nat)
    (admitted : decideReservation counts countCaps slots slotCaps totals sumCaps amount = .admit)
    (inside : index < totals.length) : totals[index]! + amount ≤ sumCaps[index]! := by
  have room := ((admitted_iff _ _ _ _ _ _ _).mp admitted).2.2
  have capInside : index < sumCaps.length := by rw [← room.length_eq]; exact inside
  have point := room.get inside capInside
  simpa only [getElem!_pos totals index inside, getElem!_pos sumCaps index capInside, List.get_eq_getElem] using point

theorem window_refusal_precedes_sum (counts countCaps slots slotCaps totals sumCaps : List Nat) (amount : Nat)
    (exhausted : ¬ CountRoom counts countCaps ∨ ¬ CountRoom slots slotCaps) :
    decideReservation counts countCaps slots slotCaps totals sumCaps amount = .windowExhausted := by
  simp only [decideReservation]
  have noRoom : ¬ (CountRoom counts countCaps ∧ CountRoom slots slotCaps) := by tauto
  simp [noRoom]
end Auths.Product.ReservationAdmission
