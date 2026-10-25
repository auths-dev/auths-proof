import Mathlib.Tactic

namespace Auths.Verifier.WorkMeterModel

def wordMaximum : Nat := 2 ^ 64 - 1

structure State where
  used : Nat
  limit : Nat
  deriving DecidableEq, Repr

structure Reservation where
  accepted : Bool
  state : State
  deriving DecidableEq, Repr

def reserve (state : State) (maximum : Nat) : Reservation :=
  if state.used + maximum ≤ wordMaximum ∧ state.used + maximum ≤ state.limit
  then ⟨true, ⟨state.used + maximum, state.limit⟩⟩
  else ⟨false, state⟩

@[simp] theorem limit_unchanged (state : State) (maximum : Nat) :
    (reserve state maximum).state.limit = state.limit := by
  unfold reserve
  split <;> rfl

theorem refusal_unchanged (state : State) (maximum : Nat)
    (refused : (reserve state maximum).accepted = false) :
    (reserve state maximum).state = state := by
  unfold reserve at refused ⊢
  split at refused ⊢ <;> simp_all

theorem accepted_exact (state : State) (maximum : Nat) :
    (reserve state maximum).accepted = true ↔
      state.used + maximum ≤ wordMaximum ∧ state.used + maximum ≤ state.limit := by
  simp [reserve]

theorem accepted_charge (state : State) (maximum : Nat)
    (accepted : (reserve state maximum).accepted = true) :
    (reserve state maximum).state.used = state.used + maximum := by
  have fits := (accepted_exact state maximum).mp accepted
  simp [reserve, fits]

theorem step_bounded (state : State) (maximum : Nat) (bounded : state.used ≤ state.limit) :
    (reserve state maximum).state.used ≤ state.limit := by
  unfold reserve
  split
  · rename_i fits
    exact fits.2
  · exact bounded

def run (state : State) : List Nat → State
  | [] => state
  | maximum :: rest => run (reserve state maximum).state rest

def charged (state : State) : List Nat → Nat
  | [] => 0
  | maximum :: rest =>
    (if (reserve state maximum).accepted then maximum else 0) +
      charged (reserve state maximum).state rest

theorem history_limit (state : State) (requests : List Nat) :
    (run state requests).limit = state.limit := by
  induction requests generalizing state with
  | nil => rfl
  | cons maximum rest ih => simp [run, ih]

theorem history_charge_exact (state : State) (requests : List Nat) :
    (run state requests).used = state.used + charged state requests := by
  induction requests generalizing state with
  | nil => simp [run, charged]
  | cons maximum rest ih =>
    rw [run, ih]
    cases accepted : (reserve state maximum).accepted with
    | false =>
      have unchanged := refusal_unchanged state maximum accepted
      simp [charged, accepted, unchanged]
    | true =>
      have exactCharge := accepted_charge state maximum accepted
      simp [charged, accepted, exactCharge, Nat.add_assoc]

theorem every_history_bounded (state : State) (requests : List Nat) (bounded : state.used ≤ state.limit) :
    (run state requests).used ≤ state.limit := by
  induction requests generalizing state with
  | nil => exact bounded
  | cons maximum rest ih =>
    have nextBound : (reserve state maximum).state.used ≤ (reserve state maximum).state.limit := by
      rw [limit_unchanged]
      exact step_bounded state maximum bounded
    simpa [run] using ih (reserve state maximum).state nextBound

example : run ⟨0, 5⟩ [3, 3, 2] = ⟨5, 5⟩ := by decide
example : charged ⟨0, 5⟩ [3, 3, 2] = 5 := by decide
example : (reserve ⟨wordMaximum, wordMaximum⟩ 1).accepted = false := by decide

end Auths.Verifier.WorkMeterModel
