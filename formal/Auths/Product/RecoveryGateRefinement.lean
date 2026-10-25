import qualification.aeneas.generated.connections.Funs
import Mathlib.Tactic
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_connections
namespace Auths.Product.RecoveryGate.Refinement
open model

deriving instance DecidableEq for ConnectionState

@[step] theorem recovery_exact (state : ConnectionState) (current requested : Std.U64) :
    kernel.recovery_lease state current requested ⦃ actual =>
      actual = if state = .Revoked then .Err .Revoked
        else if current.val = 0 ∨ requested.val = 0 ∨ current.val < requested.val
          then .Err .InvalidGeneration else .Ok () ⦄ := by
  cases hstate : state <;> unfold kernel.recovery_lease
  all_goals simp only [reduceCtorEq, ↓reduceIte, UScalar.eq_equiv, UScalar.lt_equiv, UScalar.ofNatCore_val_eq]
  all_goals repeat' split
  all_goals simp_all [spec_ok]
  all_goals omega

theorem revoked_refuses_every_generation (current requested : Std.U64) :
    kernel.recovery_lease .Revoked current requested ⦃ actual => actual = .Err .Revoked ⦄ := by
  exact recovery_exact .Revoked current requested

theorem success_earns_generation_and_state (state : ConnectionState) (current requested : Std.U64) :
    kernel.recovery_lease state current requested ⦃ actual => actual = .Ok () →
      state ≠ .Revoked ∧ 0 < requested.val ∧ requested.val ≤ current.val ⦄ := by
  step with recovery_exact as ⟨actual, exactMeaning⟩
  rename_i accepted
  rw [accepted] at exactMeaning
  split at exactMeaning
  · contradiction
  · split at exactMeaning
    · contradiction
    · simp_all
      omega

@[step] theorem binding_requirement_exact (current operation credential : Std.U64) :
    kernel.recovery_binding_requirement current operation credential ⦃ actual =>
      actual = if current.val = 0 ∨ operation.val = 0 ∨ credential.val = 0 ∨ operation.val < credential.val
        then kernel.RecoveryBindingRequirement.Refuse
        else if operation.val < current.val then .RecordedCommitment
        else if credential.val = current.val then .CurrentCommitment else .Refuse ⦄ := by
  unfold kernel.recovery_binding_requirement
  repeat' split
  all_goals simp_all [spec_ok, UScalar.eq_equiv, UScalar.le_equiv, UScalar.lt_equiv]
  all_goals omega

theorem current_requirement_earns_exact_generation (current operation credential : Std.U64) :
    kernel.recovery_binding_requirement current operation credential ⦃ actual =>
      actual = .CurrentCommitment → credential = current ∧ 0 < current.val ∧ current.val ≤ operation.val ⦄ := by
  step with binding_requirement_exact as ⟨actual, exactMeaning⟩
  rename_i accepted
  rw [accepted] at exactMeaning
  split at exactMeaning
  · contradiction
  · split at exactMeaning
    · contradiction
    · split at exactMeaning
      · constructor
        · scalar_tac
        · constructor <;> omega
      · contradiction

theorem recorded_requirement_earns_older_generation (current operation credential : Std.U64) :
    kernel.recovery_binding_requirement current operation credential ⦃ actual =>
      actual = .RecordedCommitment → 0 < credential.val ∧ credential.val ≤ operation.val ∧ operation.val < current.val ⦄ := by
  step with binding_requirement_exact as ⟨actual, exactMeaning⟩
  rename_i accepted
  rw [accepted] at exactMeaning
  split at exactMeaning
  · contradiction
  · split at exactMeaning
    · constructor
      · omega
      · constructor <;> omega
    · split at exactMeaning <;> contradiction

@[step] theorem state_transition_exact (current next : ConnectionState) (previous proposed : Std.U64) :
    kernel.state_transition_allows current next previous proposed ⦃ actual =>
      actual = decide (current ≠ .Revoked ∧ current ≠ next ∧ previous.val ≤ proposed.val) ⦄ := by
  cases hcurrent : current <;> cases hnext : next <;> unfold kernel.state_transition_allows
  all_goals simp only [UScalar.lt_equiv]
  all_goals split <;> simp_all [spec_ok]

theorem state_transition_earns_terminal_and_time (current next : ConnectionState) (previous proposed : Std.U64) :
    kernel.state_transition_allows current next previous proposed ⦃ actual => actual = true →
      current ≠ .Revoked ∧ current ≠ next ∧ previous.val ≤ proposed.val ⦄ := by
  step with state_transition_exact as ⟨actual, exactMeaning⟩
  rename_i accepted
  rw [accepted] at exactMeaning
  simpa using exactMeaning.symm


@[step] theorem record_change_exact (state : ConnectionState) (previous proposed : Std.U64) :
    kernel.record_change_allows state previous proposed ⦃ actual =>
      actual = decide (state ≠ .Revoked ∧ previous.val ≤ proposed.val) ⦄ := by
  cases hstate : state <;> unfold kernel.record_change_allows
  all_goals simp [spec_ok, UScalar.le_equiv, hstate]

theorem record_change_earns_terminal_and_time (state : ConnectionState) (previous proposed : Std.U64) :
    kernel.record_change_allows state previous proposed ⦃ actual => actual = true →
      state ≠ .Revoked ∧ previous.val ≤ proposed.val ⦄ := by
  step with record_change_exact as ⟨actual, exactMeaning⟩
  rename_i accepted
  rw [accepted] at exactMeaning
  simpa using exactMeaning.symm

end Auths.Product.RecoveryGate.Refinement
