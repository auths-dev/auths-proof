import qualification.aeneas.generated.connections.Funs
import Auths.Product.RecoveryGateRefinement
import Mathlib.Tactic
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_connections
namespace Auths.Product.RecordTimes.Refinement
open model


def valid (state : ConnectionState) (created updated : Nat) (revoked : Option Nat) : Prop :=
  created ≤ updated ∧ match state, revoked with
  | .Revoked, some atTime => created ≤ atTime ∧ atTime ≤ updated
  | .Revoked, none => False
  | .Active, none | .Disabled, none => True
  | .Active, some _ | .Disabled, some _ => False
instance (state : ConnectionState) (created updated : Nat) (revoked : Option Nat) :
    Decidable (valid state created updated revoked) := by
  cases state <;> cases revoked <;> unfold valid <;> infer_instance

@[step] theorem record_times_exact (state : ConnectionState) (created updated : Std.U64) (revoked : Option Std.U64) :
    kernel.record_times_valid state created updated revoked ⦃ actual =>
      actual = decide (valid state created.val updated.val (revoked.map (·.val))) ⦄ := by
  cases hstate : state <;> cases hrevoked : revoked <;> unfold kernel.record_times_valid
  all_goals repeat' split
  all_goals simp_all [spec_ok, valid, UScalar.lt_equiv, UScalar.le_equiv]

theorem success_earns_order (state : ConnectionState) (created updated : Std.U64) (revoked : Option Std.U64) :
    kernel.record_times_valid state created updated revoked ⦃ actual => actual = true → created.val ≤ updated.val ⦄ := by
  step with record_times_exact as ⟨actual, exactMeaning⟩
  rename_i accepted
  rw [accepted] at exactMeaning
  have checked : valid state created.val updated.val (revoked.map (·.val)) := by simpa using exactMeaning.symm
  exact checked.1

theorem success_earns_revocation_shape (state : ConnectionState) (created updated : Std.U64) (revoked : Option Std.U64) :
    kernel.record_times_valid state created updated revoked ⦃ actual => actual = true →
      (state = .Revoked ↔ revoked.isSome = true) ∧
      ∀ atTime, revoked = some atTime → created.val ≤ atTime.val ∧ atTime.val ≤ updated.val ⦄ := by
  step with record_times_exact as ⟨actual, exactMeaning⟩
  rename_i accepted
  rw [accepted] at exactMeaning
  have checked : valid state created.val updated.val (revoked.map (·.val)) := by simpa using exactMeaning.symm
  cases hstate : state <;> cases hrevoked : revoked <;> simp_all [valid]

theorem state_change_preserves_valid_time (current next : ConnectionState)
    (created previous proposed : Nat) (revoked : Option Nat)
    (before : valid current created previous revoked)
    (allowed : current ≠ .Revoked ∧ current ≠ next ∧ previous ≤ proposed) :
    valid next created proposed (if next = .Revoked then some proposed else none) := by
  have ordered := before.1
  cases hnext : next <;> simp_all [valid]
  all_goals omega

theorem data_change_preserves_valid_time (state : ConnectionState)
    (created previous proposed : Nat) (revoked : Option Nat)
    (before : valid state created previous revoked)
    (allowed : state ≠ .Revoked ∧ previous ≤ proposed) :
    valid state created proposed none := by
  have ordered := before.1
  cases hstate : state <;> simp_all [valid]
  all_goals omega

end Auths.Product.RecordTimes.Refinement
