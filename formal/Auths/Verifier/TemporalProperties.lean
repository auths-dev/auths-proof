import Auths.Verifier.TemporalModel
import Mathlib.Tactic
namespace Auths.TemporalWitness

/-- This checks expiry only. The evaluator separately establishes observation
time ordering, claim validity, and which records satisfy the policy. -/
def selectedExpiryAllows (ages : List (Option Nat)) (record : Witness) (now : Nat) : Prop :=
  match ages[record.requirementIndex]? with
  | none => False
  | some none => True
  | some (some age) =>
    match record.observedAt with
    | none => False
    | some observed => now ≤ min wordMaximum (observed + age)

theorem assurance_permits_iff (ages : List (Option Nat)) (records : List Witness)
    (initial now : Nat) :
    (∃ horizon, assuranceHorizon ages records initial = .ok horizon ∧ now ≤ horizon) ↔
      now ≤ initial ∧ ∀ record ∈ records, selectedExpiryAllows ages record now := by
  induction records generalizing initial with
  | nil => simp [assuranceHorizon]
  | cons record rest ih =>
    cases selected : ages[record.requirementIndex]? with
    | none => simp [assuranceHorizon, selectedExpiryAllows, selected]
    | some age =>
      cases age with
      | none =>
        simpa [assuranceHorizon, selectedExpiryAllows, selected] using ih initial
      | some age =>
        cases observed : record.observedAt with
        | none => simp [assuranceHorizon, selectedExpiryAllows, selected, observed]
        | some atTime =>
          simpa [assuranceHorizon, selectedExpiryAllows, selected, observed,
            le_min_iff, and_assoc, and_left_comm, and_comm] using
            ih (min initial (min wordMaximum (atTime + age)))

theorem successful_horizon_bounded (ages : List (Option Nat)) (records : List Witness)
    (initial horizon : Nat) (accepted : assuranceHorizon ages records initial = .ok horizon) :
    horizon ≤ initial ∧ ∀ record ∈ records, selectedExpiryAllows ages record horizon :=
  (assurance_permits_iff ages records initial horizon).mp ⟨horizon, accepted, Nat.le_refl _⟩

end Auths.TemporalWitness
