import Auths.Verifier.TemporalAssurance
import Auths.Verifier.TemporalProperties
import Auths.Verifier.TemporalStatus
open Aeneas Aeneas.Std Result
open AuthsTemporalWitness
namespace Auths.TemporalWitness

theorem successful_native_horizon_exact (records : Slice auths_model.AssuranceSatisfaction)
    (context : auths_model.TrustedContext) (horizon : auths_model.Timestamp)
    (accepted : assurance_horizon records context = ok (.Ok horizon)) :
    assuranceHorizon (policyView context) (records.val.map witnessView) wordMaximum = .ok horizon.val := by
  have contract := assurance_entry_refines records context
  rw [accepted] at contract
  simp only [Aeneas.Std.WP.spec_ok] at contract
  cases model : assuranceHorizon (policyView context) (records.val.map witnessView) wordMaximum with
  | error reason => simp [AssuranceRefines, model] at contract
  | ok value =>
    have meaning : horizon.val = value := by
      simpa [AssuranceRefines, model] using contract
    simp [meaning]

theorem native_horizon_permits_iff (records : Slice auths_model.AssuranceSatisfaction)
    (context : auths_model.TrustedContext) (horizon : auths_model.Timestamp)
    (accepted : assurance_horizon records context = ok (.Ok horizon)) (now : Nat) :
    now ≤ horizon.val ↔ now ≤ wordMaximum ∧
      ∀ record ∈ records.val, selectedExpiryAllows (policyView context) (witnessView record) now := by
  have result := assurance_permits_iff (policyView context) (records.val.map witnessView) wordMaximum now
  rw [successful_native_horizon_exact records context horizon accepted] at result
  simpa using result

end Auths.TemporalWitness
