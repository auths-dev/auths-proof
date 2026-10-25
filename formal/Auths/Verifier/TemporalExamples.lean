import Auths.Verifier.TemporalConsequences
open Aeneas Aeneas.Std Result
open AuthsTemporalWitness
namespace Auths.TemporalWitness.Examples

theorem inclusive_status_endpoint :
    status_horizon ⟨.Active, 100#u64⟩ 100#u64 = ok (.Ok 100#u64) := by
  rw [status_horizon_exact]
  simp [UScalar.ofNatCore_val_eq]

theorem expired_status_refused :
    status_horizon ⟨.Active, 100#u64⟩ 101#u64 = ok (.Err (.Indeterminate .StaleStatus)) := by
  rw [status_horizon_exact]
  simp [UScalar.ofNatCore_val_eq]

theorem revoked_principal_refused :
    status_decision .Revoked true = ok (.Err (.Denied .PrincipalRevoked)) := rfl

theorem revoked_grant_refused :
    status_decision .Revoked false = ok (.Err (.Denied .GrantRevoked)) := rfl

theorem selected_expiry_admitted :
    assuranceHorizon [some 20] [⟨0, some 100⟩] wordMaximum = .ok 120 := by decide

theorem missing_requirement_refused :
    assuranceHorizon [some 20] [⟨1, some 100⟩] wordMaximum = .error () := by decide

theorem missing_observation_refused :
    assuranceHorizon [some 20] [⟨0, none⟩] wordMaximum = .error () := by decide

theorem unbounded_requirement_needs_no_observation :
    assuranceHorizon [none] [⟨0, none⟩] wordMaximum = .ok wordMaximum := by decide

theorem overflowing_expiry_saturates :
    assuranceHorizon [some 20] [⟨0, some wordMaximum⟩] wordMaximum = .ok wordMaximum := by decide

end Auths.TemporalWitness.Examples
