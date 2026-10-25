import qualification.aeneas.generated.temporal_witness.Funs

open Aeneas Aeneas.Std Result
open AuthsTemporalWitness

namespace Auths.Verifier.ObservationControl

/-- Optional invalid/unavailable observation control supplies no witness;
exhaustion is a stage-level refusal. A successful payload is moved intact. -/
def classify {Payload : Type}
    (input : core.result.Result Payload auths_ports.PrincipalControlError) :
    core.result.Result (Option Payload) VerificationFailure :=
  match input with
  | .Ok payload => .Ok (some payload)
  | .Err .ResourceLimitExceeded => .Err (.Denied .ResourceLimitExceeded)
  | .Err _ => .Ok none

/-- Complete translated result, including exact failure code and payload;
no expected source outcome or validity of the adapter result is assumed. -/
theorem exact_result {Payload : Type}
    (input : core.result.Result Payload auths_ports.PrincipalControlError) :
    observation.control_result (T := Payload) input = ok (classify input) := by
  cases input with
  | Ok payload => rfl
  | Err failure => cases failure <;> rfl

theorem payload_exact {Payload : Type} (payload : Payload) :
    observation.control_result (T := Payload) (.Ok payload) = ok (.Ok (some payload)) := by
  simpa [classify] using exact_result (.Ok payload)

theorem resource_refused (Payload : Type) :
    observation.control_result (T := Payload) (.Err .ResourceLimitExceeded) =
      ok (.Err (.Denied .ResourceLimitExceeded)) := by
  simpa [classify] using exact_result (Payload := Payload) (.Err .ResourceLimitExceeded)

theorem ordinary_ignored (Payload : Type) (failure : auths_ports.PrincipalControlError)
    (ordinary : failure ≠ .ResourceLimitExceeded) :
    observation.control_result (T := Payload) (.Err failure) = ok (.Ok none) := by
  rw [exact_result]
  cases failure <;> simp_all [classify]

end Auths.Verifier.ObservationControl
