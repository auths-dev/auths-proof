import Auths.Verifier.TemporalNative
open Aeneas Aeneas.Std Result
open AuthsTemporalWitness
namespace Auths.TemporalWitness.Status

def stateView : auths_ports.StatusDecision → State
  | .Active => .active | .Revoked => .revoked | .Missing => .missing | .Stale => .stale
  | .Rollback => .rollback | .UntrustedIssuer => .untrustedIssuer | .WrongMethod => .wrongMethod

def errorValue : Failure → VerificationFailure
  | .principalRevoked => .Denied .PrincipalRevoked
  | .grantRevoked => .Denied .GrantRevoked
  | .missingPrincipal => .Indeterminate .MissingPrincipalStatus
  | .missingGrant => .Indeterminate .MissingGrantStatus
  | .stale => .Indeterminate .StaleStatus
  | .rollback => .Denied .StatusSequenceRollback
  | .untrustedIssuer => .Denied .StatusIssuerUntrusted
  | .wrongMethod => .Denied .StatusMethodMismatch

def resultValue : Except Failure Unit → core.result.Result Unit VerificationFailure
  | .ok value => .Ok value | .error reason => .Err (errorValue reason)

theorem decision_refines (decision : auths_ports.StatusDecision) (principal : Bool) :
    status_decision decision principal = ok (resultValue (evaluate principal (stateView decision))) := by
  cases decision <;> cases principal <;> rfl

end Auths.TemporalWitness.Status
