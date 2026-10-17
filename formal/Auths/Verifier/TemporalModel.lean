import Std.Tactic

-- Independent expiry and status semantics; no generated Rust import.
namespace Auths.TemporalWitness

def wordMaximum : Nat := 2 ^ 64 - 1

def statusHorizon (horizon evaluatedAt : Nat) : Except Unit Nat :=
  if evaluatedAt ≤ horizon then .ok horizon else .error ()

structure Witness where
  requirementIndex : Nat
  observedAt : Option Nat

def assuranceHorizon (maximumAges : List (Option Nat)) : List Witness → Nat → Except Unit Nat
  | [], initial => .ok initial
  | witness :: rest, initial =>
    match maximumAges[witness.requirementIndex]? with
    | none => .error ()
    | some none => assuranceHorizon maximumAges rest initial
    | some (some age) =>
      match witness.observedAt with
      | none => .error ()
      | some observed =>
        assuranceHorizon maximumAges rest (min initial (min wordMaximum (observed + age)))


namespace Status

inductive State where
  | active | revoked | missing | stale | rollback | untrustedIssuer | wrongMethod

inductive Failure where
  | principalRevoked | grantRevoked | missingPrincipal | missingGrant
  | stale | rollback | untrustedIssuer | wrongMethod

def evaluate (principal : Bool) : State → Except Failure Unit
  | .active => .ok ()
  | .revoked => .error (if principal then .principalRevoked else .grantRevoked)
  | .missing => .error (if principal then .missingPrincipal else .missingGrant)
  | .stale => .error .stale
  | .rollback => .error .rollback
  | .untrustedIssuer => .error .untrustedIssuer
  | .wrongMethod => .error .wrongMethod

end Status

end Auths.TemporalWitness
