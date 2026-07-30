import Mathlib.Data.Nat.Basic

namespace Auths.Lifecycle

inductive State where
  | decisionRecorded
  | reserved
  | executionIntentRecorded
  | executing
  | committed
  | released
  | outcomeUnknown
  | reconciledCommitted
  | reconciledReleased
  deriving BEq, DecidableEq, Repr

def State.isTerminal : State → Bool
  | .committed | .released | .reconciledCommitted | .reconciledReleased => true
  | _ => false

inductive Operation where
  | recordDecision
  | reserve
  | recordExecutionIntent
  | authorizeCredential
  | startAttempt
  | markProviderCallEntered
  | commit
  | release
  | markOutcomeUnknown
  | reconcileEffect
  | reconcileNonEffect
  | reconcileInconclusive
  deriving BEq, DecidableEq, Repr

structure Gates where
  coreAuthorized : Bool
  policyEligible : Bool
  configurationMatches : Bool
  notRevoked : Bool
  notExpired : Bool
  capacityAvailable : Bool
  executionIntentPresent : Bool
  credentialAuthorized : Bool
  attemptPresent : Bool
  providerCallEntered : Bool
  cancellationAllowed : Bool
  definiteEffect : Bool
  definiteNonEffect : Bool
  reconciliationFresh : Bool
  reconciliationMatches : Bool
  deriving BEq, DecidableEq, Repr

inductive Code where
  | applied (state : State)
  | observationOnly
  | terminal
  | illegalTransition
  | notAuthorized
  | notEligible
  | configurationMismatch
  | revoked
  | expired
  | capacityExceeded
  | executionIntentMissing
  | credentialNotAuthorized
  | attemptMissing
  | providerCallNotEntered
  | effectNotProved
  | nonEffectNotProved
  | reconciliationStale
  | reconciliationMismatch
  deriving BEq, DecidableEq, Repr

def reconciliationCode (gates : Gates) (next : State) : Code :=
  if !gates.reconciliationFresh then
    .reconciliationStale
  else if !gates.reconciliationMatches then
    .reconciliationMismatch
  else
    .applied next

def transitionCode
    (current : Option State) (operation : Operation) (gates : Gates) : Code :=
  if current.any State.isTerminal then
    .terminal
  else
    match current, operation with
    | none, .recordDecision =>
        if !gates.coreAuthorized then .notAuthorized
        else if !gates.policyEligible then .notEligible
        else if !gates.configurationMatches then .configurationMismatch
        else if !gates.notRevoked then .revoked
        else if !gates.notExpired then .expired
        else .applied .decisionRecorded
    | some .decisionRecorded, .reserve =>
        if !gates.configurationMatches then .configurationMismatch
        else if !gates.notRevoked then .revoked
        else if !gates.notExpired then .expired
        else if !gates.capacityAvailable then .capacityExceeded
        else .applied .reserved
    | some .reserved, .recordExecutionIntent =>
        if !gates.configurationMatches then .configurationMismatch
        else if !gates.notRevoked then .revoked
        else if !gates.notExpired then .expired
        else if !gates.executionIntentPresent then .executionIntentMissing
        else .applied .executionIntentRecorded
    | some .executionIntentRecorded, .authorizeCredential =>
        if !gates.configurationMatches then .configurationMismatch
        else if !gates.notRevoked then .revoked
        else if !gates.notExpired then .expired
        else if !gates.executionIntentPresent then .executionIntentMissing
        else if gates.credentialAuthorized then .illegalTransition
        else .applied .executionIntentRecorded
    | some .executionIntentRecorded, .startAttempt =>
        if !gates.configurationMatches then .configurationMismatch
        else if !gates.notRevoked then .revoked
        else if !gates.notExpired then .expired
        else if !gates.executionIntentPresent then .executionIntentMissing
        else if !gates.credentialAuthorized then .credentialNotAuthorized
        else .applied .executing
    | some .executing, .markProviderCallEntered =>
        if gates.providerCallEntered then .illegalTransition
        else if gates.attemptPresent then .applied .executing
        else .attemptMissing
    | some .executing, .commit =>
        if !gates.attemptPresent then .attemptMissing
        else if !gates.providerCallEntered then .providerCallNotEntered
        else if !gates.definiteEffect then .effectNotProved
        else .applied .committed
    | some .reserved, .release =>
        if gates.attemptPresent then .illegalTransition
        else if !gates.cancellationAllowed && !gates.definiteNonEffect then
          .nonEffectNotProved
        else .applied .released
    | some .executionIntentRecorded, .release =>
        if gates.attemptPresent then .illegalTransition
        else .applied .released
    | some .executing, .release =>
        if !gates.attemptPresent then .attemptMissing
        else if !gates.definiteNonEffect then .nonEffectNotProved
        else .applied .released
    | some .executing, .markOutcomeUnknown =>
        if gates.attemptPresent then .applied .outcomeUnknown
        else .attemptMissing
    | some .outcomeUnknown, .reconcileEffect =>
        reconciliationCode gates .reconciledCommitted
    | some .outcomeUnknown, .reconcileNonEffect =>
        reconciliationCode gates .reconciledReleased
    | some .outcomeUnknown, .reconcileInconclusive =>
        if !gates.reconciliationFresh then .reconciliationStale
        else if !gates.reconciliationMatches then .reconciliationMismatch
        else .observationOnly
    | _, _ => .illegalTransition

def u64Max : Nat := 2 ^ 64 - 1

def additiveCapacityAvailable
    (ceiling committed active requested : Nat) : Bool :=
  ceiling != 0 &&
    requested != 0 &&
    committed + active ≤ u64Max &&
    committed + active + requested ≤ u64Max &&
    committed + active + requested ≤ ceiling

def exclusiveCapacityAvailable
    (hasLiveOwner ownerIsExactReplay : Bool) : Bool :=
  !hasLiveOwner || ownerIsExactReplay

inductive ReplayCode where
  | absent
  | exactReplay
  | conflict
  deriving BEq, DecidableEq, Repr

def replayCode (recordExists commitmentsEqual : Bool) : ReplayCode :=
  if !recordExists then .absent
  else if commitmentsEqual then .exactReplay
  else .conflict

structure CapacityLedger where
  ceiling : Nat
  committed : Nat
  active : Nat
  deriving BEq, DecidableEq, Repr

def CapacityLedger.valid (ledger : CapacityLedger) : Prop :=
  0 < ledger.ceiling ∧ ledger.committed + ledger.active ≤ ledger.ceiling

def CapacityLedger.reserve
    (ledger : CapacityLedger) (requested : Nat) : Option CapacityLedger :=
  if additiveCapacityAvailable
      ledger.ceiling ledger.committed ledger.active requested then
    some { ledger with active := ledger.active + requested }
  else
    none

def CapacityLedger.commit
    (ledger : CapacityLedger) (amount : Nat) : Option CapacityLedger :=
  if amount ≤ ledger.active then
    some {
      ledger with
      committed := ledger.committed + amount
      active := ledger.active - amount
    }
  else
    none

def CapacityLedger.release
    (ledger : CapacityLedger) (amount : Nat) : Option CapacityLedger :=
  if amount ≤ ledger.active then
    some { ledger with active := ledger.active - amount }
  else
    none

end Auths.Lifecycle
