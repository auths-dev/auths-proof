import Auths.Lifecycle.Theorems
import qualification.aeneas.generated.lifecycle.Funs

open Aeneas Aeneas.Std Result

namespace Auths.Lifecycle.Refinement

@[simp] def generatedState :
    Auths.Lifecycle.State → auths_lifecycle.model.LifecycleState
  | .decisionRecorded => .DecisionRecorded
  | .reserved => .Reserved
  | .executionIntentRecorded => .ExecutionIntentRecorded
  | .executing => .Executing
  | .committed => .Committed
  | .released => .Released
  | .outcomeUnknown => .OutcomeUnknown
  | .reconciledCommitted => .ReconciledCommitted
  | .reconciledReleased => .ReconciledReleased

@[simp] def generatedOperation :
    Auths.Lifecycle.Operation → auths_lifecycle.kernel.OperationCode
  | .recordDecision => .RecordDecision
  | .reserve => .Reserve
  | .recordExecutionIntent => .RecordExecutionIntent
  | .authorizeCredential => .AuthorizeCredential
  | .startAttempt => .StartAttempt
  | .markProviderCallEntered => .MarkProviderCallEntered
  | .commit => .Commit
  | .release => .Release
  | .markOutcomeUnknown => .MarkOutcomeUnknown
  | .reconcileEffect => .ReconcileEffect
  | .reconcileNonEffect => .ReconcileNonEffect
  | .reconcileInconclusive => .ReconcileInconclusive

def generatedGates
    (gates : Auths.Lifecycle.Gates) :
    auths_lifecycle.kernel.TransitionGates where
  core_authorized := gates.coreAuthorized
  policy_eligible := gates.policyEligible
  configuration_matches := gates.configurationMatches
  not_revoked := gates.notRevoked
  not_expired := gates.notExpired
  capacity_available := gates.capacityAvailable
  execution_intent_present := gates.executionIntentPresent
  credential_authorized := gates.credentialAuthorized
  attempt_present := gates.attemptPresent
  provider_call_entered := gates.providerCallEntered
  cancellation_allowed := gates.cancellationAllowed
  definite_effect := gates.definiteEffect
  definite_non_effect := gates.definiteNonEffect
  reconciliation_fresh := gates.reconciliationFresh
  reconciliation_matches := gates.reconciliationMatches

def generatedCode :
    Auths.Lifecycle.Code → auths_lifecycle.kernel.KernelCode
  | .applied state => .Applied (generatedState state)
  | .observationOnly => .ObservationOnly
  | .terminal => .Terminal
  | .illegalTransition => .IllegalTransition
  | .notAuthorized => .NotAuthorized
  | .notEligible => .NotEligible
  | .configurationMismatch => .ConfigurationMismatch
  | .revoked => .Revoked
  | .expired => .Expired
  | .capacityExceeded => .CapacityExceeded
  | .executionIntentMissing => .ExecutionIntentMissing
  | .credentialNotAuthorized => .CredentialNotAuthorized
  | .attemptMissing => .AttemptMissing
  | .providerCallNotEntered => .ProviderCallNotEntered
  | .effectNotProved => .EffectNotProved
  | .nonEffectNotProved => .NonEffectNotProved
  | .reconciliationStale => .ReconciliationStale
  | .reconciliationMismatch => .ReconciliationMismatch

@[simp] def generatedReplayCode :
    Auths.Lifecycle.ReplayCode → auths_lifecycle.kernel.ReplayCode
  | .absent => .Absent
  | .exactReplay => .ExactReplay
  | .conflict => .Conflict

@[simp]
private theorem if_bool_eq_false {α : Sort _}
    (condition : Bool) (whenFalse whenTrue : α) :
    (if condition = false then whenFalse else whenTrue) =
      if condition = true then whenTrue else whenFalse := by
  cases condition <;> rfl

@[simp]
private theorem if_two_bools_eq_false {α : Sort _}
    (left right : Bool) (whenBothFalse otherwise : α) :
    (if left = false ∧ right = false then whenBothFalse else otherwise) =
      if left = true then otherwise
      else if right = true then otherwise
      else whenBothFalse := by
  cases left <;> cases right <;> rfl

@[simp]
private theorem generatedCode_ite
    (condition : Prop) [Decidable condition]
    (whenTrue whenFalse : Auths.Lifecycle.Code) :
    generatedCode (if condition then whenTrue else whenFalse) =
      if condition then generatedCode whenTrue else generatedCode whenFalse := by
  by_cases condition <;> simp_all

@[simp]
private theorem ok_ite {α : Type}
    (condition : Prop) [Decidable condition] (whenTrue whenFalse : α) :
    (ok (if condition then whenTrue else whenFalse) : Result α) =
      if condition then ok whenTrue else ok whenFalse := by
  by_cases condition <;> simp_all

@[simp] theorem generatedCode_applied
    (state : Auths.Lifecycle.State) :
    generatedCode (.applied state) =
      .Applied (generatedState state) := rfl

@[simp] theorem generatedCode_observationOnly :
    generatedCode .observationOnly = .ObservationOnly := rfl

@[simp] theorem generatedCode_terminal :
    generatedCode .terminal = .Terminal := rfl

@[simp] theorem generatedCode_illegalTransition :
    generatedCode .illegalTransition = .IllegalTransition := rfl

@[simp] theorem generatedCode_notAuthorized :
    generatedCode .notAuthorized = .NotAuthorized := rfl

@[simp] theorem generatedCode_notEligible :
    generatedCode .notEligible = .NotEligible := rfl

@[simp] theorem generatedCode_configurationMismatch :
    generatedCode .configurationMismatch = .ConfigurationMismatch := rfl

@[simp] theorem generatedCode_revoked :
    generatedCode .revoked = .Revoked := rfl

@[simp] theorem generatedCode_expired :
    generatedCode .expired = .Expired := rfl

@[simp] theorem generatedCode_capacityExceeded :
    generatedCode .capacityExceeded = .CapacityExceeded := rfl

@[simp] theorem generatedCode_executionIntentMissing :
    generatedCode .executionIntentMissing = .ExecutionIntentMissing := rfl

@[simp] theorem generatedCode_credentialNotAuthorized :
    generatedCode .credentialNotAuthorized = .CredentialNotAuthorized := rfl

@[simp] theorem generatedCode_attemptMissing :
    generatedCode .attemptMissing = .AttemptMissing := rfl

@[simp] theorem generatedCode_providerCallNotEntered :
    generatedCode .providerCallNotEntered = .ProviderCallNotEntered := rfl

@[simp] theorem generatedCode_effectNotProved :
    generatedCode .effectNotProved = .EffectNotProved := rfl

@[simp] theorem generatedCode_nonEffectNotProved :
    generatedCode .nonEffectNotProved = .NonEffectNotProved := rfl

@[simp] theorem generatedCode_reconciliationStale :
    generatedCode .reconciliationStale = .ReconciliationStale := rfl

@[simp] theorem generatedCode_reconciliationMismatch :
    generatedCode .reconciliationMismatch = .ReconciliationMismatch := rfl

theorem translated_terminal_refines_rich
    (state : Auths.Lifecycle.State) :
    auths_lifecycle.model.LifecycleState.is_terminal
      (generatedState state) =
        ok state.isTerminal := by
  cases state <;> rfl

set_option linter.unnecessarySeqFocus false in
theorem translated_transition_refines_rich
    (current : Option Auths.Lifecycle.State)
    (operation : Auths.Lifecycle.Operation)
    (gates : Auths.Lifecycle.Gates) :
    auths_lifecycle.kernel.transition_code
      (current.map generatedState)
      (generatedOperation operation)
      (generatedGates gates) =
        ok (generatedCode
          (Auths.Lifecycle.transitionCode current operation gates)) := by
  cases gates
  cases current with
  | none =>
      cases operation <;>
        simp [auths_lifecycle.kernel.transition_code,
          Auths.Lifecycle.transitionCode, generatedOperation,
          generatedGates] <;>
        rfl
  | some state =>
      cases state <;>
        cases operation <;>
        simp [auths_lifecycle.kernel.transition_code,
          auths_lifecycle.kernel.reconciliation_code,
          auths_lifecycle.model.LifecycleState.is_terminal,
          Auths.Lifecycle.transitionCode,
          Auths.Lifecycle.reconciliationCode,
          Auths.Lifecycle.State.isTerminal, generatedState,
          generatedOperation, generatedGates] <;>
        rfl

theorem translated_exclusive_capacity_refines_rich
    (hasLiveOwner ownerIsExactReplay : Bool) :
    auths_lifecycle.kernel.exclusive_capacity_available
      hasLiveOwner ownerIsExactReplay =
        ok (Auths.Lifecycle.exclusiveCapacityAvailable
          hasLiveOwner ownerIsExactReplay) := by
  cases hasLiveOwner <;> cases ownerIsExactReplay <;> rfl

theorem translated_additive_capacity_refines_rich
    (ceiling committed active requested : U64) :
    auths_lifecycle.kernel.additive_capacity_available
      ceiling committed active requested =
        ok (Auths.Lifecycle.additiveCapacityAvailable
          ceiling.val committed.val active.val requested.val) := by
  by_cases ceilingZero : ceiling = 0#u64
  · simp [auths_lifecycle.kernel.additive_capacity_available, ceilingZero,
      Auths.Lifecycle.additiveCapacityAvailable,
      Auths.Lifecycle.u64Max]
  by_cases requestedZero : requested = 0#u64
  · simp [auths_lifecycle.kernel.additive_capacity_available, ceilingZero,
      requestedZero, Auths.Lifecycle.additiveCapacityAvailable,
      Auths.Lifecycle.u64Max]
  have ceilingValNonzero : ceiling.val ≠ 0 := by
    intro valueZero
    apply ceilingZero
    scalar_tac
  have requestedValNonzero : requested.val ≠ 0 := by
    intro valueZero
    apply requestedZero
    scalar_tac
  have usedSpecification := U64.checked_add_bv_spec committed active
  cases usedEquation : U64.checked_add committed active with
  | none =>
      simp [usedEquation, U64.max_eq] at usedSpecification
      simp [auths_lifecycle.kernel.additive_capacity_available, ceilingZero,
        requestedZero, usedEquation, Aeneas.Std.lift,
        Auths.Lifecycle.additiveCapacityAvailable,
        Auths.Lifecycle.u64Max, ceilingValNonzero,
        requestedValNonzero]
      omega
  | some used =>
      simp [usedEquation, U64.max_eq] at usedSpecification
      have nextSpecification := U64.checked_add_bv_spec used requested
      cases nextEquation : U64.checked_add used requested with
      | none =>
          simp [nextEquation, U64.max_eq] at nextSpecification
          simp [auths_lifecycle.kernel.additive_capacity_available,
            ceilingZero, requestedZero, usedEquation, nextEquation,
            Aeneas.Std.lift,
            Auths.Lifecycle.additiveCapacityAvailable,
            Auths.Lifecycle.u64Max, ceilingValNonzero,
            requestedValNonzero, usedSpecification]
          omega
      | some next =>
          simp [nextEquation, U64.max_eq] at nextSpecification
          obtain ⟨usedBound, usedValue, _⟩ := usedSpecification
          obtain ⟨nextBound, nextValue, _⟩ := nextSpecification
          simp [auths_lifecycle.kernel.additive_capacity_available,
            ceilingZero, requestedZero, usedEquation, nextEquation,
            Aeneas.Std.lift,
            Auths.Lifecycle.additiveCapacityAvailable,
            Auths.Lifecycle.u64Max, usedBound, usedValue,
            nextValue]
          omega

theorem translated_replay_refines_rich
    (recordExists commitmentsEqual : Bool) :
    auths_lifecycle.kernel.replay_code recordExists commitmentsEqual =
      ok (generatedReplayCode
        (Auths.Lifecycle.replayCode recordExists commitmentsEqual)) := by
  cases recordExists <;> cases commitmentsEqual <;> rfl

end Auths.Lifecycle.Refinement
