import Auths.Lifecycle.Semantics
import Mathlib.Tactic

namespace Auths.Lifecycle

theorem additive_capacity_success_positive
    {ceiling committed active requested : Nat}
    (accepted :
      additiveCapacityAvailable ceiling committed active requested = true) :
    0 < ceiling ∧ 0 < requested := by
  simp [additiveCapacityAvailable] at accepted
  omega

theorem additive_capacity_success_conserves
    {ceiling committed active requested : Nat}
    (accepted :
      additiveCapacityAvailable ceiling committed active requested = true) :
    committed + active + requested ≤ ceiling := by
  have facts := (by
    simpa [additiveCapacityAvailable] using accepted :
      (((ceiling ≠ 0 ∧ requested ≠ 0) ∧
        committed + active ≤ u64Max) ∧
        committed + active + requested ≤ u64Max) ∧
        committed + active + requested ≤ ceiling)
  exact facts.2

theorem additive_capacity_success_never_overflows_u64
    {ceiling committed active requested : Nat}
    (accepted :
      additiveCapacityAvailable ceiling committed active requested = true) :
    committed + active ≤ u64Max ∧
      committed + active + requested ≤ u64Max := by
  have facts := (by
    simpa [additiveCapacityAvailable] using accepted :
      (((ceiling ≠ 0 ∧ requested ≠ 0) ∧
        committed + active ≤ u64Max) ∧
        committed + active + requested ≤ u64Max) ∧
        committed + active + requested ≤ ceiling)
  exact ⟨facts.1.1.2, facts.1.2⟩

theorem reserve_preserves_capacity
    {ledger next : CapacityLedger} {requested : Nat}
    (valid : ledger.valid)
    (step : ledger.reserve requested = some next) :
    next.valid := by
  simp [CapacityLedger.reserve] at step
  obtain ⟨accepted, rfl⟩ := step
  simp [CapacityLedger.valid] at valid ⊢
  constructor
  · exact valid.1
  · have bounded := additive_capacity_success_conserves accepted
    omega

theorem commit_preserves_capacity
    {ledger next : CapacityLedger} {amount : Nat}
    (valid : ledger.valid)
    (step : ledger.commit amount = some next) :
    next.valid := by
  simp [CapacityLedger.commit] at step
  obtain ⟨available, rfl⟩ := step
  simp [CapacityLedger.valid] at valid ⊢
  omega

theorem release_preserves_capacity
    {ledger next : CapacityLedger} {amount : Nat}
    (valid : ledger.valid)
    (step : ledger.release amount = some next) :
    next.valid := by
  simp [CapacityLedger.release] at step
  obtain ⟨available, rfl⟩ := step
  simp [CapacityLedger.valid] at valid ⊢
  omega

theorem exact_replay_is_stable :
    replayCode true true = .exactReplay := by
  rfl

theorem conflicting_replay_is_not_exact :
    replayCode true false = .conflict := by
  rfl

theorem absent_replay_never_claims_effect (commitmentsEqual : Bool) :
    replayCode false commitmentsEqual = .absent := by
  cases commitmentsEqual <;> rfl

theorem start_attempt_requires_credential
    {gates : Gates}
    (applied :
      transitionCode
        (some .executionIntentRecorded) .startAttempt gates =
          .applied .executing) :
    gates.credentialAuthorized = true := by
  simp [transitionCode] at applied
  split at applied <;> simp_all
  split at applied <;> simp_all
  split at applied <;> simp_all
  split at applied <;> simp_all
  split at applied <;> simp_all

theorem provider_call_requires_attempt
    {gates : Gates}
    (applied :
      transitionCode
        (some .executing) .markProviderCallEntered gates =
          .applied .executing) :
    gates.attemptPresent = true := by
  simp [transitionCode] at applied
  split at applied <;> simp_all
  split at applied <;> simp_all

theorem commit_requires_provider_entry_and_effect
    {gates : Gates}
    (applied :
      transitionCode (some .executing) .commit gates =
        .applied .committed) :
    gates.attemptPresent = true ∧
      gates.providerCallEntered = true ∧
      gates.definiteEffect = true := by
  simp [transitionCode] at applied
  split at applied <;> simp_all
  split at applied <;> simp_all
  split at applied <;> simp_all

theorem outcome_unknown_cannot_release
    (gates : Gates) :
    transitionCode (some .outcomeUnknown) .release gates =
      .illegalTransition := by
  simp [transitionCode, State.isTerminal]

theorem outcome_unknown_only_reconciliation_can_terminate
    {operation : Operation} {gates : Gates} {terminal : State}
    (terminalState :
      terminal = .reconciledCommitted ∨ terminal = .reconciledReleased)
    (applied :
      transitionCode (some .outcomeUnknown) operation gates =
        .applied terminal) :
    operation = .reconcileEffect ∨ operation = .reconcileNonEffect := by
  cases operation <;>
    simp [transitionCode, State.isTerminal, reconciliationCode] at applied
  all_goals aesop

theorem configuration_mismatch_stops_reservation
    (gates : Gates) (mismatch : gates.configurationMatches = false) :
    transitionCode (some .decisionRecorded) .reserve gates =
      .configurationMismatch := by
  simp [transitionCode, State.isTerminal, mismatch]

theorem configuration_mismatch_stops_credential
    (gates : Gates) (mismatch : gates.configurationMatches = false) :
    transitionCode
      (some .executionIntentRecorded) .authorizeCredential gates =
        .configurationMismatch := by
  simp [transitionCode, State.isTerminal, mismatch]

theorem terminal_states_never_transition
    (state : State) (operation : Operation) (gates : Gates)
    (terminal : state.isTerminal = true) :
    transitionCode (some state) operation gates = .terminal := by
  simp [transitionCode, terminal]

end Auths.Lifecycle
