import Auths.Product.AdmissionOwnership
import Auths.Product.CeilingCount

/-!
One fixed-window reference history combining the existing chain/partition
policy evaluator with durable logical claims and one-use ownership. Capacities
may differ between arrivals; no globally fixed counter capacity is assumed.
Atomic storage linearization and the shipping reservation driver remain
separate source-correspondence obligations.
-/
namespace Auths.Product.BoundedClaimHistory
namespace C
export Auths.Product.CeilingCount (CounterKey Arrival Link SumBound Name chainAdmits admitStep
  countInvariant sumInvariant countInvariant_preserved sumInvariant_preserved containing containingIn)
end C
namespace O
export Auths.Product.AdmissionHistory (State Policy Operation Worker SingleOwner empty admit crash enter
  admit_preserves_owner crash_preserves_owner enter_preserves_owner claim_has_one_owner)
end O

structure State where
  bounds : (C.CounterKey → Nat) × List C.Arrival
  ownership : O.State
  closed : Bool

private def ownershipPolicy : O.Policy := ⟨fun _ => 0, fun _ => 0⟩
private def claim (state : O.State) (operation : O.Operation) (worker : O.Worker)
    (acknowledged : Bool) : O.State :=
  O.admit ownershipPolicy state ⟨operation, worker, []⟩ acknowledged

/-- Successful reservations charge every chain counter even if the commit's
    acknowledgement is lost. Refusals can retain a terminal claim, but give
    no handle. An existing logical claim cannot reserve a second time. -/
def attempt (state : State) (operation : O.Operation) (worker : O.Worker)
    (arrival : C.Arrival) (acknowledged : Bool) : State :=
  if state.ownership.claims operation = none then
    if state.closed then
      {state with ownership := claim state.ownership operation worker false}
    else if C.chainAdmits arrival.facts arrival.value arrival.links state.bounds.1 then
      {state with
        bounds := C.admitStep state.bounds arrival
        ownership := claim state.ownership operation worker acknowledged}
    else {state with ownership := claim state.ownership operation worker false}
  else state

inductive Event where
  | admission (operation : O.Operation) (worker : O.Worker) (arrival : C.Arrival) (acknowledged : Bool)
  | processCrash (worker : O.Worker)
  | writeEntry (operation : O.Operation) (worker : O.Worker)
  | collection
  | readOnlyRecovery
  | failedBeforeCommit

def step (state : State) : Event → State
  | .admission operation worker arrival acknowledged => attempt state operation worker arrival acknowledged
  | .processCrash worker => {state with ownership := O.crash state.ownership worker}
  | .writeEntry operation worker => {state with ownership := O.enter state.ownership operation worker}
  | .collection => {state with closed := true}
  | .readOnlyRecovery | .failedBeforeCommit => state

def run (initial : State) (events : List Event) : State := events.foldl step initial

def initial : State := ⟨(fun _ => 0, []), O.empty, false⟩

structure Invariant (state : State) : Prop where
  owner : O.SingleOwner state.ownership
  counts : ∀ link, C.countInvariant link state.bounds
  sums : ∀ (link : C.Link) (bound : C.SumBound), link.2.sum = some bound → ∀ partition,
    C.sumInvariant link bound partition state.bounds

theorem attempt_preserves (state : State) (operation : O.Operation) (worker : O.Worker)
    (arrival : C.Arrival) (acknowledged : Bool) (valid : Invariant state) :
    Invariant (attempt state operation worker arrival acknowledged) := by
  unfold attempt
  split
  · split
    · exact ⟨O.admit_preserves_owner _ _ _ _ valid.owner, valid.counts, valid.sums⟩
    · split
      · exact ⟨O.admit_preserves_owner _ _ _ _ valid.owner,
          fun link => C.countInvariant_preserved link state.bounds arrival (valid.counts link),
          fun link bound carries partition => C.sumInvariant_preserved link carries partition
            state.bounds arrival (valid.sums link bound carries partition)⟩
      · exact ⟨O.admit_preserves_owner _ _ _ _ valid.owner, valid.counts, valid.sums⟩
  · exact valid

theorem step_preserves (state : State) (event : Event) (valid : Invariant state) :
    Invariant (step state event) := by
  cases event with
  | admission operation worker arrival acknowledged =>
    exact attempt_preserves state operation worker arrival acknowledged valid
  | processCrash worker =>
    exact ⟨O.crash_preserves_owner _ _ valid.owner, valid.counts, valid.sums⟩
  | writeEntry operation worker =>
    exact ⟨O.enter_preserves_owner _ _ _ valid.owner, valid.counts, valid.sums⟩
  | collection => exact ⟨valid.owner, valid.counts, valid.sums⟩
  | readOnlyRecovery => exact valid
  | failedBeforeCommit => exact valid

theorem run_preserves (events : List Event) (state : State) (valid : Invariant state) :
    Invariant (run state events) := by
  induction events generalizing state with
  | nil => exact valid
  | cons event rest ih => exact ih _ (step_preserves state event valid)

/-- Every finite interleaving preserves one-use claim ownership and the
    existing per-link count/ceiling/partition-sum invariants together. This
    reference theorem permits different chains and policies on each arrival. -/
theorem every_history_preserves (events : List Event) : Invariant (run initial events) := by
  apply run_preserves
  constructor
  · exact O.claim_has_one_owner ownershipPolicy []
  · intro link
    exact ⟨by simp [initial, C.containing], by simp [initial, C.containing], by simp [initial, C.containing]⟩
  · intro link bound _ partition
    exact ⟨by simp [initial, C.containingIn], by simp [initial, C.containingIn]⟩

theorem every_history_count_bound (events : List Event) (link : C.Link) :
    (C.containing link (run initial events).bounds.2).length ≤ link.2.maxCount :=
  ((every_history_preserves events).counts link).2.1

theorem every_history_sum_bound (events : List Event) (link : C.Link) (bound : C.SumBound)
    (carries : link.2.sum = some bound) (partition : C.Name) :
    ((C.containingIn link bound partition (run initial events).bounds.2).map Auths.Product.CeilingCount.Arrival.value).sum ≤ bound.limit :=
  ((every_history_preserves events).sums link bound carries partition).2

theorem every_history_one_owner (events : List Event) :
    O.SingleOwner (run initial events).ownership := (every_history_preserves events).owner

theorem replay_preserves_counters (state : State) (operation : O.Operation) (worker : O.Worker)
    (arrival : C.Arrival) (acknowledged : Bool) (occupied : state.ownership.claims operation ≠ none) :
    (attempt state operation worker arrival acknowledged).bounds = state.bounds := by
  simp [attempt, occupied]

theorem collection_preserves_charges (state : State) : (step state .collection).bounds = state.bounds := rfl

theorem closed_window_cannot_charge (state : State) (operation : O.Operation) (worker : O.Worker)
    (arrival : C.Arrival) (acknowledged : Bool) (closed : state.closed = true) :
    (attempt state operation worker arrival acknowledged).bounds = state.bounds := by
  by_cases fresh : state.ownership.claims operation = none
  · simp only [attempt, fresh, closed, ↓reduceIte]
  · simp only [attempt, fresh, ↓reduceIte]

theorem crash_preserves_charges (state : State) (worker : O.Worker) :
    (step state (.processCrash worker)).bounds = state.bounds := rfl

/-- A known logical operation cannot charge any chain again, even when a
retry has another worker, different policy links, or a different value. -/
theorem known_operation_cannot_charge_again (state : State) (operation : O.Operation)
    (owner worker : O.Worker) (arrival : C.Arrival) (acknowledged : Bool)
    (known : state.ownership.claims operation = some owner) :
    attempt state operation worker arrival acknowledged = state := by
  simp [attempt, known]

private theorem claim_records_fresh_operation (state : O.State)
    (operation : O.Operation) (worker : O.Worker) (acknowledged : Bool)
    (fresh : state.claims operation = none) :
    (claim state operation worker acknowledged).claims operation = some worker := by
  simp [claim, Auths.Product.AdmissionHistory.admit,
    Auths.Product.AdmissionHistory.fits, fresh]

/-- Both successful reservations and terminal refusals retain the winning
logical claim. A lost acknowledgement affects its volatile handle only. -/
theorem attempt_records_fresh_operation (state : State) (operation : O.Operation)
    (worker : O.Worker) (arrival : C.Arrival) (acknowledged : Bool)
    (fresh : state.ownership.claims operation = none) :
    (attempt state operation worker arrival acknowledged).ownership.claims operation = some worker := by
  unfold attempt
  rw [if_pos fresh]
  split
  · exact claim_records_fresh_operation _ _ _ _ fresh
  · split <;> exact claim_records_fresh_operation _ _ _ _ fresh

private theorem attempt_keeps_known_owner (state : State) (operation : O.Operation)
    (owner : O.Worker) (target : O.Operation) (worker : O.Worker)
    (arrival : C.Arrival) (acknowledged : Bool)
    (known : state.ownership.claims operation = some owner) :
    (attempt state target worker arrival acknowledged).ownership.claims operation = some owner := by
  unfold attempt
  split
  · split
    · exact Auths.Product.AdmissionHistory.admitted_claim_stays _ _ _ _ _ _ known
    · split <;> exact Auths.Product.AdmissionHistory.admitted_claim_stays _ _ _ _ _ _ known
  · exact known

theorem step_keeps_known_owner (state : State) (event : Event)
    (operation : O.Operation) (owner : O.Worker)
    (known : state.ownership.claims operation = some owner) :
    (step state event).ownership.claims operation = some owner := by
  cases event with
  | admission target worker arrival acknowledged =>
    exact attempt_keeps_known_owner _ _ _ _ _ _ _ known
  | processCrash worker => exact known
  | writeEntry target worker =>
    simp only [step, Auths.Product.AdmissionHistory.enter]
    split <;> exact known
  | collection => exact known
  | readOnlyRecovery => exact known
  | failedBeforeCommit => exact known

/-- Every finite suffix preserves the durable owner, including a suffix with
collection and a retry under another chain or counter arrangement. -/
theorem every_suffix_keeps_known_owner (state : State) (events : List Event)
    (operation : O.Operation) (owner : O.Worker)
    (known : state.ownership.claims operation = some owner) :
    (run state events).ownership.claims operation = some owner := by
  induction events generalizing state with
  | nil => exact known
  | cons event rest ih =>
    exact ih _ (step_keeps_known_owner _ _ _ _ known)

/-- A committed admission whose acknowledgement is lost cannot be charged a
second time after any finite suffix, regardless of the retry's worker/value/
policy links. Other operations in the suffix may still spend their allowance. -/
theorem lost_acknowledgement_cannot_recharge_after_any_suffix
    (state : State) (operation : O.Operation) (owner retryWorker : O.Worker)
    (first retry : C.Arrival) (suffix : List Event)
    (acknowledged : Bool) (fresh : state.ownership.claims operation = none) :
    let after := run (attempt state operation owner first false) suffix
    attempt after operation retryWorker retry acknowledged = after := by
  dsimp only
  apply known_operation_cannot_charge_again _ _ owner
  exact every_suffix_keeps_known_owner _ _ _ _
    (attempt_records_fresh_operation _ _ _ _ _ fresh)

/-- Lost versus received acknowledgement cannot undo the charged aggregate
state. The reference permits no acknowledgement-driven counter rollback. -/
theorem acknowledgement_does_not_change_aggregate_charge (state : State)
    (operation : O.Operation) (worker : O.Worker) (arrival : C.Arrival) :
    (attempt state operation worker arrival false).bounds =
      (attempt state operation worker arrival true).bounds := by
  unfold attempt
  split_ifs <;> rfl

/-- A fixed-window collection fence cannot be reversed by a later arrival's
clock facts, policy links, crash or read-only recovery. -/
theorem step_preserves_closed_window (state : State) (event : Event)
    (closed : state.closed = true) : (step state event).closed = true := by
  cases event with
  | admission operation worker arrival acknowledged =>
    simp [step, attempt, closed]
  | processCrash worker => exact closed
  | writeEntry operation worker => exact closed
  | collection => rfl
  | readOnlyRecovery => exact closed
  | failedBeforeCommit => exact closed

theorem step_in_closed_window_cannot_charge (state : State) (event : Event)
    (closed : state.closed = true) : (step state event).bounds = state.bounds := by
  cases event with
  | admission operation worker arrival acknowledged =>
    simp [step, attempt, closed]
  | processCrash worker => rfl
  | writeEntry operation worker => rfl
  | collection => rfl
  | readOnlyRecovery => rfl
  | failedBeforeCommit => rfl

/-- Every arbitrary finite suffix after the shared fence leaves the aggregate
state unchanged, even when a different worker supplies an earlier clock value.
This is a fixed-window reference result; durable backend fence correspondence
and actual slot deletion remain separate source obligations. -/
theorem every_suffix_after_collection_preserves_capacity
    (state : State) (events : List Event) (closed : state.closed = true) :
    (run state events).closed = true ∧ (run state events).bounds = state.bounds := by
  induction events generalizing state with
  | nil => exact ⟨closed, rfl⟩
  | cons event rest ih =>
    have nextClosed := step_preserves_closed_window state event closed
    have nextBounds := step_in_closed_window_cannot_charge state event closed
    have later := ih (step state event) nextClosed
    exact ⟨later.1, later.2.trans nextBounds⟩

theorem collection_cannot_reopen_under_any_later_history
    (state : State) (events : List Event) :
    (run (step state .collection) events).closed = true ∧
    (run (step state .collection) events).bounds = state.bounds := by
  exact every_suffix_after_collection_preserves_capacity (step state .collection) events rfl

namespace Examples
private def rootPolicy : Auths.Product.CeilingCount.Policy :=
  ⟨[1], 5, 60, 2, some ⟨10, none⟩, none⟩
private def rootLink : C.Link := ([114], rootPolicy)
private def childLink : C.Link := ([99], {rootPolicy with maxCount := 1})
private def rootArrival : C.Arrival :=
  ⟨⟨fun _ => some 5, fun _ => none⟩, [rootLink], 5⟩
private def childArrival : C.Arrival := {rootArrival with links := [rootLink, childLink]}
private def trace : List Event :=
  [.admission ("operator", "first") 1 rootArrival false,
   .processCrash 1,
   .admission ("operator", "second") 2 childArrival true,
   .admission ("operator", "third") 3 rootArrival true]

/-- A useful delegated admission succeeds after a lost acknowledgement,
    sharing the root's count and sum; the third action is refused. -/
theorem useful_delegation_shares_capacity :
    (run initial trace).bounds.2.length = 2 ∧
    (run initial trace).ownership.handles ("operator", "second") = some 2 ∧
    (run initial trace).ownership.handles ("operator", "third") = none := by
  decide

/-- Read-only recovery cannot turn the first unacknowledged admission into
    an entry, while the acknowledged delegate can enter once. -/
theorem recovery_cannot_reissue_lost_handle :
    (run initial (trace ++ [.readOnlyRecovery, .writeEntry ("operator", "first") 1,
      .writeEntry ("operator", "second") 2, .writeEntry ("operator", "second") 2])).ownership.entries =
        [(("operator", "second"), 2)] := by
  decide
end Examples

end Auths.Product.BoundedClaimHistory
