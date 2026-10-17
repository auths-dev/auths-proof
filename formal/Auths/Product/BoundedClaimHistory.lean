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
