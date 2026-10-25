import Auths.Product.CounterAggregation
import Mathlib.Tactic
namespace Auths.Product.CounterAggregation
structure SumCounter where
  key : Key
  capacity : Nat
  slots : Nat
  deriving DecidableEq

def SumCounter.counter (value : SumCounter) : Counter := ⟨value.key, value.capacity⟩

def contributeSum : List SumCounter → Key → Nat → Nat → List SumCounter
  | [], key, capacity, slots => [⟨key, capacity, slots⟩]
  | first :: rest, key, capacity, slots =>
    if first.key = key then {first with capacity := min first.capacity capacity} :: rest
    else first :: contributeSum rest key capacity slots

def aggregateSum : List SumCounter → List SumCounter → List SumCounter
  | state, [] => state
  | state, first :: rest => aggregateSum (contributeSum state first.key first.capacity first.slots) rest

/-- Sum aggregation obeys the same shared minimum-capacity semantics as count
    aggregation; the separately retained slot bound never changes that map. -/
theorem sum_contribution_projection (state : List SumCounter) (key : Key) (capacity slots : Nat) :
    (contributeSum state key capacity slots).map SumCounter.counter =
      contribute (state.map SumCounter.counter) key capacity := by
  induction state with
  | nil => rfl
  | cons first rest ih =>
    by_cases selected : first.key = key <;>
      simp [contributeSum, contribute, SumCounter.counter, selected, ih]

theorem sum_aggregate_projection (state incoming : List SumCounter) :
    (aggregateSum state incoming).map SumCounter.counter =
      aggregate (state.map SumCounter.counter) (incoming.map SumCounter.counter) := by
  induction incoming generalizing state with
  | nil => rfl
  | cons first rest ih =>
    simp only [aggregateSum, List.map_cons, aggregate, ih]
    rw [sum_contribution_projection]
    rfl

theorem sum_aggregate_unique (incoming : List SumCounter) :
    (((aggregateSum [] incoming).map SumCounter.counter).map Counter.key).Nodup := by
  rw [sum_aggregate_projection]
  exact aggregate_unique [] _ (by simp)

theorem sum_aggregate_capacities (incoming : List SumCounter) (key : Key) :
    lookup ((aggregateSum [] incoming).map SumCounter.counter) key =
      specification (fun _ => none) (incoming.map SumCounter.counter) key := by
  rw [sum_aggregate_projection, aggregate_exact]
  rfl

theorem sum_contribute_length_le (state : List SumCounter) (key : Key) (capacity slots : Nat) :
    (contributeSum state key capacity slots).length ≤ state.length + 1 := by
  have bound := contribute_length_le (state.map SumCounter.counter) key capacity
  rw [← sum_contribution_projection state key capacity slots] at bound
  simpa using bound

theorem sum_aggregate_append (state first rest : List SumCounter) :
    aggregateSum state (first ++ rest) = aggregateSum (aggregateSum state first) rest := by
  induction first generalizing state with
  | nil => rfl
  | cons head tail ih => simpa only [List.cons_append, aggregateSum] using ih (contributeSum state head.key head.capacity head.slots)

theorem sum_aggregate_snoc (state first : List SumCounter) (next : SumCounter) :
    aggregateSum state (first ++ [next]) = contributeSum (aggregateSum state first) next.key next.capacity next.slots := by
  rw [sum_aggregate_append]
  rfl

/-- A duplicate contribution retains the first slot bound, independently of
    whether it tightens the sum capacity. -/
theorem first_slots_preserved (first : SumCounter) (rest : List SumCounter) (capacity slots : Nat) :
    contributeSum (first :: rest) first.key capacity slots =
      {first with capacity := min first.capacity capacity} :: rest := by
  simp [contributeSum]
theorem sum_contribute_at (counters : List SumCounter) (key : Key) (capacity slots index : Nat) (old : SumCounter)
    (found : SchemaIndex.position (counters.map SumCounter.key) key = some index)
    (atIndex : counters[index]? = some old) :
    contributeSum counters key capacity slots = counters.set index {old with capacity := min old.capacity capacity} := by
  induction counters generalizing index with
  | nil => simp at atIndex
  | cons first rest ih =>
    by_cases selected : first.key = key
    · simp [SchemaIndex.position, selected] at found
      subst index
      simp at atIndex
      subst old
      simp [contributeSum, selected]
    · cases index with
      | zero => simp [SchemaIndex.position, selected] at found
      | succ index =>
        have tailFound : SchemaIndex.position (rest.map SumCounter.key) key = some index := by
          simpa [SchemaIndex.position, selected] using found
        have tailAt : rest[index]? = some old := by simpa using atIndex
        simp [contributeSum, selected, ih index tailFound tailAt]

theorem sum_contribute_absent (counters : List SumCounter) (key : Key) (capacity slots : Nat)
    (absent : SchemaIndex.position (counters.map SumCounter.key) key = none) :
    contributeSum counters key capacity slots = counters ++ [⟨key, capacity, slots⟩] := by
  induction counters with
  | nil => rfl
  | cons first rest ih =>
    have different : first.key ≠ key := by intro same; simp [SchemaIndex.position, same] at absent
    have tailAbsent : SchemaIndex.position (rest.map SumCounter.key) key = none := by
      simpa [SchemaIndex.position, different] using absent
    simp [contributeSum, different, ih tailAbsent]

end Auths.Product.CounterAggregation
