import Mathlib.Tactic
import Auths.Product.SchemaIndex
namespace Auths.Product.CounterAggregation
abbrev Key := List Nat
structure Counter where
  key : Key
  capacity : Nat
  deriving DecidableEq

def lookup : List Counter → Key → Option Nat
  | [], _ => none
  | first :: rest, key => if first.key = key then some first.capacity else lookup rest key

def contribute : List Counter → Key → Nat → List Counter
  | [], key, capacity => [⟨key, capacity⟩]
  | first :: rest, key, capacity =>
    if first.key = key then ⟨key, min first.capacity capacity⟩ :: rest
    else first :: contribute rest key capacity

def tighten (previous : Option Nat) (capacity : Nat) : Option Nat :=
  some (match previous with | none => capacity | some old => min old capacity)

/-- Lookup of every key agrees with an independent pointwise minimum update. -/
theorem lookup_contribute (counters : List Counter) (key : Key) (capacity : Nat) (wanted : Key) :
    lookup (contribute counters key capacity) wanted =
      if wanted = key then tighten (lookup counters wanted) capacity else lookup counters wanted := by
  induction counters with
  | nil =>
    by_cases same : wanted = key
    · subst wanted; simp [contribute, lookup, tighten]
    · simp [contribute, lookup, tighten, same, Ne.symm same]
  | cons first rest ih =>
    by_cases selected : first.key = key
    · by_cases same : wanted = key
      · subst wanted; simp [contribute, lookup, selected, tighten]
      · have different : first.key ≠ wanted := by intro equal; exact same (equal.symm.trans selected)
        simp [contribute, lookup, selected, same, different, Ne.symm same]
    · by_cases same : first.key = wanted
      · have different : wanted ≠ key := by intro equal; exact selected (same.trans equal)
        simp [contribute, lookup, selected, same, different]
      · simp [contribute, lookup, selected, same, ih]

theorem contribute_keys (counters : List Counter) (key : Key) (capacity : Nat) :
    (contribute counters key capacity).map Counter.key =
      if key ∈ counters.map Counter.key then counters.map Counter.key else counters.map Counter.key ++ [key] := by
  induction counters with
  | nil => simp [contribute]
  | cons first rest ih =>
    by_cases selected : first.key = key
    · simp [contribute, selected, eq_comm]
    · simp [contribute, selected, ih, Ne.symm selected]
      split <;> rfl

theorem contribute_unique (counters : List Counter) (key : Key) (capacity : Nat)
    (unique : (counters.map Counter.key).Nodup) :
    ((contribute counters key capacity).map Counter.key).Nodup := by
  rw [contribute_keys]
  split
  · exact unique
  · exact List.nodup_append'.mpr ⟨unique, by simp,
      List.disjoint_singleton.mpr (by assumption)⟩

/-- The structural update agrees with a first-match indexed update. -/
theorem contribute_at (counters : List Counter) (key : Key) (capacity index : Nat) (old : Counter)
    (found : SchemaIndex.position (counters.map Counter.key) key = some index)
    (atIndex : counters[index]? = some old) :
    contribute counters key capacity = counters.set index {old with capacity := min old.capacity capacity} := by
  induction counters generalizing index with
  | nil => simp at atIndex
  | cons first rest ih =>
    by_cases selected : first.key = key
    · simp [SchemaIndex.position, selected] at found
      subst index
      simp at atIndex
      subst old
      simp [contribute, selected]
    · cases index with
      | zero =>
        simp [SchemaIndex.position, selected] at found
      | succ index =>
        have tailFound : SchemaIndex.position (rest.map Counter.key) key = some index := by
          simpa [SchemaIndex.position, selected] using found
        have tailAt : rest[index]? = some old := by simpa using atIndex
        simp [contribute, selected, ih index tailFound tailAt]

theorem contribute_absent (counters : List Counter) (key : Key) (capacity : Nat)
    (absent : SchemaIndex.position (counters.map Counter.key) key = none) :
    contribute counters key capacity = counters ++ [⟨key, capacity⟩] := by
  induction counters with
  | nil => rfl
  | cons first rest ih =>
    have different : first.key ≠ key := by intro same; simp [SchemaIndex.position, same] at absent
    have tailAbsent : SchemaIndex.position (rest.map Counter.key) key = none := by
      simpa [SchemaIndex.position, different] using absent
    simp [contribute, different, ih tailAbsent]

/-- Indexed first-match selection and recursive lookup agree, including duplicates. -/
theorem lookup_at (counters : List Counter) (key : Key) (index : Nat) (entry : Counter)
    (found : SchemaIndex.position (counters.map Counter.key) key = some index)
    (atIndex : counters[index]? = some entry) : lookup counters key = some entry.capacity := by
  induction counters generalizing index with
  | nil => simp at atIndex
  | cons first rest ih =>
    by_cases selected : first.key = key
    · simp [SchemaIndex.position, selected] at found
      subst index
      simp at atIndex
      subst entry
      simp [lookup, selected]
    · cases index with
      | zero => simp [SchemaIndex.position, selected] at found
      | succ index =>
        have tailFound : SchemaIndex.position (rest.map Counter.key) key = some index := by
          simpa [SchemaIndex.position, selected] using found
        have tailAt : rest[index]? = some entry := by simpa using atIndex
        simpa [lookup, selected] using ih index tailFound tailAt

theorem lookup_absent (counters : List Counter) (key : Key)
    (absent : SchemaIndex.position (counters.map Counter.key) key = none) : lookup counters key = none := by
  induction counters with
  | nil => rfl
  | cons first rest ih =>
    have different : first.key ≠ key := by intro same; simp [SchemaIndex.position, same] at absent
    have tailAbsent : SchemaIndex.position (rest.map Counter.key) key = none := by
      simpa [SchemaIndex.position, different] using absent
    simp [lookup, different, ih tailAbsent]

/-- Arbitrary finite contributions always share a key's smallest limit. -/
def aggregate : List Counter → List Counter → List Counter
  | state, [] => state
  | state, first :: rest => aggregate (contribute state first.key first.capacity) rest

def specification : (Key → Option Nat) → List Counter → Key → Option Nat
  | state, [], wanted => state wanted
  | state, first :: rest, wanted =>
      specification (fun key => if key = first.key then tighten (state key) first.capacity else state key) rest wanted

theorem aggregate_exact (state contributions : List Counter) (wanted : Key) :
    lookup (aggregate state contributions) wanted = specification (lookup state) contributions wanted := by
  induction contributions generalizing state with
  | nil => rfl
  | cons first rest ih =>
    simp only [aggregate, specification, ih]
    congr 1
    funext key
    exact lookup_contribute state first.key first.capacity key

theorem aggregate_unique (state contributions : List Counter)
    (unique : (state.map Counter.key).Nodup) :
    ((aggregate state contributions).map Counter.key).Nodup := by
  induction contributions generalizing state with
  | nil => exact unique
  | cons first rest ih => exact ih _ (contribute_unique state first.key first.capacity unique)
theorem contribute_length_le (counters : List Counter) (key : Key) (capacity : Nat) :
    (contribute counters key capacity).length ≤ counters.length + 1 := by
  have lengths := congrArg List.length (contribute_keys counters key capacity)
  by_cases present : key ∈ counters.map Counter.key <;> simp [present] at lengths <;> omega

theorem aggregate_append (state first rest : List Counter) :
    aggregate state (first ++ rest) = aggregate (aggregate state first) rest := by
  induction first generalizing state with
  | nil => rfl
  | cons head tail ih => simpa only [List.cons_append, aggregate] using ih (contribute state head.key head.capacity)

theorem aggregate_snoc (state first : List Counter) (next : Counter) :
    aggregate state (first ++ [next]) = contribute (aggregate state first) next.key next.capacity := by
  rw [aggregate_append]
  rfl

theorem aggregate_length_le (state incoming : List Counter) :
    (aggregate state incoming).length ≤ state.length + incoming.length := by
  induction incoming generalizing state with
  | nil => simp [aggregate]
  | cons first rest ih =>
    have next := ih (contribute state first.key first.capacity)
    have lengthBound := contribute_length_le state first.key first.capacity
    simp only [aggregate, List.length_cons]
    omega

end Auths.Product.CounterAggregation
