import Auths.Product.CounterAggregationRefinement
import Auths.Product.SumAggregation
open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
namespace Auths.Product.CounterAggregation.Refinement
set_option maxHeartbeats 4000000
def sumKeys (counters : Slice counter_aggregation.SumCapacity) : List SchemaIndex.Name :=
  counters.val.map (fun counter => counter.key.val.map (·.val))
@[step] theorem sum_position_spec (counters : Slice counter_aggregation.SumCapacity) (key : Array Std.U8 32#usize) :
    counter_aggregation.sum_position counters key ⦃ actual =>
      actual.map UScalar.val = SchemaIndex.position (sumKeys counters) (key.val.map (·.val)) ⦄ := by
  unfold counter_aggregation.sum_position counter_aggregation.sum_position_loop
  apply loop.spec_decr_nat
    (measure := fun position => counters.val.length - position.val)
    (inv := fun position => position.val ≤ counters.val.length ∧
      ∀ index, index < position.val → (sumKeys counters)[index]? ≠ some (key.val.map (·.val)))
  · intro position processed
    unfold counter_aggregation.sum_position_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : position.val < counters.val.length := by simpa using within
      step as ⟨counter, counterAt⟩
      step with counter_equal_spec as ⟨same, sameMeaning⟩
      cases same
      · simp only [Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
        step as ⟨next, nextValue⟩
        refine ⟨by omega, ?_, by omega⟩
        intro index before
        by_cases earlier : index < position.val
        · exact processed.2 index earlier
        · have atCurrent : index = position.val := by omega
          subst index
          simp_all [sumKeys, List.getElem?_map]
          exact sameMeaning ∘ (byteList_injective _ _).mp
      · simp only [↓reduceIte, spec_ok]
        symm
        apply SchemaIndex.position_eq_first
        · simp_all [sumKeys, List.getElem?_map]
        · exact processed.2
    · simp only [spec_ok]
      symm
      apply (SchemaIndex.absent_iff _ _).mpr
      intro member
      obtain ⟨index, atIndex⟩ := List.mem_iff_getElem?.mp member
      have inside : index < (sumKeys counters).length := (List.getElem?_eq_some_iff.mp atIndex).1
      have atEnd : counters.val.length ≤ position.val := by simpa using within
      have length : (sumKeys counters).length = counters.val.length := by simp [sumKeys]
      exact processed.2 index (by omega) atIndex
  · exact ⟨by simp, by simp⟩
def sumView (counter : counter_aggregation.SumCapacity) : CounterAggregation.SumCounter :=
  ⟨counter.key.val.map (·.val), counter.capacity.val, counter.slots.val⟩

def sumCountersView (counters : alloc.vec.Vec counter_aggregation.SumCapacity) : List CounterAggregation.SumCounter :=
  counters.val.map sumView

/-- The actual keyed update preserves the independent minimum-capacity map. -/
@[step] theorem contribute_sum_spec (counters : alloc.vec.Vec counter_aggregation.SumCapacity)
    (key : Array Std.U8 32#usize) (capacity slots : Std.U64)
    (fits : counters.val.length < 4294967295) :
    counter_aggregation.contribute_sum counters key capacity slots ⦃ actual =>
      sumCountersView actual = CounterAggregation.contributeSum (sumCountersView counters) (key.val.map (·.val)) capacity.val slots.val ⦄ := by
  unfold counter_aggregation.contribute_sum
  step with sum_position_spec as ⟨position, positionMeaning⟩
  have positioned : position.map UScalar.val =
      SchemaIndex.position ((sumCountersView counters).map SumCounter.key) (key.val.map (·.val)) := by
    simpa [sumKeys, sumCountersView, sumView, alloc.vec.Vec.deref, List.map_map, Function.comp_def] using positionMeaning
  cases position with
  | none =>
    simp only [bind_tc_ok]
    have room : counters.length < Usize.max := by
      rcases Usize.bounds_eq with equal | equal <;> rw [equal] <;>
        simp only [U32.max_eq, U64.max_eq] <;> change counters.val.length < _ <;> omega
    step as ⟨actual, actualMeaning⟩
    rw [CounterAggregation.sum_contribute_absent _ _ _ _ positioned.symm]
    simp [sumCountersView, actualMeaning, sumView, List.map_append]
  | some index =>
    simp only [Option.map_some] at positioned
    have keyAt := SchemaIndex.position_points_to_name _ _ index.val positioned.symm
    have inside : index.val < counters.val.length := by
      have lengthBound := (List.getElem?_eq_some_iff.mp keyAt).1
      simpa [sumCountersView, List.length_map] using lengthBound
    step as ⟨old, oldAt⟩
    have modelAt : (sumCountersView counters)[index.val]? = some (sumView old) := by
      simp [sumCountersView, List.getElem?_map, List.getElem?_eq_getElem inside, oldAt]
    have update := CounterAggregation.sum_contribute_at _ _ capacity.val slots.val index.val (sumView old) positioned.symm modelAt
    rw [update]
    split <;> rename_i tighter
    · step as ⟨mutable, restore, mutableAt, restoreMeaning⟩
      have same : mutable = old := mutableAt.trans oldAt.symm
      subst mutable
      have tight : capacity.val < old.capacity.val := by simpa using tighter
      simp [restoreMeaning, sumCountersView, sumView, List.map_set, Nat.min_eq_right (Nat.le_of_lt tight), same]
    · simp only [spec_ok]
      have kept : old.capacity.val ≤ capacity.val := by simpa using tighter
      have same : {sumView old with capacity := min (sumView old).capacity capacity.val} = sumView old := by
        simp [sumView, Nat.min_eq_left kept]
      rw [same]
      have modelInside : index.val < (sumCountersView counters).length := by simpa [sumCountersView] using inside
      have actualAt : (sumCountersView counters)[index.val] = sumView old := by
        simpa only [List.getElem?_eq_getElem modelInside, Option.some.injEq] using modelAt
      rw [← actualAt, List.set_getElem_self]

/-- The complete native loop implements every contribution in order. Its size
    bound is the admitted gateway chain limit, not a uniqueness assumption. -/
@[step] theorem aggregate_sum_spec (contributions : Slice counter_aggregation.SumCapacity)
    (bounded : contributions.val.length ≤ 16) :
    counter_aggregation.aggregate_sum contributions ⦃ actual =>
      sumCountersView actual = CounterAggregation.aggregateSum [] (contributions.val.map sumView) ⦄ := by
  unfold counter_aggregation.aggregate_sum counter_aggregation.aggregate_sum_loop
  apply loop.spec_decr_nat
    (measure := fun state => contributions.val.length - state.2.val)
    (inv := fun state => state.1.val.length ≤ state.2.val ∧ state.2.val ≤ contributions.val.length ∧
      sumCountersView state.1 = CounterAggregation.aggregateSum [] ((contributions.val.take state.2.val).map sumView))
  · rintro ⟨current, index⟩ ⟨currentSize, indexBound, currentMeaning⟩
    dsimp only at currentSize indexBound currentMeaning
    unfold counter_aggregation.aggregate_sum_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < contributions.val.length := by simpa using within
      step as ⟨entry, entryAt⟩
      step with contribute_sum_spec as ⟨updated, updatedMeaning⟩
      have updatedSize : updated.val.length ≤ current.val.length + 1 := by
        have modelBound := CounterAggregation.sum_contribute_length_le (sumCountersView current) (entry.key.val.map (·.val)) entry.capacity.val entry.slots.val
        have exactSize := congrArg List.length updatedMeaning
        simp only [sumCountersView, List.length_map] at exactSize modelBound
        omega
      step as ⟨next, nextValue⟩
      have nextNat : next.val = index.val + 1 := by simpa using nextValue
      refine ⟨by omega, by omega, ?_, by omega⟩
      rw [updatedMeaning, currentMeaning, nextValue,
        List.take_succ_eq_append_getElem inside, List.map_append, List.map_cons, List.map_nil,
        CounterAggregation.sum_aggregate_snoc]
      simp only [← entryAt, sumView]
    · simp only [spec_ok]
      have atEnd : contributions.val.length ≤ index.val := by simpa using within
      simpa only [List.take_of_length_le atEnd] using currentMeaning
  · simp [sumCountersView, CounterAggregation.aggregateSum]

theorem source_sum_aggregate_unique (contributions : Slice counter_aggregation.SumCapacity)
    (bounded : contributions.val.length ≤ 16) :
    counter_aggregation.aggregate_sum contributions ⦃ actual =>
      ((sumCountersView actual).map SumCounter.key).Nodup ⦄ := by
  apply spec_mono (aggregate_sum_spec contributions bounded)
  intro actual exactResult
  rw [exactResult]
  simpa [SumCounter.counter, List.map_map, Function.comp_def] using
    CounterAggregation.sum_aggregate_unique (contributions.val.map sumView)

theorem source_sum_aggregate_capacities (contributions : Slice counter_aggregation.SumCapacity)
    (bounded : contributions.val.length ≤ 16) :
    counter_aggregation.aggregate_sum contributions ⦃ actual =>
      ∀ key, CounterAggregation.lookup ((sumCountersView actual).map SumCounter.counter) key =
        CounterAggregation.specification (fun _ => none)
          ((contributions.val.map sumView).map SumCounter.counter) key ⦄ := by
  apply spec_mono (aggregate_sum_spec contributions bounded)
  intro actual exactResult key
  rw [exactResult]
  exact CounterAggregation.sum_aggregate_capacities _ key
/-- Every sum contribution receives the exact shared count counter's slot bound. -/
@[step] theorem linked_sum_contribution_exact (counts : Slice counter_aggregation.CounterCapacity)
    (countKey sumKey : Array Std.U8 32#usize) (capacity : Std.U64) :
    counter_aggregation.linked_sum_contribution counts countKey sumKey capacity ⦃ actual =>
      sumView actual = ⟨sumKey.val.map (·.val), capacity.val,
        (CounterAggregation.lookup (counts.val.map counterView) (countKey.val.map (·.val))).getD 0⟩ ⦄ := by
  unfold counter_aggregation.linked_sum_contribution
  step with count_capacity_spec as ⟨slots, slotMeaning⟩
  simp [sumView, slotMeaning]

/-- Composing the actual count aggregator and sum constructor earns the minimum;
    it does not assume a precomputed minimum or uniqueness of input keys. -/
theorem source_sum_slots_share_count_minimum (incoming : Slice counter_aggregation.CounterCapacity)
    (countKey sumKey : Array Std.U8 32#usize) (capacity : Std.U64) (bounded : incoming.val.length ≤ 16) :
    (do
      let counts ← counter_aggregation.aggregate incoming
      counter_aggregation.linked_sum_contribution (alloc.vec.Vec.deref counts) countKey sumKey capacity) ⦃ actual =>
      sumView actual = ⟨sumKey.val.map (·.val), capacity.val,
        (CounterAggregation.specification (fun _ => none) (incoming.val.map counterView)
          (countKey.val.map (·.val))).getD 0⟩ ⦄ := by
  step with aggregate_spec as ⟨counts, countMeaning⟩
  step with linked_sum_contribution_exact as ⟨actual, exactMeaning⟩
  have lookupMeaning : CounterAggregation.lookup (counts.val.map counterView) (countKey.val.map (·.val)) =
      CounterAggregation.specification (fun _ => none) (incoming.val.map counterView) (countKey.val.map (·.val)) := by
    change CounterAggregation.lookup (countersView counts) _ = _
    rw [countMeaning, CounterAggregation.aggregate_exact]
    rfl
  simpa [alloc.vec.Vec.deref, lookupMeaning] using exactMeaning

end Auths.Product.CounterAggregation.Refinement
