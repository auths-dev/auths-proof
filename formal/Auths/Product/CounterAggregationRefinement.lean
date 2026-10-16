import qualification.aeneas.generated.gateway.Funs
import Auths.Product.CounterAggregation
import Auths.Product.SchemaIndex
open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
namespace Auths.Product.CounterAggregation.Refinement
set_option maxHeartbeats 4000000

@[step] theorem counter_equal_spec (left right : Array Std.U8 32#usize) :
    counter_aggregation.counter_equal left right ⦃ actual => actual = decide (left.val = right.val) ⦄ := by
  unfold counter_aggregation.counter_equal counter_aggregation.counter_equal_loop
  have leftSize : left.val.length = 32 := by simpa using left.property
  have rightSize : right.val.length = 32 := by simpa using right.property
  apply loop.spec_decr_nat
    (measure := fun position => 32 - position.val)
    (inv := fun position => position.val ≤ 32 ∧ left.val.take position.val = right.val.take position.val)
  · intro position processed
    unfold counter_aggregation.counter_equal_loop.body
    split <;> rename_i within
    · have inside : position.val < 32 := by simpa using within
      step as ⟨leftByte, leftAt⟩
      step as ⟨rightByte, rightAt⟩
      split <;> rename_i equal
      · simp only [spec_ok]
        have different : left.val ≠ right.val := by
          intro same
          have sameAt := congrArg (fun values : List Std.U8 => values[position.val]?) same
          rw [List.getElem?_eq_getElem (l := left.val) (i := position.val) (by omega),
            List.getElem?_eq_getElem (l := right.val) (i := position.val) (by omega)] at sameAt
          have sameByte : leftByte = rightByte := by
            simpa only [← leftAt, ← rightAt, Option.some.injEq] using sameAt
          simpa [sameByte] using equal
        simp [different]
      · step as ⟨next, nextValue⟩
        refine ⟨by omega, ?_, by omega⟩
        have sameByte : leftByte = rightByte := (UScalar.eq_equiv _ _).mpr (by simpa using equal)
        rw [nextValue, List.take_succ_eq_append_getElem (by omega), List.take_succ_eq_append_getElem (by omega)]
        simp only [← leftAt, ← rightAt, processed.2, sameByte]
    · simp only [spec_ok]
      have atEnd : 32 ≤ position.val := by simpa using within
      have leftDone : left.val.take position.val = left.val := List.take_of_length_le (by omega)
      have rightDone : right.val.take position.val = right.val := List.take_of_length_le (by omega)
      have same : left.val = right.val := by simpa only [leftDone, rightDone] using processed.2
      simp [same]
  · exact ⟨by simp, by simp⟩

def counterKeys (counters : Slice counter_aggregation.CounterCapacity) : List SchemaIndex.Name :=
  counters.val.map (fun counter => counter.key.val.map (·.val))

theorem byteList_injective (left right : List Std.U8) : left.map (·.val) = right.map (·.val) ↔ left = right := by
  constructor
  · intro same
    induction left generalizing right with
    | nil => cases right <;> simp_all
    | cons head tail ih =>
      cases right with
      | nil => simp at same
      | cons other rest =>
        simp only [List.map_cons, List.cons.injEq] at same
        rw [(UScalar.eq_equiv _ _).mpr same.1, ih rest same.2]
  · intro same; rw [same]

@[step] theorem counter_position_spec (counters : Slice counter_aggregation.CounterCapacity) (key : Array Std.U8 32#usize) :
    counter_aggregation.counter_position counters key ⦃ actual =>
      actual.map UScalar.val = SchemaIndex.position (counterKeys counters) (key.val.map (·.val)) ⦄ := by
  unfold counter_aggregation.counter_position counter_aggregation.counter_position_loop
  apply loop.spec_decr_nat
    (measure := fun position => counters.val.length - position.val)
    (inv := fun position => position.val ≤ counters.val.length ∧
      ∀ index, index < position.val → (counterKeys counters)[index]? ≠ some (key.val.map (·.val)))
  · intro position processed
    unfold counter_aggregation.counter_position_loop.body
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
          simp_all [counterKeys, List.getElem?_map]
          exact sameMeaning ∘ (byteList_injective _ _).mp
      · simp only [↓reduceIte, spec_ok]
        symm
        apply SchemaIndex.position_eq_first
        · simp_all [counterKeys, List.getElem?_map]
        · exact processed.2
    · simp only [spec_ok]
      symm
      apply (SchemaIndex.absent_iff _ _).mpr
      intro member
      obtain ⟨index, atIndex⟩ := List.mem_iff_getElem?.mp member
      have inside : index < (counterKeys counters).length := (List.getElem?_eq_some_iff.mp atIndex).1
      have atEnd : counters.val.length ≤ position.val := by simpa using within
      have length : (counterKeys counters).length = counters.val.length := by simp [counterKeys]
      exact processed.2 index (by omega) atIndex
  · exact ⟨by simp, by simp⟩
def counterView (counter : counter_aggregation.CounterCapacity) : CounterAggregation.Counter :=
  ⟨counter.key.val.map (·.val), counter.capacity.val⟩

def countersView (counters : alloc.vec.Vec counter_aggregation.CounterCapacity) : List CounterAggregation.Counter :=
  counters.val.map counterView

/-- The actual keyed update preserves the independent minimum-capacity map. -/
@[step] theorem contribute_spec (counters : alloc.vec.Vec counter_aggregation.CounterCapacity)
    (key : Array Std.U8 32#usize) (capacity : Std.U64)
    (fits : counters.val.length < 4294967295) :
    counter_aggregation.contribute counters key capacity ⦃ actual =>
      countersView actual = CounterAggregation.contribute (countersView counters) (key.val.map (·.val)) capacity.val ⦄ := by
  unfold counter_aggregation.contribute
  step with counter_position_spec as ⟨position, positionMeaning⟩
  have positioned : position.map UScalar.val =
      SchemaIndex.position ((countersView counters).map Counter.key) (key.val.map (·.val)) := by
    simpa [counterKeys, countersView, counterView, alloc.vec.Vec.deref, List.map_map, Function.comp_def] using positionMeaning
  cases position with
  | none =>
    simp only [bind_tc_ok]
    have room : counters.length < Usize.max := by
      rcases Usize.bounds_eq with equal | equal <;> rw [equal] <;>
        simp only [U32.max_eq, U64.max_eq] <;> change counters.val.length < _ <;> omega
    step as ⟨actual, actualMeaning⟩
    rw [CounterAggregation.contribute_absent _ _ _ positioned.symm]
    simp [countersView, actualMeaning, counterView, List.map_append]
  | some index =>
    simp only [Option.map_some] at positioned
    have keyAt := SchemaIndex.position_points_to_name _ _ index.val positioned.symm
    have inside : index.val < counters.val.length := by
      have lengthBound := (List.getElem?_eq_some_iff.mp keyAt).1
      simpa [countersView, List.length_map] using lengthBound
    step as ⟨old, oldAt⟩
    have modelAt : (countersView counters)[index.val]? = some (counterView old) := by
      simp [countersView, List.getElem?_map, List.getElem?_eq_getElem inside, oldAt]
    have update := CounterAggregation.contribute_at _ _ capacity.val index.val (counterView old) positioned.symm modelAt
    rw [update]
    split <;> rename_i tighter
    · step as ⟨mutable, restore, mutableAt, restoreMeaning⟩
      have same : mutable = old := mutableAt.trans oldAt.symm
      subst mutable
      have tight : capacity.val < old.capacity.val := by simpa using tighter
      simp [restoreMeaning, countersView, counterView, List.map_set, Nat.min_eq_right (Nat.le_of_lt tight), same]
    · simp only [spec_ok]
      have kept : old.capacity.val ≤ capacity.val := by simpa using tighter
      have same : {counterView old with capacity := min (counterView old).capacity capacity.val} = counterView old := by
        simp [counterView, Nat.min_eq_left kept]
      rw [same]
      have modelInside : index.val < (countersView counters).length := by simpa [countersView] using inside
      have actualAt : (countersView counters)[index.val] = counterView old := by
        simpa only [List.getElem?_eq_getElem modelInside, Option.some.injEq] using modelAt
      rw [← actualAt, List.set_getElem_self]

/-- The complete native loop implements every contribution in order. Its size
    bound is the admitted gateway chain limit, not a uniqueness assumption. -/
@[step] theorem aggregate_spec (contributions : Slice counter_aggregation.CounterCapacity)
    (bounded : contributions.val.length ≤ 16) :
    counter_aggregation.aggregate contributions ⦃ actual =>
      countersView actual = CounterAggregation.aggregate [] (contributions.val.map counterView) ⦄ := by
  unfold counter_aggregation.aggregate counter_aggregation.aggregate_loop
  apply loop.spec_decr_nat
    (measure := fun state => contributions.val.length - state.2.val)
    (inv := fun state => state.1.val.length ≤ state.2.val ∧ state.2.val ≤ contributions.val.length ∧
      countersView state.1 = CounterAggregation.aggregate [] ((contributions.val.take state.2.val).map counterView))
  · rintro ⟨current, index⟩ ⟨currentSize, indexBound, currentMeaning⟩
    dsimp only at currentSize indexBound currentMeaning
    unfold counter_aggregation.aggregate_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < contributions.val.length := by simpa using within
      step as ⟨entry, entryAt⟩
      step with contribute_spec as ⟨updated, updatedMeaning⟩
      have updatedSize : updated.val.length ≤ current.val.length + 1 := by
        have modelBound := CounterAggregation.contribute_length_le (countersView current) (entry.key.val.map (·.val)) entry.capacity.val
        have exactSize := congrArg List.length updatedMeaning
        simp only [countersView, List.length_map] at exactSize modelBound
        omega
      step as ⟨next, nextValue⟩
      have nextNat : next.val = index.val + 1 := by simpa using nextValue
      refine ⟨by omega, by omega, ?_, by omega⟩
      rw [updatedMeaning, currentMeaning, nextValue,
        List.take_succ_eq_append_getElem inside, List.map_append, List.map_cons, List.map_nil,
        CounterAggregation.aggregate_snoc]
      simp only [← entryAt, counterView]
    · simp only [spec_ok]
      have atEnd : contributions.val.length ≤ index.val := by simpa using within
      simpa only [List.take_of_length_le atEnd] using currentMeaning
  · simp [countersView, CounterAggregation.aggregate]

theorem source_aggregate_unique (contributions : Slice counter_aggregation.CounterCapacity)
    (bounded : contributions.val.length ≤ 16) :
    counter_aggregation.aggregate contributions ⦃ actual =>
      ((countersView actual).map Counter.key).Nodup ⦄ := by
  apply spec_mono (aggregate_spec contributions bounded)
  intro actual exactResult
  rw [exactResult]
  exact CounterAggregation.aggregate_unique [] _ (by simp)

theorem source_aggregate_capacities (contributions : Slice counter_aggregation.CounterCapacity)
    (bounded : contributions.val.length ≤ 16) :
    counter_aggregation.aggregate contributions ⦃ actual =>
      ∀ key, CounterAggregation.lookup (countersView actual) key =
        CounterAggregation.specification (fun _ => none) (contributions.val.map counterView) key ⦄ := by
  apply spec_mono (aggregate_spec contributions bounded)
  intro actual exactResult key
  rw [exactResult, CounterAggregation.aggregate_exact]
  rfl

end Auths.Product.CounterAggregation.Refinement
