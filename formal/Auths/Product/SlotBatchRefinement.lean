import qualification.aeneas.generated.gateway.Funs
import Auths.Product.SlotBatch
open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
namespace Auths.Product.SlotBatch.Refinement
set_option maxHeartbeats 4000000

def keyBytes (value : Array Std.U8 32#usize) : Key := value.val.map (·.val)
def meaning : reservation_batch.SlotEntry → Entry
  | .Claim key => .claim (keyBytes key)
  | .Count key slot => .count (keyBytes key) slot.val
  | .Sum key slot amount cumulative => .sum (keyBytes key) slot.val amount.val cumulative.val

def entriesView (value : alloc.vec.Vec reservation_batch.SlotEntry) : List Entry := value.val.map meaning

def nativeCounts (counts : Slice counter_aggregation.CounterCapacity) (slots : Slice Std.U64) : List Entry :=
  List.zipWith (fun counter slot => Entry.count (keyBytes counter.key) slot.val) counts.val slots.val

private theorem below_pointer_max {size : Nat} (small : size < 4294967295) : size < Usize.max := by
  rcases Usize.bounds_eq with equal | equal <;> rw [equal] <;>
    simp only [U32.max_eq, U64.max_eq] <;> omega

@[step] theorem count_loop_exact (counts : Slice counter_aggregation.CounterCapacity) (slots : Slice Std.U64)
    (initial : alloc.vec.Vec reservation_batch.SlotEntry)
    (bound : counts.val.length ≤ 16) (aligned : counts.val.length = slots.val.length)
    (initialBound : initial.val.length ≤ 1) :
    reservation_batch.build_batch_loop0 counts slots initial 0#usize ⦃ actual =>
      entriesView actual = entriesView initial ++ nativeCounts counts slots ⦄ := by
  unfold reservation_batch.build_batch_loop0
  have completeLength : (nativeCounts counts slots).length = counts.val.length := by
    simp [nativeCounts, aligned]
  apply loop.spec_decr_nat
    (measure := fun state => counts.val.length - state.2.val)
    (inv := fun state => state.2.val ≤ counts.val.length ∧
      entriesView state.1 = entriesView initial ++ (nativeCounts counts slots).take state.2.val)
  · rintro ⟨current, index⟩ ⟨indexBound, prefixMeaning⟩
    dsimp only at indexBound prefixMeaning
    unfold reservation_batch.build_batch_loop0.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < counts.val.length := by simpa using within
      step as ⟨counter, counterAt⟩
      step as ⟨slot, slotAt⟩
      have currentSize : current.val.length = initial.val.length + index.val := by
        have size := congrArg List.length prefixMeaning
        simp only [entriesView, List.length_map, List.length_append, List.length_take, completeLength,
          Nat.min_eq_left indexBound] at size
        exact size
      have room : current.length < Usize.max := below_pointer_max (by change current.val.length < _; omega)
      step as ⟨updated, updatedMeaning⟩
      step as ⟨next, nextValue⟩
      refine ⟨by omega, ?_, by omega⟩
      have viewUpdate : entriesView updated = entriesView current ++ [Entry.count (keyBytes counter.key) slot.val] := by
        simp [entriesView, updatedMeaning, meaning, List.map_append]
      rw [viewUpdate, prefixMeaning, nextValue, List.take_succ_eq_append_getElem (by omega)]
      simp only [List.append_assoc, List.append_cancel_left_eq, List.cons.injEq, and_true]
      simp [nativeCounts, counterAt, slotAt]
    · simp only [spec_ok]
      have atEnd : counts.val.length ≤ index.val := by simpa using within
      have complete : (nativeCounts counts slots).length ≤ index.val := by omega
      simpa only [List.take_of_length_le complete] using prefixMeaning
  · exact ⟨by simp, by simp⟩
def nativeSums : List Entry → List counter_aggregation.SumCapacity → List Std.U64 → List Std.U64 → Std.U64 → Option (List Entry)
  | built, [], [], [], _ => some built
  | built, counter :: counters, slot :: slots, total :: totals, amount =>
    match U64.checked_add total amount with
    | none => none
    | some cumulative => nativeSums
        (built ++ [.sum (keyBytes counter.key) slot.val amount.val cumulative.val]) counters slots totals amount
  | _, _, _, _, _ => none

/-- The tail-recursive native-shaped value model agrees with the independent
    list specification, including failure after any complete prefix. -/
theorem native_sums_refines (built : List Entry) (counters : List counter_aggregation.SumCapacity)
    (slots totals : List Std.U64) (amount : Std.U64) :
    nativeSums built counters slots totals amount =
      (sumEntries (counters.map (fun counter => keyBytes counter.key))
        (slots.map (fun slot => slot.val)) (totals.map (fun total => total.val)) amount.val).map (built ++ ·) := by
  induction counters generalizing built slots totals with
  | nil => cases slots <;> cases totals <;> simp [nativeSums, sumEntries]
  | cons counter counters ih =>
    cases slots with
    | nil => simp [nativeSums, sumEntries]
    | cons slot slots =>
      cases totals with
      | nil => simp [nativeSums, sumEntries]
      | cons total totals =>
        have specification := U64.checked_add_bv_spec total amount
        cases equation : U64.checked_add total amount with
        | none =>
          rw [equation] at specification
          simp only [U64.max_eq] at specification
          have overflow : ¬total.val + amount.val ≤ wordMax := by unfold wordMax; scalar_tac
          simp [nativeSums, equation, sumEntries, overflow]
        | some cumulative =>
          rw [equation] at specification
          simp only [U64.max_eq] at specification
          obtain ⟨within, cumulativeValue, _⟩ := specification
          have fits : total.val + amount.val ≤ wordMax := by unfold wordMax; scalar_tac
          have exactValue : cumulative.val = total.val + amount.val := by scalar_tac
          simp [nativeSums, equation, sumEntries, fits, ih, exactValue, Option.map_map,
            Function.comp_def, List.append_assoc]

@[step] theorem sum_loop_exact (sums : Slice counter_aggregation.SumCapacity) (slots totals : Slice Std.U64)
    (amount : Std.U64) (initial : alloc.vec.Vec reservation_batch.SlotEntry)
    (bound : sums.val.length ≤ 16) (slotsAligned : sums.val.length = slots.val.length)
    (totalsAligned : sums.val.length = totals.val.length) (initialBound : initial.val.length ≤ 17) :
    reservation_batch.build_batch_loop1 sums slots totals amount initial 0#usize ⦃ actual =>
      actual.map entriesView = nativeSums (entriesView initial) sums.val slots.val totals.val amount ⦄ := by
  unfold reservation_batch.build_batch_loop1
  let wanted := nativeSums (entriesView initial) sums.val slots.val totals.val amount
  apply loop.spec_decr_nat
    (measure := fun state => sums.val.length - state.2.val)
    (inv := fun state => state.2.val ≤ sums.val.length ∧
      state.1.val.length ≤ initial.val.length + state.2.val ∧
      wanted = nativeSums (entriesView state.1) (sums.val.drop state.2.val)
        (slots.val.drop state.2.val) (totals.val.drop state.2.val) amount)
  · rintro ⟨current, index⟩ ⟨indexBound, currentBound, remainingMeaning⟩
    dsimp only at indexBound currentBound remainingMeaning
    unfold reservation_batch.build_batch_loop1.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < sums.val.length := by simpa using within
      have insideSlots : index.val < slots.val.length := by omega
      have insideTotals : index.val < totals.val.length := by omega
      step as ⟨total, totalAt⟩
      simp only [lift, bind_tc_ok]
      cases equation : U64.checked_add total amount with
      | none =>
        simp only [spec_ok, Option.map_none]
        rw [List.drop_eq_getElem_cons inside, List.drop_eq_getElem_cons insideSlots,
          List.drop_eq_getElem_cons insideTotals] at remainingMeaning
        simp only [nativeSums, ← totalAt, equation] at remainingMeaning
        exact remainingMeaning.symm
      | some cumulative =>
        step as ⟨counter, counterAt⟩
        step as ⟨slot, slotAt⟩
        have room : current.length < Usize.max := below_pointer_max (by change current.val.length < _; omega)
        step as ⟨updated, updatedMeaning⟩
        step as ⟨next, nextValue⟩
        have updatedSize : updated.val.length = current.val.length + 1 := by simp [updatedMeaning]
        have nextNat : next.val = index.val + 1 := by simpa using nextValue
        refine ⟨by omega, by omega, ?_, by omega⟩
        have viewUpdate : entriesView updated = entriesView current ++
            [.sum (keyBytes counter.key) slot.val amount.val cumulative.val] := by
          simp [entriesView, updatedMeaning, meaning, List.map_append]
        rw [List.drop_eq_getElem_cons inside, List.drop_eq_getElem_cons insideSlots,
          List.drop_eq_getElem_cons insideTotals] at remainingMeaning
        simp only [nativeSums, ← totalAt, equation, ← counterAt, ← slotAt] at remainingMeaning
        simpa only [viewUpdate, nextNat] using remainingMeaning
    · simp only [spec_ok, Option.map_some]
      have atEnd : sums.val.length ≤ index.val := by simpa using within
      have slotsEnd : slots.val.length ≤ index.val := by omega
      have totalsEnd : totals.val.length ≤ index.val := by omega
      simp only [List.drop_of_length_le atEnd, List.drop_of_length_le slotsEnd,
        List.drop_of_length_le totalsEnd, nativeSums] at remainingMeaning
      exact remainingMeaning.symm
  · simp [wanted]

def countKeys (counts : Slice counter_aggregation.CounterCapacity) : List Key := counts.val.map (fun counter => keyBytes counter.key)
def sumKeys (sums : Slice counter_aggregation.SumCapacity) : List Key := sums.val.map (fun counter => keyBytes counter.key)
def wordValues (values : Slice Std.U64) : List Nat := values.val.map (fun value => value.val)

/-- The complete source constructor either refuses the checked malformed shape
    or produces the independent complete claim/count/sum batch. -/
@[step] theorem build_exact (claim : Array Std.U8 32#usize)
    (counts : Slice counter_aggregation.CounterCapacity) (countSlots : Slice Std.U64)
    (sums : Slice counter_aggregation.SumCapacity) (sumSlots totals : Slice Std.U64) (amount : Std.U64) :
    reservation_batch.build_batch claim counts countSlots sums sumSlots totals amount ⦃ actual =>
      actual.map entriesView = build (keyBytes claim) (countKeys counts) (wordValues countSlots)
        (sumKeys sums) (wordValues sumSlots) (wordValues totals) amount.val ⦄ := by
  have reject (invalid : ¬shape (countKeys counts) (wordValues countSlots) (sumKeys sums)
      (wordValues sumSlots) (wordValues totals)) :
      ok (none : Option (alloc.vec.Vec reservation_batch.SlotEntry)) ⦃ actual =>
        actual.map entriesView = build (keyBytes claim) (countKeys counts) (wordValues countSlots)
          (sumKeys sums) (wordValues sumSlots) (wordValues totals) amount.val ⦄ := by
    simp [spec_ok, build, invalid]
  unfold reservation_batch.build_batch
  simp only [reservation_batch.MAX_COUNTERS_PER_KIND]
  split <;> rename_i longCounts
  · apply reject
    simp only [shape, countKeys, sumKeys, wordValues, List.length_map]
    scalar_tac
  · split <;> rename_i longSums
    · apply reject
      simp only [shape, countKeys, sumKeys, wordValues, List.length_map]
      scalar_tac
    · split <;> rename_i mismatchedCounts
      · apply reject
        simp only [shape, countKeys, sumKeys, wordValues, List.length_map]
        scalar_tac
      · split <;> rename_i mismatchedSlots
        · apply reject
          simp only [shape, countKeys, sumKeys, wordValues, List.length_map]
          scalar_tac
        · split <;> rename_i mismatchedTotals
          · apply reject
            simp only [shape, countKeys, sumKeys, wordValues, List.length_map]
            scalar_tac
          · have countBound : counts.val.length ≤ 16 := by scalar_tac
            have sumBound : sums.val.length ≤ 16 := by scalar_tac
            have countAligned : counts.val.length = countSlots.val.length := by scalar_tac
            have slotsAligned : sums.val.length = sumSlots.val.length := by scalar_tac
            have totalsAligned : sums.val.length = totals.val.length := by scalar_tac
            have valid : shape (countKeys counts) (wordValues countSlots) (sumKeys sums)
                (wordValues sumSlots) (wordValues totals) := by
              simp only [shape, countKeys, sumKeys, wordValues, List.length_map]
              exact ⟨countBound, sumBound, countAligned, slotsAligned, totalsAligned⟩
            step as ⟨initial, initialMeaning⟩
            apply spec_bind (count_loop_exact counts countSlots initial countBound countAligned (by simp [initialMeaning]))
            intro afterCounts countsMeaning
            have countLength : afterCounts.val.length = 1 + counts.val.length := by
              have length := congrArg List.length countsMeaning
              simpa [entriesView, initialMeaning, nativeCounts, countAligned, Nat.add_comm] using length
            apply spec_mono (sum_loop_exact sums sumSlots totals amount afterCounts sumBound slotsAligned totalsAligned (by omega))
            intro actual actualMeaning
            simp only [build, valid, ↓reduceIte]
            rw [actualMeaning, native_sums_refines, countsMeaning]
            simp [build, valid, entriesView, initialMeaning, meaning, nativeCounts,
              countEntries, countKeys, sumKeys, wordValues, List.zipWith_map,
              List.append_assoc]

theorem source_claim_first (claim : Array Std.U8 32#usize)
    (counts : Slice counter_aggregation.CounterCapacity) (countSlots : Slice Std.U64)
    (sums : Slice counter_aggregation.SumCapacity) (sumSlots totals : Slice Std.U64) (amount : Std.U64) :
    reservation_batch.build_batch claim counts countSlots sums sumSlots totals amount ⦃ actual =>
      match actual with
      | none => True
      | some entries => (entriesView entries).head? = some (.claim (keyBytes claim)) ⦄ := by
  apply spec_mono (build_exact claim counts countSlots sums sumSlots totals amount)
  intro actual exactResult
  cases actual with
  | none => trivial
  | some entries =>
    simp only [Option.map_some] at exactResult
    exact first_is_claim _ _ _ _ _ _ _ _ exactResult.symm

theorem source_complete_entry_count (claim : Array Std.U8 32#usize)
    (counts : Slice counter_aggregation.CounterCapacity) (countSlots : Slice Std.U64)
    (sums : Slice counter_aggregation.SumCapacity) (sumSlots totals : Slice Std.U64) (amount : Std.U64) :
    reservation_batch.build_batch claim counts countSlots sums sumSlots totals amount ⦃ actual =>
      match actual with
      | none => True
      | some entries => entries.val.length = 1 + counts.val.length + sums.val.length ∧ entries.val.length ≤ 33 ⦄ := by
  apply spec_mono (build_exact claim counts countSlots sums sumSlots totals amount)
  intro actual exactResult
  cases actual with
  | none => trivial
  | some entries =>
    simp only [Option.map_some] at exactResult
    have complete := exact_entry_count _ _ _ _ _ _ _ _ exactResult.symm
    simpa only [entriesView, countKeys, sumKeys, List.length_map] using complete

theorem source_invalid_shape_refused (claim : Array Std.U8 32#usize)
    (counts : Slice counter_aggregation.CounterCapacity) (countSlots : Slice Std.U64)
    (sums : Slice counter_aggregation.SumCapacity) (sumSlots totals : Slice Std.U64) (amount : Std.U64)
    (invalid : ¬shape (countKeys counts) (wordValues countSlots) (sumKeys sums)
      (wordValues sumSlots) (wordValues totals)) :
    reservation_batch.build_batch claim counts countSlots sums sumSlots totals amount ⦃ actual => actual = none ⦄ := by
  apply spec_mono (build_exact claim counts countSlots sums sumSlots totals amount)
  intro actual exactResult
  rw [invalid_shape_refused _ _ _ _ _ _ _ invalid] at exactResult
  cases actual <;> simp_all

end Auths.Product.SlotBatch.Refinement
