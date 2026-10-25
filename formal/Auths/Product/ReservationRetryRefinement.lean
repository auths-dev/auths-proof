import qualification.aeneas.generated.gateway.Funs
import Auths.Product.ReservationRetry
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
namespace Auths.Product.ReservationRetry.Refinement
set_option maxHeartbeats 4000000

def meaning : reservation_retry.RetryTarget → Target
  | .Replay => .replay
  | .Corrupt => .corrupt
  | .Count position next => .count position.val next.val
  | .Sum position readSlot next => .sum position.val readSlot.val next.val

private theorem successor_exact (previous : Std.U64) :
    (U64.checked_add previous 1#u64).map (fun value => value.val) =
      if previous.val < wordMax then some (previous.val + 1) else none := by
  have specification := U64.checked_add_bv_spec previous 1#u64
  cases equation : U64.checked_add previous 1#u64 with
  | none =>
    rw [equation] at specification
    simp only [U64.max_eq] at specification
    simp only [Option.map_none, wordMax, Nat.reducePow, Nat.reduceSub]
    split <;> first | rfl | (exfalso; scalar_tac)
  | some next =>
    rw [equation] at specification
    simp only [U64.max_eq] at specification
    obtain ⟨within, nextValue, _⟩ := specification
    simp only [Option.map_some, wordMax, Nat.reducePow, Nat.reduceSub]
    split
    · simp only [Option.some.injEq]; scalar_tac
    · exfalso; scalar_tac

private theorem checked_count (position : Std.Usize) (previous : Std.U64) :
    (match U64.checked_add previous 1#u64 with
    | none => ok reservation_retry.RetryTarget.Corrupt
    | some next => ok (reservation_retry.RetryTarget.Count position next)) ⦃ actual =>
      meaning actual = if previous.val < wordMax then .count position.val (previous.val + 1) else .corrupt ⦄ := by
  have nextMeaning := successor_exact previous
  cases next : U64.checked_add previous 1#u64 with
  | none =>
    rw [next] at nextMeaning
    simp only [Option.map_none] at nextMeaning
    split_ifs at nextMeaning ⊢ <;> simp_all [spec_ok, meaning]
  | some value =>
    rw [next] at nextMeaning
    simp only [Option.map_some] at nextMeaning
    split_ifs at nextMeaning ⊢ <;> simp_all [spec_ok, meaning]

private theorem checked_sum (position : Std.Usize) (previous : Std.U64) :
    (match U64.checked_add previous 1#u64 with
    | none => ok reservation_retry.RetryTarget.Corrupt
    | some next => ok (reservation_retry.RetryTarget.Sum position previous next)) ⦃ actual =>
      meaning actual = if previous.val < wordMax then .sum position.val previous.val (previous.val + 1) else .corrupt ⦄ := by
  have nextMeaning := successor_exact previous
  cases next : U64.checked_add previous 1#u64 with
  | none =>
    rw [next] at nextMeaning
    simp only [Option.map_none] at nextMeaning
    split_ifs at nextMeaning ⊢ <;> simp_all [spec_ok, meaning]
  | some value =>
    rw [next] at nextMeaning
    simp only [Option.map_some] at nextMeaning
    split_ifs at nextMeaning ⊢ <;> simp_all [spec_ok, meaning]

/-- Every native conflict index is interpreted exactly, including malformed
    indices, missing parallel arrays and word overflow. No bounds are assumed. -/
@[step] theorem retry_target_exact (index : Std.Usize) (counts sums : Slice Std.U64)
    (totalSize counterSize : Std.Usize) :
    reservation_retry.retry_target index counts sums totalSize counterSize ⦃ actual =>
      meaning actual = target index.val (counts.val.map (fun value => value.val)) (sums.val.map (fun value => value.val))
        totalSize.val counterSize.val ⦄ := by
  unfold reservation_retry.retry_target
  split <;> rename_i zero
  · have zeroNat : index.val = 0 := by scalar_tac
    simp only [spec_ok, meaning, target, zeroNat, ↓reduceIte]
  ·
    have nonzero : index.val ≠ 0 := by intro equal; apply zero; scalar_tac
    step as ⟨position, positionValue⟩
    have positionNat : position.val = index.val - 1 := by simpa using positionValue
    split <;> rename_i countRole
    · have inside : position.val < counts.val.length := by simpa using countRole
      step as ⟨previous, previousAt⟩
      have projected : (counts.val.map (fun value => value.val))[position.val]! = previous.val := by
        simp [getElem!_pos (counts.val.map (fun value => value.val)) position.val (by simpa using inside), previousAt]
      have model : target index.val (counts.val.map (fun value => value.val)) (sums.val.map (fun value => value.val)) totalSize.val counterSize.val =
          if previous.val < wordMax then .count position.val (previous.val + 1) else .corrupt := by
        simp only [target, nonzero, ↓reduceIte, List.length_map, ← positionNat, inside, projected]
      rw [model]
      simp only [lift, bind_tc_ok]
      exact checked_count position previous
    · have notCount : ¬ position.val < counts.val.length := by simpa using countRole
      step as ⟨sumPosition, sumPositionValue⟩
      have sumPositionNat : sumPosition.val = position.val - counts.val.length := by simpa using sumPositionValue
      have model : target index.val (counts.val.map (fun value => value.val)) (sums.val.map (fun value => value.val)) totalSize.val counterSize.val =
          if sumPosition.val < sums.val.length ∧ sumPosition.val < totalSize.val ∧ sumPosition.val < counterSize.val then
            let previous := (sums.val.map (fun value => value.val))[sumPosition.val]!
            if previous < wordMax then .sum sumPosition.val previous (previous + 1) else .corrupt
          else .corrupt := by
        simp only [target, nonzero, ↓reduceIte, List.length_map, ← positionNat, notCount, ← sumPositionNat]
      rw [model]
      split <;> rename_i outsideSums
      · have outside : ¬sumPosition.val < sums.val.length := by simpa using outsideSums
        simp [outside, meaning, spec_ok]
      · have inside : sumPosition.val < sums.val.length := by simpa using outsideSums
        split <;> rename_i outsideTotals
        · have outside : ¬sumPosition.val < totalSize.val := by simpa using outsideTotals
          simp [outside, meaning, spec_ok]
        · have insideTotals : sumPosition.val < totalSize.val := by simpa using outsideTotals
          split <;> rename_i outsideCounters
          · have outside : ¬sumPosition.val < counterSize.val := by simpa using outsideCounters
            simp [outside, meaning, spec_ok]
          · have insideCounters : sumPosition.val < counterSize.val := by simpa using outsideCounters
            step as ⟨previous, previousAt⟩
            have projected : (sums.val.map (fun value => value.val))[sumPosition.val]! = previous.val := by
              simp [getElem!_pos (sums.val.map (fun value => value.val)) sumPosition.val (by simpa using inside), previousAt]
            simp only [inside, insideTotals, insideCounters, and_self, ↓reduceIte, projected, lift, bind_tc_ok]
            exact checked_sum sumPosition previous
theorem source_claim_conflict_is_replay (counts sums : Slice Std.U64) (totalSize counterSize : Std.Usize) :
    reservation_retry.retry_target 0#usize counts sums totalSize counterSize ⦃ actual =>
      actual = .Replay ⦄ := by
  apply spec_mono (retry_target_exact 0#usize counts sums totalSize counterSize)
  intro actual exactResult
  have matched : meaning actual = .replay := by simpa [target] using exactResult
  cases actual <;> simp_all [meaning]

theorem source_count_progress_safe (index : Std.Usize) (counts sums : Slice Std.U64)
    (totalSize counterSize : Std.Usize) :
    reservation_retry.retry_target index counts sums totalSize counterSize ⦃ actual =>
      ∀ position next, meaning actual = .count position next →
        index.val = position + 1 ∧ position < counts.val.length ∧
          next = (counts.val.map (fun value => value.val))[position]! + 1 ∧ next ≤ wordMax ⦄ := by
  apply spec_mono (retry_target_exact index counts sums totalSize counterSize)
  intro actual exactResult position next returned
  have modelResult := exactResult.symm.trans returned
  simpa only [List.length_map] using
    count_progress_exact index.val (counts.val.map (fun value => value.val))
      (sums.val.map (fun value => value.val)) totalSize.val counterSize.val position next modelResult

theorem source_sum_progress_safe (index : Std.Usize) (counts sums : Slice Std.U64)
    (totalSize counterSize : Std.Usize) :
    reservation_retry.retry_target index counts sums totalSize counterSize ⦃ actual =>
      ∀ position readSlot next, meaning actual = .sum position readSlot next →
        index.val = counts.val.length + position + 1 ∧ position < sums.val.length ∧
          position < totalSize.val ∧ position < counterSize.val ∧
          readSlot = (sums.val.map (fun value => value.val))[position]! ∧
          next = readSlot + 1 ∧ next ≤ wordMax ⦄ := by
  apply spec_mono (retry_target_exact index counts sums totalSize counterSize)
  intro actual exactResult position readSlot next returned
  have modelResult := exactResult.symm.trans returned
  simpa only [List.length_map] using
    sum_progress_exact index.val (counts.val.map (fun value => value.val))
      (sums.val.map (fun value => value.val)) totalSize.val counterSize.val position readSlot next modelResult

end Auths.Product.ReservationRetry.Refinement
