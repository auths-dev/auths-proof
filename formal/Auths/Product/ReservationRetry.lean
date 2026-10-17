import Mathlib.Tactic
namespace Auths.Product.ReservationRetry
inductive Target where
  | replay
  | count (position next : Nat)
  | sum (position readSlot next : Nat)
  | corrupt
  deriving DecidableEq

def wordMax : Nat := 2 ^ 64 - 1

def target (index : Nat) (counts sums : List Nat) (totalSize counterSize : Nat) : Target :=
  if index = 0 then .replay
  else
    let position := index - 1
    if position < counts.length then
      let previous := counts[position]!
      if previous < wordMax then .count position (previous + 1) else .corrupt
    else
      let position := position - counts.length
      if position < sums.length ∧ position < totalSize ∧ position < counterSize then
        let previous := sums[position]!
        if previous < wordMax then .sum position previous (previous + 1) else .corrupt
      else .corrupt

theorem existing_claim_is_replay (counts sums : List Nat) (totalSize counterSize : Nat) :
    target 0 counts sums totalSize counterSize = .replay := by simp [target]

theorem count_progress_exact (index : Nat) (counts sums : List Nat) (totalSize counterSize position next : Nat)
    (progress : target index counts sums totalSize counterSize = .count position next) :
    index = position + 1 ∧ position < counts.length ∧
      next = counts[position]! + 1 ∧ next ≤ wordMax := by
  unfold target at progress
  dsimp only at progress
  split_ifs at progress <;> simp_all
  all_goals rcases progress with ⟨rfl, rfl⟩
  all_goals omega

theorem sum_progress_exact (index : Nat) (counts sums : List Nat)
    (totalSize counterSize position readSlot next : Nat)
    (progress : target index counts sums totalSize counterSize = .sum position readSlot next) :
    index = counts.length + position + 1 ∧ position < sums.length ∧
      position < totalSize ∧ position < counterSize ∧
      readSlot = sums[position]! ∧ next = readSlot + 1 ∧ next ≤ wordMax := by
  unfold target at progress
  dsimp only at progress
  split_ifs at progress <;> simp_all
  all_goals rcases progress with ⟨rfl, rfl, rfl⟩
  all_goals omega

theorem count_available (counts sums : List Nat) (totalSize counterSize position : Nat)
    (inside : position < counts.length) (room : counts[position]! < wordMax) :
    target (position + 1) counts sums totalSize counterSize = .count position (counts[position]! + 1) := by
  have roomExact : counts[position] < wordMax := by simpa only [getElem!_pos counts position inside] using room
  simp [target, inside, roomExact]

theorem sum_available (counts sums : List Nat) (totalSize counterSize position : Nat)
    (inside : position < sums.length) (totals : position < totalSize) (counters : position < counterSize)
    (room : sums[position]! < wordMax) :
    target (counts.length + position + 1) counts sums totalSize counterSize =
      .sum position sums[position]! (sums[position]! + 1) := by
  have roomExact : sums[position] < wordMax := by simpa only [getElem!_pos sums position inside] using room
  simp [target, inside, totals, counters, roomExact]

end Auths.Product.ReservationRetry
