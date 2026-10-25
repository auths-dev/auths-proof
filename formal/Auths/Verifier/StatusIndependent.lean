import Auths.Verifier.StatusFold
namespace Auths.StatusSelection.Algebra
open Model

def trustedMaximum {Subject : Type} (rows : List (Statement Subject × Nat)) : Nat :=
  rows.foldl (fun maximum pair => max maximum pair.1.sequence) 0

def trustedLatest {Subject : Type} (rows : List (Statement Subject × Nat)) : List (Statement Subject × Nat) :=
  rows.filter (fun pair => pair.1.sequence == trustedMaximum rows)

theorem latest_map_maximum {Subject : Type} (rows : List (Statement Subject × Nat)) (cap age now : Nat) :
    sequenceMaximum (rows.map (latestRow cap age now)) = trustedMaximum rows := by
  simp [sequenceMaximum, List.foldr_map, trustedMaximum, maximum_foldl, latestRow]

theorem latest_map_filter {Subject : Type} (rows : List (Statement Subject × Nat)) (cap age now sequence : Nat) :
    atSequence (rows.map (latestRow cap age now)) sequence =
      (rows.filter (fun pair => pair.1.sequence == sequence)).map (latestRow cap age now) := by
  simp [atSequence, List.filter_map, Function.comp_def, latestRow]

theorem latest_map_summary {Subject : Type} (rows : List (Statement Subject × Nat)) (cap age now : Nat) :
    collectLatest (rows.map (latestRow cap age now)) =
      if rows.isEmpty then none else
      some ⟨trustedMaximum rows,
        (trustedLatest rows).any (fun pair => !fresh age pair.1.observed pair.1.expiresAt now),
        (trustedLatest rows).any (fun pair => !pair.1.active),
        (trustedLatest rows).foldl (fun horizon pair => min horizon (deadline age pair.1.observed pair.1.expiresAt)) cap⟩ := by
  rw [collectLatest_exact cap _ (by
    intro row member
    obtain ⟨pair, _, equal⟩ := List.mem_map.mp member
    subst row
    exact Nat.min_le_left _ _)]
  simp only [listSummary, List.isEmpty_map, latest_map_maximum, latest_map_filter]
  split_ifs
  · rfl
  · congr 2
    · simp [List.any_map, latestRow, trustedLatest]
    · simp [List.any_map, latestRow, trustedLatest]
    · simp only [List.foldr_map, latestRow]
      rw [capped_minimum, minimum_foldl]
      rfl

def listFinish {Subject : Type} (cap age now : Nat) (selected exact : List (Statement Subject))
    (admitted : List (Statement Subject × Nat)) : Evaluation :=
  if selected.isEmpty then ⟨.missing, cap⟩
  else if exact.isEmpty then ⟨.wrongMethod, now⟩
  else if admitted.isEmpty then ⟨.untrusted, now⟩
  else if admitted.any (fun pair => pair.1.sequence < pair.2) then ⟨.rollback, now⟩
  else if (trustedLatest admitted).any (fun pair => !fresh age pair.1.observed pair.1.expiresAt now) then ⟨.stale, now⟩
  else ⟨if (trustedLatest admitted).any (fun pair => !pair.1.active) then .revoked else .active,
    (trustedLatest admitted).foldl (fun horizon pair => min horizon (deadline age pair.1.observed pair.1.expiresAt)) cap⟩

theorem summaryFinish_independent {Subject : Type} [BEq Subject] (cap age now : Nat)
    (method : String) (rules : List Rule) (subject : Subject) (view : View)
    (rows : List (Statement Subject)) :
    summaryFinish cap now (independentAggregate cap age now method rules subject view rows) =
      listFinish cap age now (candidates rules subject view rows)
        (matching method (candidates rules subject view rows))
        (trusted method rules (matching method (candidates rules subject view rows))) := by
  by_cases noCandidates : candidates rules subject view rows = []
  · simp [independentAggregate, noCandidates, matching, trusted, summaryFinish, listFinish, collectLatest]
  · by_cases noMatches : matching method (candidates rules subject view rows) = []
    · simp [independentAggregate, noMatches, trusted, summaryFinish, listFinish, collectLatest, noCandidates]
    · by_cases noTrusted : trusted method rules (matching method (candidates rules subject view rows)) = []
      · simp [independentAggregate, noTrusted, summaryFinish, listFinish, collectLatest, noCandidates, noMatches]
      · simp only [independentAggregate, latest_map_summary]
        simp only [List.isEmpty_iff, noTrusted, ↓reduceIte]
        split_ifs <;> simp_all [summaryFinish, listFinish, List.isEmpty_iff]

/-- The accumulator and independent filter/max/tie-set specification agree
    for every finite input, every view and every policy, with no validity premise. -/
theorem evaluateScan_eq_evaluate {Subject : Type} [BEq Subject]
    (id : String) (policy : Policy) (observed cap : Nat)
    (rules : List Rule) (rows : List (Statement Subject))
    (subject : Subject) (view : View) (now : Nat) :
    evaluateScan id policy observed cap rules rows subject view now =
      evaluate id policy observed cap rules rows subject view now := by
  cases policy with
  | expiryOnly => rfl
  | required method age =>
    simp only [evaluateScan, evaluate]
    by_cases mismatch : (method != id) = true
    · simp only [mismatch, ↓reduceIte]
    · simp only [mismatch]
      by_cases stale : (decide (observed > now) || decide (cap < now)) = true
      · simp only [stale, ↓reduceIte]
      · simp only [stale]
        rw [scan_finish_independent, summaryFinish_independent]
        rfl

end Auths.StatusSelection.Algebra
