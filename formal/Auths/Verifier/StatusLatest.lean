import Auths.Verifier.StatusAlgebra
namespace Auths.StatusSelection.Algebra

def sequenceMaximum (rows : List Latest) : Nat :=
  rows.foldr (fun row maximum => max row.sequence maximum) 0

@[simp] theorem sequenceMaximum_nil : sequenceMaximum [] = 0 := rfl
@[simp] theorem sequenceMaximum_cons (head : Latest) (rest : List Latest) :
    sequenceMaximum (head :: rest) = max head.sequence (sequenceMaximum rest) := rfl

theorem sequenceMaximum_upper (rows : List Latest) (row : Latest) (member : row ∈ rows) :
    row.sequence ≤ sequenceMaximum rows := by
  induction rows with
  | nil => simp at member
  | cons head rest ih =>
    simp only [List.mem_cons] at member
    simp only [sequenceMaximum_cons]
    rcases member with equal | member
    · subst row; exact Nat.le_max_left _ _
    · exact Nat.le_trans (ih member) (Nat.le_max_right _ _)

theorem sequenceMaximum_attained (rows : List Latest) (nonempty : rows ≠ []) :
    ∃ row ∈ rows, row.sequence = sequenceMaximum rows := by
  induction rows with
  | nil => contradiction
  | cons head rest ih =>
    by_cases empty : rest = []
    · subst rest; exact ⟨head, by simp, by simp⟩
    · obtain ⟨row, member, equal⟩ := ih empty
      by_cases larger : head.sequence ≤ sequenceMaximum rest
      · exact ⟨row, by simp [member], by simp [max_eq_right larger, equal]⟩
      · exact ⟨head, by simp, by simp [max_eq_left (by omega : sequenceMaximum rest ≤ head.sequence)]⟩

def atSequence (rows : List Latest) (sequence : Nat) : List Latest :=
  rows.filter (fun row => row.sequence == sequence)

def listSummary (cap : Nat) (rows : List Latest) : Option Latest :=
  if rows.isEmpty then none else
    let maximum := sequenceMaximum rows
    let latest := atSequence rows maximum
    some ⟨maximum, latest.any Latest.stale, latest.any Latest.revoked,
      latest.foldr (fun row horizon => min row.through horizon) cap⟩

def collectLatest : List Latest → Option Latest
  | [] => none
  | row :: rest => mergeLatest (some row) (collectLatest rest)

theorem atSequence_above (rows : List Latest) (sequence : Nat)
    (above : sequenceMaximum rows < sequence) : atSequence rows sequence = [] := by
  apply List.filter_eq_nil_iff.mpr
  intro row member
  have upper := sequenceMaximum_upper rows row member
  simp only [beq_iff_eq]
  omega

theorem collectLatest_exact (cap : Nat) (rows : List Latest)
    (bounded : ∀ row ∈ rows, row.through ≤ cap) : collectLatest rows = listSummary cap rows := by
  induction rows with
  | nil => rfl
  | cons head rest ih =>
    have headBound := bounded head (by simp)
    have restBound : ∀ row ∈ rest, row.through ≤ cap := by
      intro row member; exact bounded row (by simp [member])
    rw [collectLatest, ih restBound]
    by_cases empty : rest = []
    · subst rest
      simp [listSummary, atSequence, mergeLatest,
        Nat.min_eq_left headBound]
    · have notEmpty : rest.isEmpty = false := by simpa using empty
      have attained := sequenceMaximum_attained rest empty
      by_cases lower : head.sequence < sequenceMaximum rest
      · have maximum : max head.sequence (sequenceMaximum rest) = sequenceMaximum rest := max_eq_right (by omega)
        have unequal : (head.sequence == sequenceMaximum rest) = false := by simp; omega
        simp [listSummary, notEmpty, mergeLatest, lower, atSequence,
          maximum, unequal]
      · by_cases higher : sequenceMaximum rest < head.sequence
        · have maximum : max head.sequence (sequenceMaximum rest) = head.sequence := max_eq_left (by omega)
          have above := atSequence_above rest head.sequence higher
          simp only [listSummary, notEmpty, Bool.false_eq_true, ↓reduceIte,
            List.isEmpty_cons, sequenceMaximum_cons]
          change mergeLatest (some head) (some _) = some _
          simp only [mergeLatest, lower, higher, ↓reduceIte, maximum]
          simp only [atSequence, List.filter_cons, beq_self_eq_true, ↓reduceIte] at above ⊢
          rw [above]
          simp [Nat.min_eq_left headBound]
        · have equal : head.sequence = sequenceMaximum rest := by omega
          simp [listSummary, notEmpty, mergeLatest,
            atSequence, equal]

end Auths.StatusSelection.Algebra
