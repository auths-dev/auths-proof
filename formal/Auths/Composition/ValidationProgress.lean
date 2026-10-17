import Auths.Composition.ValidationCapacity
open Auths.Composition.PlanModel Auths.Composition.ValidationModel Auths.Composition.Work
namespace Auths.Composition.ValidationProgress
variable {R : Type} [DecidableEq R]

/-- No reference is reused, and the result is exactly the original set extended
    by the plan's leaves. This relation does not mention the checker. -/
def Progress (before : Finset R) (references : List R) (after : Finset R) : Prop :=
  references.Nodup ∧ (∀ item ∈ references, item ∉ before) ∧ after = before ∪ references.toFinset

theorem progress_nil (seen : Finset R) : Progress seen [] seen := by simp [Progress]

theorem progress_one (seen : Finset R) (reference : R) (fresh : reference ∉ seen) :
    Progress seen [reference] (insert reference seen) := by
  refine ⟨by simp, by simpa using fresh, ?_⟩
  ext item
  simp

theorem progress_append (before middle after : Finset R) (left right : List R)
    (first : Progress before left middle) (second : Progress middle right after) :
    Progress before (left ++ right) after := by
  obtain ⟨leftUnique, leftFresh, middleEq⟩ := first
  obtain ⟨rightUnique, rightFresh, afterEq⟩ := second
  have cross : List.Disjoint left right := by
    rw [List.disjoint_left]
    intro item inLeft inRight
    exact rightFresh item inRight (by simp [middleEq, inLeft])
  refine ⟨List.nodup_append.mpr ⟨leftUnique, rightUnique, by
    intro a inLeft b inRight same
    subst b
    exact (List.disjoint_left.mp cross) inLeft inRight⟩, ?_, ?_⟩
  · intro item member
    rcases List.mem_append.mp member with inLeft | inRight
    · exact leftFresh item inLeft
    · intro old
      exact rightFresh item inRight (by simp [middleEq, old])
  · simp [afterEq, middleEq, List.toFinset_append, Finset.union_assoc]

theorem progress_card (before after : Finset R) (references : List R)
    (meaning : Progress before references after) : after.card = before.card + references.length := by
  obtain ⟨unique, fresh, same⟩ := meaning
  have disjoint : Disjoint before references.toFinset := by
    rw [Finset.disjoint_left]
    intro item old new
    exact fresh item (List.mem_toFinset.mp new) old
  rw [same, Finset.card_union_of_disjoint disjoint, List.toFinset_card_of_nodup unique]

def NodeProgress (plan : Plan R) : Prop :=
  ∀ limits depth (state next : State R), checkPlan limits depth plan state = .ok next →
    Progress state.seen (leaves plan) next.seen

def ChildrenProgress (members : List (Plan R)) : Prop :=
  ∀ limits depth (state next : State R), checkChildren limits depth members state = .ok next →
    Progress state.seen (memberLeaves members) next.seen

theorem checker_progress (plan : Plan R) : NodeProgress plan := by
  refine Plan.rec
    (motive_1 := fun plan => NodeProgress plan)
    (motive_2 := fun members => ChildrenProgress members)
    ?_ ?_ ?_ ?_ ?_ ?_ plan
  · intro reference limits depth state next evaluates
    by_cases deep : depth > limits.depth
    · simp [checkPlan, enter, deep, Bind.bind, Except.bind] at evaluates
    · simp only [checkPlan, enter, deep, ite_false, Bind.bind, Except.bind] at evaluates
      split at evaluates
      · contradiction
      · rename_i fresh
        split at evaluates
        · contradiction
        · cases evaluates
          simpa only [leaves] using progress_one state.seen reference fresh
  · intro members correct limits depth state next evaluates
    by_cases deep : depth > limits.depth
    · simp [checkPlan, enter, deep, Bind.bind, Except.bind] at evaluates
    · simp only [checkPlan, enter, deep, ite_false, Bind.bind, Except.bind] at evaluates
      split at evaluates
      · contradiction
      · split at evaluates
        · contradiction
        · simpa only [leaves] using correct limits (depth + 1) { state with maximumDepth := max state.maximumDepth depth } next evaluates
  · intro members correct limits depth state next evaluates
    by_cases deep : depth > limits.depth
    · simp [checkPlan, enter, deep, Bind.bind, Except.bind] at evaluates
    · simp only [checkPlan, enter, deep, ite_false, Bind.bind, Except.bind] at evaluates
      split at evaluates
      · contradiction
      · split at evaluates
        · contradiction
        · simpa only [leaves] using correct limits (depth + 1) { state with maximumDepth := max state.maximumDepth depth } next evaluates
  · intro required members correct limits depth state next evaluates
    by_cases deep : depth > limits.depth
    · simp [checkPlan, enter, deep, Bind.bind, Except.bind] at evaluates
    · simp only [checkPlan, enter, deep, ite_false, Bind.bind, Except.bind] at evaluates
      split at evaluates
      · contradiction
      · split at evaluates
        · contradiction
        · simpa only [leaves] using correct limits (depth + 1) { state with maximumDepth := max state.maximumDepth depth } next evaluates
  · intro limits depth state next evaluates
    simp only [checkChildren, Except.ok.injEq] at evaluates
    cases evaluates
    simpa only [memberLeaves] using progress_nil state.seen
  · intro head tail headCorrect tailCorrect limits depth state next evaluates
    simp only [checkChildren, Bind.bind, Except.bind] at evaluates
    cases first : checkPlan limits depth head state with
    | error reason => simp [first] at evaluates
    | ok middle =>
      simp only [first] at evaluates
      simpa only [memberLeaves] using progress_append state.seen middle.seen next.seen (leaves head) (memberLeaves tail)
        (headCorrect limits depth state middle first) (tailCorrect limits depth middle next evaluates)

end Auths.Composition.ValidationProgress
