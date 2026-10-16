import Auths.Composition.ValidationShape
open Auths.Composition.PlanModel Auths.Composition.ValidationModel Auths.Composition.Bounds
open Auths.Composition.Work Auths.Composition.ValidationProgress
namespace Auths.Composition.ValidationComplete
variable {R : Type} [DecidableEq R]
set_option maxHeartbeats 2000000

def Fits (limits : Limits) (level : Nat) (plan : Plan R) (state : State R) : Prop :=
  operatorsValid limits plan ∧ level + depth plan ≤ limits.depth + 1 ∧
    (leaves plan).Nodup ∧ (∀ item ∈ leaves plan, item ∉ state.seen) ∧
    state.seen.card + (leaves plan).length ≤ limits.leaves

def ChildrenFit (limits : Limits) (level : Nat) (members : List (Plan R)) (state : State R) : Prop :=
  childrenValid limits members ∧ (members ≠ [] → level + memberDepth members ≤ limits.depth + 1) ∧
    (memberLeaves members).Nodup ∧ (∀ item ∈ memberLeaves members, item ∉ state.seen) ∧
    state.seen.card + (memberLeaves members).length ≤ limits.leaves

def NodeComplete (plan : Plan R) : Prop :=
  ∀ limits level (state : State R), Fits limits level plan state →
    ∃ next, checkPlan limits level plan state = .ok next

def ChildrenComplete (members : List (Plan R)) : Prop :=
  ∀ limits level (state : State R), ChildrenFit limits level members state →
    ∃ next, checkChildren limits level members state = .ok next

theorem checker_complete (plan : Plan R) : NodeComplete plan := by
  refine Plan.rec
    (motive_1 := fun plan => NodeComplete plan)
    (motive_2 := fun members => ChildrenComplete members)
    ?_ ?_ ?_ ?_ ?_ ?_ plan
  · intro reference limits level state fits
    obtain ⟨valid, depthBound, unique, fresh, capacity⟩ := fits
    simp only [depth, leaves, List.length_singleton] at depthBound fresh capacity
    have within : ¬ level > limits.depth := by omega
    have absent : reference ∉ state.seen := fresh reference (by simp)
    exact ⟨{ seen := insert reference state.seen, maximumDepth := max state.maximumDepth level },
      by simp [checkPlan, enter, within, Bind.bind, Except.bind, absent]; omega⟩
  · intro members correct limits level state fits
    obtain ⟨valid, depthBound, unique, fresh, capacity⟩ := fits
    simp only [operatorsValid] at valid
    obtain ⟨nonempty, width, children⟩ := valid
    simp only [depth] at depthBound
    have within : ¬ level > limits.depth := by omega
    have childFits : ChildrenFit limits (level + 1) members
        { state with maximumDepth := max state.maximumDepth level } := by
      exact ⟨children, by intro _; omega, by simpa only [leaves] using unique,
        by simpa only [leaves] using fresh, by simpa only [leaves] using capacity⟩
    obtain ⟨next, executes⟩ := correct limits (level + 1) _ childFits
    refine ⟨next, ?_⟩
    simpa [checkPlan, enter, within, Bind.bind, Except.bind, nonempty, Nat.not_lt.mpr width] using executes
  · intro members correct limits level state fits
    obtain ⟨valid, depthBound, unique, fresh, capacity⟩ := fits
    simp only [operatorsValid] at valid
    obtain ⟨nonempty, width, children⟩ := valid
    simp only [depth] at depthBound
    have within : ¬ level > limits.depth := by omega
    have childFits : ChildrenFit limits (level + 1) members
        { state with maximumDepth := max state.maximumDepth level } := by
      exact ⟨children, by intro _; omega, by simpa only [leaves] using unique,
        by simpa only [leaves] using fresh, by simpa only [leaves] using capacity⟩
    obtain ⟨next, executes⟩ := correct limits (level + 1) _ childFits
    refine ⟨next, ?_⟩
    simpa [checkPlan, enter, within, Bind.bind, Except.bind, nonempty, Nat.not_lt.mpr width] using executes
  · intro required members correct limits level state fits
    obtain ⟨valid, depthBound, unique, fresh, capacity⟩ := fits
    simp only [operatorsValid] at valid
    obtain ⟨positive, feasible, width, children⟩ := valid
    have nonempty : members ≠ [] := by intro empty; simp [empty] at feasible; omega
    simp only [depth] at depthBound
    have within : ¬ level > limits.depth := by omega
    have childFits : ChildrenFit limits (level + 1) members
        { state with maximumDepth := max state.maximumDepth level } := by
      exact ⟨children, by intro _; omega, by simpa only [leaves] using unique,
        by simpa only [leaves] using fresh, by simpa only [leaves] using capacity⟩
    obtain ⟨next, executes⟩ := correct limits (level + 1) _ childFits
    refine ⟨next, ?_⟩
    simpa [checkPlan, enter, within, Bind.bind, Except.bind, nonempty,
      Nat.ne_of_gt positive, Nat.not_lt.mpr feasible, Nat.not_lt.mpr width] using executes
  · intro limits level state fits
    exact ⟨state, by simp [checkChildren]⟩
  · intro head tail headCorrect tailCorrect limits level state fits
    obtain ⟨valid, depthBound, unique, fresh, capacity⟩ := fits
    simp only [childrenValid] at valid
    simp only [memberLeaves, List.length_append] at unique fresh capacity
    obtain ⟨headUnique, tailUnique, cross⟩ := List.nodup_append.mp unique
    have wholeDepth := depthBound (by simp)
    simp only [memberDepth] at wholeDepth
    have headFits : Fits limits level head state := by
      refine ⟨valid.1, by omega, headUnique, ?_, by omega⟩
      intro item member
      exact fresh item (List.mem_append_left _ member)
    obtain ⟨middle, headRuns⟩ := headCorrect limits level state headFits
    have progress := checker_progress head limits level state middle headRuns
    have middleCard := progress_card state.seen middle.seen (leaves head) progress
    have tailFits : ChildrenFit limits level tail middle := by
      refine ⟨valid.2, by intro _; omega, tailUnique, ?_, by omega⟩
      intro item member old
      rw [progress.2.2] at old
      rcases Finset.mem_union.mp old with original | inHead
      · exact fresh item (List.mem_append_right _ member) original
      · exact cross item (List.mem_toFinset.mp inHead) item member rfl
    obtain ⟨next, tailRuns⟩ := tailCorrect limits level middle tailFits
    exact ⟨next, by simp [checkChildren, Bind.bind, Except.bind, headRuns, tailRuns]⟩

theorem valid_is_accepted (limits : Limits) (plan : Plan R) (valid : Valid limits plan) :
    ∃ next, checkPlan limits 1 plan rootState = .ok next := by
  apply checker_complete plan limits 1 rootState
  obtain ⟨operators, depthBound, unique, size⟩ := valid
  exact ⟨operators, by omega, unique, by simp [rootState], by simpa [rootState] using size⟩

end Auths.Composition.ValidationComplete
