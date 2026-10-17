import Auths.Composition.ValidationProgress
open Auths.Composition.PlanModel Auths.Composition.ValidationModel Auths.Composition.Bounds
namespace Auths.Composition.ValidationShape
variable {R : Type} [DecidableEq R]

def NodeShape (plan : Plan R) : Prop :=
  ∀ limits level (state next : State R), checkPlan limits level plan state = .ok next →
    operatorsValid limits plan ∧ level + depth plan ≤ limits.depth + 1

def ChildrenShape (members : List (Plan R)) : Prop :=
  ∀ limits level (state next : State R), checkChildren limits level members state = .ok next →
    childrenValid limits members ∧ (members ≠ [] → level + memberDepth members ≤ limits.depth + 1)

theorem checker_shape (plan : Plan R) : NodeShape plan := by
  refine Plan.rec
    (motive_1 := fun plan => NodeShape plan)
    (motive_2 := fun members => ChildrenShape members)
    ?_ ?_ ?_ ?_ ?_ ?_ plan
  · intro reference limits level state next evaluates
    by_cases deep : level > limits.depth
    · simp [checkPlan, enter, deep, Bind.bind, Except.bind] at evaluates
    · simp [operatorsValid, depth]
      omega
  · intro members correct limits level state next evaluates
    by_cases deep : level > limits.depth
    · simp [checkPlan, enter, deep, Bind.bind, Except.bind] at evaluates
    · simp only [checkPlan, enter, deep, ite_false, Bind.bind, Except.bind] at evaluates
      split at evaluates
      · contradiction
      · rename_i nonempty
        split at evaluates
        · contradiction
        · rename_i width
          have nonempty : members ≠ [] := by simpa using nonempty
          obtain ⟨valid, depthBound⟩ := correct limits (level + 1)
            { state with maximumDepth := max state.maximumDepth level } next evaluates
          refine ⟨by simpa [operatorsValid] using And.intro nonempty (And.intro (Nat.le_of_not_gt width) valid), ?_⟩
          have := depthBound nonempty
          simp only [depth]
          omega
  · intro members correct limits level state next evaluates
    by_cases deep : level > limits.depth
    · simp [checkPlan, enter, deep, Bind.bind, Except.bind] at evaluates
    · simp only [checkPlan, enter, deep, ite_false, Bind.bind, Except.bind] at evaluates
      split at evaluates
      · contradiction
      · rename_i nonempty
        split at evaluates
        · contradiction
        · rename_i width
          have nonempty : members ≠ [] := by simpa using nonempty
          obtain ⟨valid, depthBound⟩ := correct limits (level + 1)
            { state with maximumDepth := max state.maximumDepth level } next evaluates
          refine ⟨by simpa [operatorsValid] using And.intro nonempty (And.intro (Nat.le_of_not_gt width) valid), ?_⟩
          have := depthBound nonempty
          simp only [depth]
          omega
  · intro required members correct limits level state next evaluates
    by_cases deep : level > limits.depth
    · simp [checkPlan, enter, deep, Bind.bind, Except.bind] at evaluates
    · simp only [checkPlan, enter, deep, ite_false, Bind.bind, Except.bind] at evaluates
      split at evaluates
      · contradiction
      · rename_i threshold
        have thresholdFacts : required ≠ 0 ∧ required ≤ members.length ∧ members ≠ [] := by
          simpa only [not_or, List.isEmpty_iff, Nat.not_lt] using threshold
        split at evaluates
        · contradiction
        · rename_i width
          obtain ⟨valid, depthBound⟩ := correct limits (level + 1)
            { state with maximumDepth := max state.maximumDepth level } next evaluates
          refine ⟨by simp only [operatorsValid]; exact ⟨by omega, thresholdFacts.2.1, Nat.le_of_not_gt width, valid⟩, ?_⟩
          have := depthBound thresholdFacts.2.2
          simp only [depth]
          omega
  · intro limits level state next evaluates
    simp [childrenValid]
  · intro head tail headCorrect tailCorrect limits level state next evaluates
    simp only [checkChildren, Bind.bind, Except.bind] at evaluates
    cases first : checkPlan limits level head state with
    | error reason => simp [first] at evaluates
    | ok middle =>
      simp only [first] at evaluates
      obtain ⟨headValid, headDepth⟩ := headCorrect limits level state middle first
      obtain ⟨tailValid, tailDepth⟩ := tailCorrect limits level middle next evaluates
      refine ⟨by simpa only [childrenValid] using And.intro headValid tailValid, ?_⟩
      intro nonempty
      by_cases empty : tail = []
      · simp only [empty, memberDepth, Nat.max_zero]
        exact headDepth
      · have := tailDepth empty
        simp only [memberDepth]
        omega

end Auths.Composition.ValidationShape
