import Auths.Composition.ValidationModel
open Auths.Composition.PlanModel Auths.Composition.ValidationModel
namespace Auths.Composition.ValidationCapacity
variable {R : Type} [DecidableEq R]

def NodeCapacity (plan : Plan R) : Prop :=
  ∀ limits depth (state next : State R), state.seen.card ≤ limits.leaves →
    checkPlan limits depth plan state = .ok next → next.seen.card ≤ limits.leaves

def ChildCapacity (members : List (Plan R)) : Prop :=
  ∀ limits depth (state next : State R), state.seen.card ≤ limits.leaves →
    checkChildren limits depth members state = .ok next → next.seen.card ≤ limits.leaves

theorem checker_preserves_capacity (plan : Plan R) : NodeCapacity plan := by
  refine Plan.rec
    (motive_1 := fun plan => NodeCapacity plan)
    (motive_2 := fun members => ChildCapacity members)
    ?_ ?_ ?_ ?_ ?_ ?_ plan
  · intro reference limits depth state next capacity evaluates
    by_cases deep : depth > limits.depth
    · simp [checkPlan, enter, deep, Bind.bind, Except.bind] at evaluates
    · simp only [checkPlan, enter, deep, ite_false, Bind.bind, Except.bind] at evaluates
      split at evaluates
      · contradiction
      · split at evaluates
        · contradiction
        · cases evaluates
          dsimp only at *
          omega
  · intro members correct limits depth state next capacity evaluates
    by_cases deep : depth > limits.depth
    · simp [checkPlan, enter, deep, Bind.bind, Except.bind] at evaluates
    · simp only [checkPlan, enter, deep, ite_false, Bind.bind, Except.bind] at evaluates
      split at evaluates
      · contradiction
      · split at evaluates
        · contradiction
        · exact correct limits (depth + 1) { state with maximumDepth := max state.maximumDepth depth } next capacity evaluates
  · intro members correct limits depth state next capacity evaluates
    by_cases deep : depth > limits.depth
    · simp [checkPlan, enter, deep, Bind.bind, Except.bind] at evaluates
    · simp only [checkPlan, enter, deep, ite_false, Bind.bind, Except.bind] at evaluates
      split at evaluates
      · contradiction
      · split at evaluates
        · contradiction
        · exact correct limits (depth + 1) { state with maximumDepth := max state.maximumDepth depth } next capacity evaluates
  · intro required members correct limits depth state next capacity evaluates
    by_cases deep : depth > limits.depth
    · simp [checkPlan, enter, deep, Bind.bind, Except.bind] at evaluates
    · simp only [checkPlan, enter, deep, ite_false, Bind.bind, Except.bind] at evaluates
      split at evaluates
      · contradiction
      · split at evaluates
        · contradiction
        · exact correct limits (depth + 1) { state with maximumDepth := max state.maximumDepth depth } next capacity evaluates
  · intro limits depth state next capacity evaluates
    simp only [checkChildren, Except.ok.injEq] at evaluates
    cases evaluates
    exact capacity
  · intro head tail headCorrect tailCorrect limits depth state next capacity evaluates
    simp only [checkChildren, Bind.bind, Except.bind] at evaluates
    cases first : checkPlan limits depth head state with
    | error reason => simp [first] at evaluates
    | ok intermediate =>
      have middleCapacity := headCorrect limits depth state intermediate capacity first
      simp only [first] at evaluates
      exact tailCorrect limits depth intermediate next middleCapacity evaluates

end Auths.Composition.ValidationCapacity
