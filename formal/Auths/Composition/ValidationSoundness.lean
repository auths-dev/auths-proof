import Auths.Composition.ValidationComplete
open Auths.Composition.PlanModel Auths.Composition.ValidationModel Auths.Composition.Bounds
open Auths.Composition.Work Auths.Composition.ValidationProgress Auths.Composition.ValidationShape
namespace Auths.Composition.ValidationSoundness
variable {R : Type} [DecidableEq R]

theorem accepted_is_valid (limits : Limits) (plan : Plan R) (next : State R)
    (accepted : checkPlan limits 1 plan rootState = .ok next) : Valid limits plan := by
  obtain ⟨operators, depthBound⟩ := checker_shape plan limits 1 rootState next accepted
  have progress := checker_progress plan limits 1 rootState next accepted
  have capacity := Auths.Composition.ValidationCapacity.checker_preserves_capacity plan limits 1 rootState next
    (by simp [rootState]) accepted
  have card := progress_card (rootState : State R).seen next.seen (leaves plan) progress
  refine ⟨operators, by omega, progress.1, ?_⟩
  simp only [rootState, Finset.card_empty, Nat.zero_add] at card
  omega

theorem accepted_iff_valid (limits : Limits) (plan : Plan R) :
    (∃ next, checkPlan limits 1 plan rootState = .ok next) ↔ Valid limits plan := by
  constructor
  · rintro ⟨next, accepted⟩
    exact accepted_is_valid limits plan next accepted
  · exact Auths.Composition.ValidationComplete.valid_is_accepted limits plan

omit [DecidableEq R] in
theorem operators_are_proper (limits : Limits) (plan : Plan R) : operatorsValid limits plan → proper plan := by
  refine Plan.rec
    (motive_1 := fun plan => operatorsValid limits plan → proper plan)
    (motive_2 := fun members => childrenValid limits members → membersProper members)
    ?_ ?_ ?_ ?_ ?_ ?_ plan
  · simp [operatorsValid, proper]
  · intro members correct valid
    simp only [operatorsValid] at valid
    simpa only [proper] using And.intro valid.1 (correct valid.2.2)
  · intro members correct valid
    simp only [operatorsValid] at valid
    simpa only [proper] using And.intro valid.1 (correct valid.2.2)
  · intro required members correct valid
    simp only [operatorsValid] at valid
    have nonempty : members ≠ [] := by intro empty; simp [empty] at valid; omega
    simpa only [proper] using And.intro nonempty (correct valid.2.2.2)
  · simp [childrenValid, membersProper]
  · intro head tail headCorrect tailCorrect valid
    simp only [childrenValid] at valid
    simpa only [membersProper] using And.intro (headCorrect valid.1) (tailCorrect valid.2)

omit [DecidableEq R] in
theorem valid_has_bounded_events (limits : Limits) (plan : Plan R) (valid : Valid limits plan)
    (depthBound : limits.depth ≤ 16) (leavesBound : limits.leaves ≤ 128) : nodes plan ≤ 2048 := by
  exact bounded_events plan (operators_are_proper limits plan valid.1)
    (by have := valid.2.1; omega) (by have := valid.2.2.2; omega)

end Auths.Composition.ValidationSoundness
