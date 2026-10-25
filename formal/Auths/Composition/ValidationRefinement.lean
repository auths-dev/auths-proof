import Auths.Composition.ValidationLeaves
import Auths.Composition.ValidationCapacity
import Auths.Composition.IteratorFacts
open Aeneas Aeneas.Std Result Aeneas.Std.WP
open auths_composition Auths.Composition.PlanModel Auths.Composition.ValidationModel
open Auths.Composition.ValidationLeaves Auths.Composition.SetModel
namespace Auths.Composition.ValidationRefinement
set_option maxHeartbeats 2000000

abbrev NativeSet := alloc.collections.btree.set.BTreeSet auths_model.ProofRef Global

def LimitsBounded (limits : auths_model.VerifierLimits) : Prop :=
  limits.plan_leaves.val ≤ 128 ∧ limits.plan_depth.val ≤ 16 ∧ limits.plan_branching.val ≤ 128

def GoodSet (limits : auths_model.VerifierLimits) (refs : NativeSet) : Prop :=
  refs.values.Pairwise Before ∧ refs.values.length ≤ limits.plan_leaves.val

theorem room_for_leaf (limits : auths_model.VerifierLimits) (bounded : LimitsBounded limits)
    (refs : NativeSet) (good : GoodSet limits refs) : refs.values.length < Usize.max := by
  have width : 128 < Usize.max := by scalar_tac
  obtain ⟨leaves, depth, children⟩ := bounded
  obtain ⟨ordered, size⟩ := good
  omega

theorem card_view (refs : NativeSet) (maximum : Std.Usize) (ordered : refs.values.Pairwise Before) :
    (viewState refs maximum).seen.card = refs.values.length :=
  List.toFinset_card_of_nodup (ordered_nodup refs.values ordered)

@[step] theorem child_depth_exact (depth : Std.Usize) (bounded : depth.val ≤ 16) :
    depth + 1#usize ⦃ next => next.val = depth.val + 1 ⦄ := by
  step as ⟨next, exactValue⟩
  exact exactValue

/-- Exact checking result under explicit protocol-sized deployment limits. -/
def NodeCorrect (plan : auths_model.AuthorizationPlan) : Prop :=
  ∀ (limits : auths_model.VerifierLimits), LimitsBounded limits →
  ∀ (depth maximum : Std.Usize) (refs : NativeSet), depth.val ≤ 17 → GoodSet limits refs →
    auths_model.AuthorizationPlan.validate.walk plan depth limits refs maximum
      ⦃ result => Corresponds
        (checkPlan (sourceLimits limits) depth.val (viewPlan plan) (viewState refs maximum)) result ⦄

def ElementsCorrect {n : Nat}
    (elements : auths_composition.alloc.vec.SizedList auths_model.AuthorizationPlan n) : Prop :=
  ∀ (limits : auths_model.VerifierLimits), LimitsBounded limits →
  ∀ (depth maximum : Std.Usize) (refs : NativeSet), depth.val ≤ 16 → GoodSet limits refs →
  ∀ (iterator : core.slice.iter.Iter auths_model.AuthorizationPlan),
    iterator.slice.val.drop iterator.i = elements.toList →
    auths_model.AuthorizationPlan.validate.walk_members_loop iterator depth limits refs maximum
      ⦃ result => Corresponds
        (checkChildren (sourceLimits limits) (depth.val + 1) (viewElements elements)
          (viewState refs maximum)) result ⦄

theorem nil_correct : ElementsCorrect
    (auths_composition.alloc.vec.SizedList.nil :
      auths_composition.alloc.vec.SizedList auths_model.AuthorizationPlan 0) := by
  intro limits bounded depth maximum refs depthBound good iterator remaining
  rw [auths_model.AuthorizationPlan.validate.walk_members_loop.eq_def,
    Auths.Composition.IteratorFacts.next_nil iterator remaining]
  simp only [bind_tc_ok, viewElements, checkChildren, Corresponds]
  exact ⟨rfl, good.1, rfl⟩

theorem cons_correct {n : Nat} (head : auths_model.AuthorizationPlan)
    (tail : auths_composition.alloc.vec.SizedList auths_model.AuthorizationPlan n)
    (headCorrect : NodeCorrect head) (tailCorrect : ElementsCorrect tail) :
    ElementsCorrect (.cons head tail) := by
  intro limits bounded depth maximum refs depthBound good iterator remaining
  simp only [auths_composition.alloc.vec.SizedList.toList] at remaining
  obtain ⟨nextIterator, nextEq, remainingTail⟩ :=
    Auths.Composition.IteratorFacts.next_cons iterator head tail.toList remaining
  rw [auths_model.AuthorizationPlan.validate.walk_members_loop.eq_def, nextEq]
  simp only [bind_tc_ok]
  step as ⟨childDepth, childDepthEq⟩
  have headRuns := headCorrect limits bounded childDepth maximum refs (by omega) good
  rw [childDepthEq] at headRuns
  apply spec_bind headRuns
  intro result meaning
  rcases result with ⟨outcome, nextRefs, nextMaximum⟩
  cases checked : checkPlan (sourceLimits limits) (depth.val + 1) (viewPlan head) (viewState refs maximum) with
  | error reason =>
    cases reason with
    | tooLarge =>
      simp only [Corresponds, checked] at meaning
      rw [meaning]
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame.from, Corresponds, viewElements, checkChildren,
        Bind.bind, Except.bind, checked]
    | invalidOperator =>
      simp only [Corresponds, checked] at meaning
      rw [meaning]
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame.from, Corresponds, viewElements, checkChildren,
        Bind.bind, Except.bind, checked]
  | ok nextState =>
    simp only [Corresponds, checked] at meaning
    obtain ⟨nativeOk, sorted, stateEq⟩ := meaning
    rw [nativeOk]
    simp only [core.result.Result.Insts.CoreOpsTry.branch]
    have oldCapacity : (viewState refs maximum).seen.card ≤ (sourceLimits limits).leaves := by
      rw [card_view refs maximum good.1]
      exact good.2
    have nextCapacity := Auths.Composition.ValidationCapacity.checker_preserves_capacity (viewPlan head)
      (sourceLimits limits) (depth.val + 1) (viewState refs maximum) nextState oldCapacity checked
    have actualCard := congrArg (fun value : State auths_model.ProofRef => value.seen.card) stateEq
    rw [card_view nextRefs nextMaximum sorted] at actualCard
    have newGood : GoodSet limits nextRefs := ⟨sorted, by simpa only [actualCard, sourceLimits] using nextCapacity⟩
    have continuation := tailCorrect limits bounded depth nextMaximum nextRefs depthBound newGood
      nextIterator remainingTail
    apply spec_mono continuation
    intro actual conclusion
    simpa only [viewElements, checkChildren, Bind.bind, Except.bind, checked, stateEq] using conclusion

@[step] theorem members_exact
    (members : auths_composition.alloc.vec.Vec auths_model.AuthorizationPlan)
    (correct : ElementsCorrect members.elements)
    (limits : auths_model.VerifierLimits) (bounded : LimitsBounded limits)
    (depth maximum : Std.Usize) (refs : NativeSet) (depthBound : depth.val ≤ 16)
    (good : GoodSet limits refs) :
    auths_model.AuthorizationPlan.validate.walk_members members.deref depth limits refs maximum
      ⦃ result => Corresponds
        (checkChildren (sourceLimits limits) (depth.val + 1) (viewMembers members)
          (viewState refs maximum)) result ⦄ := by
  rw [auths_model.AuthorizationPlan.validate.walk_members.eq_def]
  simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter,
    bind_tc_ok]
  have viewEq : viewMembers members = viewElements members.elements := by cases members; simp [viewMembers]
  rw [viewEq]
  apply correct limits bounded depth maximum refs depthBound good
  simp only [List.drop_zero, auths_composition.alloc.vec.Vec.deref_exact]


theorem view_members_empty (members : auths_composition.alloc.vec.Vec auths_model.AuthorizationPlan) :
    members.elements.toList.isEmpty = (viewMembers members).isEmpty := by
  have lengthEq := Auths.Composition.Traversal.view_members_length members
  have sourceLength : members.elements.toList.length = members.size := by
    exact members.elements.length
  apply Bool.eq_iff_iff.mpr
  simp only [List.isEmpty_iff_length_eq_zero]
  omega

theorem members_len (members : auths_composition.alloc.vec.Vec auths_model.AuthorizationPlan) :
    (auths_composition.alloc.vec.Vec.len members).val = (viewMembers members).length := by
  rw [Auths.Composition.Traversal.view_members_length]
  simp [auths_composition.alloc.vec.Vec.len, auths_composition.alloc.vec.Vec.toBase, auths_composition.alloc.vec.SizedList.length]

theorem all_node_exact (members : auths_composition.alloc.vec.Vec auths_model.AuthorizationPlan)
    (correct : ElementsCorrect members.elements) : NodeCorrect (.mk (.AllOf members)) := by
  intro limits bounded depth maximum refs depthBound good
  rw [auths_model.AuthorizationPlan.validate.walk.eq_def]
  simp only [auths_model.AuthorizationPlan._0]
  by_cases tooDeep : depth > limits.plan_depth
  · have excessive : depth.val > limits.plan_depth.val := by
      simpa only [UScalar.lt_equiv] using tooDeep
    simp [tooDeep, Corresponds, checkPlan, enter, Except.bind, Bind.bind, sourceLimits,
      viewPlan, viewNode, excessive]
  · have within : ¬ depth.val > limits.plan_depth.val := by
      simpa only [UScalar.lt_equiv] using tooDeep
    simp only [tooDeep, ite_false]
    step as ⟨updatedMaximum, maximumEq⟩
    simp only [auths_composition.alloc.vec.Vec.is_empty, bind_tc_ok, view_members_empty]
    by_cases empty : (viewMembers members).isEmpty
    · simp [empty, Corresponds, checkPlan, enter, Except.bind, Bind.bind, sourceLimits,
        viewPlan, viewNode, within]
    · simp only [empty, Bool.false_eq_true, ite_false]
      by_cases tooWide : auths_composition.alloc.vec.Vec.len members > limits.plan_branching
      · have excessive : (viewMembers members).length > limits.plan_branching.val := by
          simpa only [UScalar.lt_equiv, members_len] using tooWide
        simp [tooWide, Corresponds, checkPlan, enter, Except.bind, Bind.bind, sourceLimits,
          viewPlan, viewNode, within, empty, excessive]
      · have width : ¬ (viewMembers members).length > limits.plan_branching.val := by
          simpa only [UScalar.lt_equiv, members_len] using tooWide
        simp only [tooWide, ite_false]
        have parentBound : depth.val ≤ 16 := by have := bounded.2.1; omega
        have run := members_exact members correct limits bounded depth updatedMaximum refs parentBound good
        apply spec_bind run
        intro actual meaning
        rcases actual with ⟨outcome, nextRefs, nextMaximum⟩
        cases outcome <;> simpa [core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
          core.convert.FromSame.from, Corresponds, checkPlan, enter, Except.bind, Bind.bind,
          sourceLimits, viewPlan, viewNode, within, empty, width, viewState, maximumEq] using meaning


theorem any_node_exact (members : auths_composition.alloc.vec.Vec auths_model.AuthorizationPlan)
    (correct : ElementsCorrect members.elements) : NodeCorrect (.mk (.AnyOf members)) := by
  intro limits bounded depth maximum refs depthBound good
  have nativeEq : auths_model.AuthorizationPlan.validate.walk (.mk (.AnyOf members)) depth limits refs maximum =
      auths_model.AuthorizationPlan.validate.walk (.mk (.AllOf members)) depth limits refs maximum := by
    rw [auths_model.AuthorizationPlan.validate.walk.eq_def,
      auths_model.AuthorizationPlan.validate.walk.eq_def]
    rfl
  rw [nativeEq]
  simpa only [viewPlan, viewNode, checkPlan] using
    all_node_exact members correct limits bounded depth maximum refs depthBound good


theorem threshold_node_exact (required : Std.U16)
    (members : auths_composition.alloc.vec.Vec auths_model.AuthorizationPlan)
    (correct : ElementsCorrect members.elements) : NodeCorrect (.mk (.KOfN required members)) := by
  intro limits bounded depth maximum refs depthBound good
  rw [auths_model.AuthorizationPlan.validate.walk.eq_def]
  simp only [auths_model.AuthorizationPlan._0]
  by_cases tooDeep : depth > limits.plan_depth
  · have excessive : depth.val > limits.plan_depth.val := by
      simpa only [UScalar.lt_equiv] using tooDeep
    simp [tooDeep, Corresponds, checkPlan, enter, Except.bind, Bind.bind, sourceLimits,
      viewPlan, viewNode, excessive]
  · have within : ¬ depth.val > limits.plan_depth.val := by
      simpa only [UScalar.lt_equiv] using tooDeep
    simp only [tooDeep, ite_false]
    step as ⟨updatedMaximum, maximumEq⟩
    by_cases zero : required = 0#u16
    · have zeroNat : required.val = 0 := by rw [zero]; rfl
      simp [zero, Corresponds, checkPlan, enter, Except.bind, Bind.bind, sourceLimits,
        viewPlan, viewNode, within]
    · have nonzero : required.val ≠ 0 := by exact fun eq => zero (UScalar.eq_of_val_eq eq)
      simp only [zero, ite_false]
      simp only [lift, bind_tc_ok]
      have convertedEq : (core.convert.num.FromUsizeU16.from required).val = required.val := core.convert.num.FromUsizeU16.from_val_eq required
      by_cases impossible : core.convert.num.FromUsizeU16.from required > auths_composition.alloc.vec.Vec.len members
      · have excessive : required.val > (viewMembers members).length := by
          simpa only [UScalar.lt_equiv, members_len, convertedEq] using impossible
        simp [impossible, Corresponds, checkPlan, enter, Except.bind, Bind.bind, sourceLimits,
          viewPlan, viewNode, within, excessive]
      · have feasible : ¬ required.val > (viewMembers members).length := by
          simpa only [UScalar.lt_equiv, members_len, convertedEq] using impossible
        simp only [impossible, ite_false, auths_composition.alloc.vec.Vec.is_empty,
          bind_tc_ok, view_members_empty]
        by_cases empty : (viewMembers members).isEmpty
        · simp [empty, Corresponds, checkPlan, enter, Except.bind, Bind.bind, sourceLimits,
            viewPlan, viewNode, within]
        · simp only [empty, Bool.false_eq_true, ite_false]
          by_cases tooWide : auths_composition.alloc.vec.Vec.len members > limits.plan_branching
          · have excessive : (viewMembers members).length > limits.plan_branching.val := by
              simpa only [UScalar.lt_equiv, members_len] using tooWide
            simp [tooWide, Corresponds, checkPlan, enter, Except.bind, Bind.bind, sourceLimits,
              viewPlan, viewNode, within, empty, excessive, nonzero, feasible]
          · have width : ¬ (viewMembers members).length > limits.plan_branching.val := by
              simpa only [UScalar.lt_equiv, members_len] using tooWide
            simp only [tooWide, ite_false]
            have parentBound : depth.val ≤ 16 := by have := bounded.2.1; omega
            have run := members_exact members correct limits bounded depth updatedMaximum refs parentBound good
            apply spec_bind run
            intro actual meaning
            rcases actual with ⟨outcome, nextRefs, nextMaximum⟩
            cases outcome <;> simpa [core.result.Result.Insts.CoreOpsTry.branch,
              core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
              core.convert.FromSame.from, Corresponds, checkPlan, enter, Except.bind, Bind.bind,
              sourceLimits, viewPlan, viewNode, within, empty, width, nonzero, feasible,
              viewState, maximumEq] using meaning


theorem all_nodes_correct (plan : auths_model.AuthorizationPlan) : NodeCorrect plan := by
  refine auths_model.AuthorizationPlan.rec
    (motive_1 := fun plan => NodeCorrect plan)
    (motive_2 := fun node => NodeCorrect (.mk node))
    (motive_3 := fun members => ElementsCorrect members.elements)
    (motive_4 := fun _ elements => ElementsCorrect elements)
    ?_ ?_ ?_ ?_ ?_ ?_ ?_ ?_ plan
  · intro node correct
    exact correct
  · intro reference limits bounded depth maximum refs depthBound good
    simpa only [viewPlan, viewNode] using
      proof_leaf_exact reference depth maximum limits refs good.1 (room_for_leaf limits bounded refs good)
  · intro members correct
    exact all_node_exact members correct
  · intro members correct
    exact any_node_exact members correct
  · intro required members correct
    exact threshold_node_exact required members correct
  · intro size elements bound correct
    exact correct
  · exact nil_correct
  · intro size head tail headCorrect tailCorrect
    exact cons_correct head tail headCorrect tailCorrect

theorem walk_refines (plan : auths_model.AuthorizationPlan)
    (limits : auths_model.VerifierLimits) (bounded : LimitsBounded limits)
    (depth maximum : Std.Usize) (refs : NativeSet) (depthBound : depth.val ≤ 17)
    (good : GoodSet limits refs) :
    auths_model.AuthorizationPlan.validate.walk plan depth limits refs maximum
      ⦃ result => Corresponds
        (checkPlan (sourceLimits limits) depth.val (viewPlan plan) (viewState refs maximum)) result ⦄ :=
  all_nodes_correct plan limits bounded depth maximum refs depthBound good

end Auths.Composition.ValidationRefinement
