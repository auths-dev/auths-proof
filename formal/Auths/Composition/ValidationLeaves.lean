import Auths.Composition.ValidationModel
open Aeneas Aeneas.Std Result Aeneas.Std.WP
open auths_composition Auths.Composition.SetModel Auths.Composition.ValidationModel
namespace Auths.Composition.ValidationLeaves

@[step] theorem word_max_exact (left right : Std.Usize) :
    auths_composition.core.cmp.Ord.max.default core.cmp.OrdUsize left right ⦃ result =>
      result.val = max left.val right.val ⦄ := by
  unfold auths_composition.core.cmp.Ord.max.default
  simp only [core.cmp.impls.PartialOrdUsize.lt, liftFun2, bind_tc_ok]
  split <;> simp_all [spec_ok, Nat.max_def]

def viewState (refs : alloc.collections.btree.set.BTreeSet auths_model.ProofRef Global)
    (maximumDepth : Std.Usize) : State auths_model.ProofRef :=
  ⟨refs.values.toFinset, maximumDepth.val⟩

def Corresponds (expected : Except ShapeError (State auths_model.ProofRef))
    (actual : core.result.Result Unit auths_model.ModelError ×
      alloc.collections.btree.set.BTreeSet auths_model.ProofRef Global × Std.Usize) : Prop :=
  match expected with
  | .error .tooLarge => actual.1 = .Err .PlanLimitExceeded
  | .error .invalidOperator => actual.1 = .Err .InvalidPlan
  | .ok next => actual.1 = .Ok () ∧ actual.2.1.values.Pairwise Before ∧
      viewState actual.2.1 actual.2.2 = next

theorem proof_leaf_exact (reference : auths_model.ProofRef) (depth maximum : Std.Usize)
    (limits : auths_model.VerifierLimits)
    (refs : alloc.collections.btree.set.BTreeSet auths_model.ProofRef Global)
    (ordered : refs.values.Pairwise Before) (room : refs.values.length < Usize.max) :
    auths_model.AuthorizationPlan.validate.walk (.mk (.Proof reference)) depth limits refs maximum
      ⦃ result => Corresponds
        (checkPlan (sourceLimits limits) depth.val (.proof reference) (viewState refs maximum)) result ⦄ := by
  rw [auths_model.AuthorizationPlan.validate.walk.eq_def]
  simp only [auths_model.AuthorizationPlan._0]
  by_cases tooDeep : depth > limits.plan_depth
  · have tooDeepNat : depth.val > limits.plan_depth.val := by
      simpa only [UScalar.lt_equiv] using tooDeep
    simp [tooDeep, Corresponds, checkPlan, enter, Except.bind, Bind.bind, sourceLimits, tooDeepNat]
  · have within : ¬ depth.val > limits.plan_depth.val := by
      simpa only [UScalar.lt_equiv] using tooDeep
    simp only [tooDeep, ite_false]
    step as ⟨updatedMaximum, maximumEq⟩
    obtain ⟨added, updated, executes, sorted, members, fresh, size⟩ :=
      insert_set core.core.clone.CloneGlobal reference refs ordered room
    rw [executes]
    simp only [bind_tc_ok, uncurry]
    cases added with
    | false =>
      have present : reference ∈ refs.values := by
        by_contra absent
        have impossible := fresh.mpr absent
        contradiction
      simp [Corresponds, checkPlan, enter, Except.bind, Bind.bind, sourceLimits, within, viewState, present]
    | true =>
      rw [if_pos rfl]
      have absent : reference ∉ refs.values := fresh.mp rfl
      have setEq : updated.values.toFinset = insert reference refs.values.toFinset := by
        ext item
        simp only [List.mem_toFinset, Finset.mem_insert]
        exact members item
      have countEq : (insert reference refs.values.toFinset).card = updated.values.length := by
        rw [← setEq]
        exact List.toFinset_card_of_nodup (ordered_nodup updated.values sorted)
      unfold alloc.collections.btree.set.BTreeSet.len
      simp only [bind_tc_ok]
      split <;> rename_i capacity
      · have excess : updated.values.length > limits.plan_leaves.val := by
          simpa only [UScalar.lt_equiv, Usize.ofNatCore_val_eq] using capacity
        simp [Corresponds, checkPlan, enter, Except.bind, Bind.bind, sourceLimits, within, viewState, absent, countEq, excess]
      · have fits : ¬ updated.values.length > limits.plan_leaves.val := by
          simpa only [UScalar.lt_equiv, Usize.ofNatCore_val_eq] using capacity
        simp [Corresponds, checkPlan, enter, Except.bind, Bind.bind, sourceLimits, within, viewState, absent, countEq, fits,
          sorted, setEq, maximumEq]

end Auths.Composition.ValidationLeaves
