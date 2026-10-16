import Auths.Composition.Plan
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_composition
open Auths.Composition.Model Auths.Composition.Refinement Auths.Composition.PlanModel
namespace Auths.Composition.Traversal
set_option maxHeartbeats 2000000

theorem view_elements_length {n : Nat}
    (elements : auths_composition.alloc.vec.SizedList auths_model.AuthorizationPlan n) :
    (viewElements elements).length = n := by
  induction elements with
  | nil => simp [viewElements]
  | cons head tail ih => simp [viewElements, ih]

theorem view_members_length (members : auths_composition.alloc.vec.Vec auths_model.AuthorizationPlan) :
    (viewMembers members).length = members.size := by
  cases members
  simp [viewMembers, view_elements_length]

def u16Count (count : Std.Usize) : Result Std.U16 := do
  let converted ← U16.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from count
  core.result.Result.unwrap_or converted core.num.U16.MAX

@[step] theorem u16_count_exact (count : Std.Usize) :
    u16Count count ⦃ result => result.val = min 65535 count.val ⦄ := by
  unfold u16Count U16.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from
    core.num.tryFromUScalar core.result.Result.unwrap_or
  split <;> rename_i within
  · have bound : count.val ≤ 65535 := by simpa [U16.max_eq] using within
    simp [UScalar.cast_val_eq, Nat.min_eq_right bound]
    omega
  · have above : 65535 < count.val := by simpa [U16.max_eq] using within
    simp [core.num.U16.MAX, U16.rMax, Nat.min_eq_left (Nat.le_of_lt above)]

@[step] theorem summary_default_exact :
    summary.Summary.Insts.CoreDefaultDefault.default ⦃ state => view state = empty ⦄ := by
  simp only [summary.Summary.Insts.CoreDefaultDefault.default,
    core.option.Option.Insts.CoreDefaultDefault.default, bind_tc_ok,
    core.default.DefaultUsize.default, view, empty, spec_ok,
    Summary.mk.injEq, and_true, and_self]
  change (0 : BitVec UScalarTy.Usize.numBits).toNat = 0
  rfl

theorem eq_of_spec {α : Type} (program : Result α) (expected : α)
    (contract : program ⦃ result => result = expected ⦄) : program = ok expected := by
  obtain ⟨result, evaluates, meaning⟩ := spec_imp_exists contract
  simpa only [meaning] using evaluates

theorem count_bind {α : Type} (count : Std.Usize) (next : Std.U16 → Result α) :
    (do let converted ← U16.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from count
        let value ← core.result.Result.unwrap_or converted core.num.U16.MAX
        next value) = (do let value ← u16Count count; next value) := by
  simp only [u16Count, bind_assoc_eq]

section
variable {B O : Type}
variable (nativeBranch : core.ops.function.FnMut B auths_model.ProofRef BranchOutcome)
variable (nativeObserver : core.ops.function.FnMut O EvaluationEvent Unit)
variable (modelBranch : B → auths_model.ProofRef → BranchOutcome × B)
variable (modelObserver : O → Event auths_model.ProofRef → O)
variable (branchContract : ∀ state reference,
  nativeBranch.call_mut state reference = ok (modelBranch state reference))
variable (observerContract : ∀ state event,
  nativeObserver.call_mut state event = ok ((), modelObserver state (eventView event)))

theorem children_count (members : List (Plan auths_model.ProofRef)) (state : B) (observer : O) :
    (evaluateChildren modelBranch modelObserver members state observer).1.length = members.length := by
  induction members generalizing state observer with
  | nil => simp [evaluateChildren]
  | cons head tail ih =>
    generalize expected : evaluate modelBranch modelObserver head state observer = child
    rcases child with ⟨outcome, next, observed⟩
    simp [evaluateChildren, expected, ih]

include branchContract observerContract

theorem proof_leaf_exact (reference : auths_model.ProofRef) (state : B) (observer : O) :
    evaluate_node nativeBranch nativeObserver (.mk (.Proof reference)) state observer =
      ok (evaluate modelBranch modelObserver (.proof reference) state observer) := by
  rw [evaluate_node.eq_def]
  simp only [auths_model.AuthorizationPlan.as_ref, auths_model.AuthorizationPlan._0,
    bind_tc_ok, branchContract]
  cases outcome : modelBranch state reference with
  | mk result next =>
    simp [outcome, observerContract, evaluate, eventView]

def NodeCorrect (plan : auths_model.AuthorizationPlan) : Prop :=
  ∀ state observer,
    evaluate_node nativeBranch nativeObserver plan state observer =
      ok (evaluate modelBranch modelObserver (viewPlan plan) state observer)

def ElementsCorrect {n : Nat}
    (elements : auths_composition.alloc.vec.SizedList auths_model.AuthorizationPlan n) : Prop :=
  ∀ (members : Slice auths_model.AuthorizationPlan) (index : Std.Usize)
      (branch : B) (observer : O) (state : summary.Summary),
    members.val.drop index.val = elements.toList →
    state.authorized.val + n ≤ Usize.max →
    state.indeterminate.val + n ≤ Usize.max →
    evaluate_members_loop nativeBranch nativeObserver members branch observer state index
      ⦃ result =>
        let expected := evaluateChildren modelBranch modelObserver (viewElements elements) branch observer
        (view result.1, result.2.1, result.2.2) =
          (expected.1.foldl record (view state), expected.2.1, expected.2.2) ⦄

omit branchContract observerContract in
 theorem nil_correct : ElementsCorrect nativeBranch nativeObserver modelBranch modelObserver
    (auths_composition.alloc.vec.SizedList.nil :
      auths_composition.alloc.vec.SizedList auths_model.AuthorizationPlan 0) := by
  intro members index branch observer state remaining authorizedFits indeterminateFits
  have endOfInput : members.val.length ≤ index.val := by
    have length := congrArg List.length remaining
    simp only [auths_composition.alloc.vec.SizedList.toList, List.length_drop, List.length_nil] at length
    omega
  have stop : ¬ index < members.len := by
    simpa only [UScalar.lt_equiv, Slice.len_val, Nat.not_lt] using endOfInput
  rw [evaluate_members_loop.eq_def]
  simp [stop, viewElements, evaluateChildren]

omit branchContract observerContract in
 theorem cons_correct {n : Nat} (head : auths_model.AuthorizationPlan)
    (tail : auths_composition.alloc.vec.SizedList auths_model.AuthorizationPlan n)
    (headCorrect : NodeCorrect nativeBranch nativeObserver modelBranch modelObserver head)
    (tailCorrect : ElementsCorrect nativeBranch nativeObserver modelBranch modelObserver tail) :
    ElementsCorrect nativeBranch nativeObserver modelBranch modelObserver (.cons head tail) := by
  intro members index branch observer state remaining authorizedFits indeterminateFits
  simp only [auths_composition.alloc.vec.SizedList.toList] at remaining
  have within : index.val < members.val.length := by
    have length := congrArg List.length remaining
    simp only [List.length_drop, List.length_cons,
      auths_composition.alloc.vec.SizedList.length] at length
    omega
  have atHead : members.val[index.val] = head := by
    have split := List.drop_eq_getElem_cons within
    rw [remaining] at split
    exact (List.cons.inj split).1.symm
  have guard : index < members.len := by
    simpa only [UScalar.lt_equiv, Slice.len_val] using within
  rw [evaluate_members_loop.eq_def]
  simp only [guard, ↓reduceIte]
  step as ⟨found, foundEq⟩
  have same : found = head := foundEq.trans atHead
  rw [same]
  unfold NodeCorrect at headCorrect
  rw [headCorrect branch observer]
  generalize expected : evaluate modelBranch modelObserver (viewPlan head) branch observer = child
  rcases child with ⟨outcome, nextBranch, nextObserver⟩
  simp only [bind_tc_ok]
  have authorizedStep : state.authorized.val + 1 ≤ Usize.max := by omega
  have indeterminateStep : state.indeterminate.val + 1 ≤ Usize.max := by omega
  step as ⟨nextState, nextEq⟩
  have incrementFits : index.val + 1 ≤ Usize.max := by
    have := members.property
    omega
  step as ⟨nextIndex, nextIndexEq⟩
  have remainingTail : members.val.drop nextIndex.val = tail.toList := by
    rw [nextIndexEq]
    have drop := congrArg (List.drop 1) remaining
    simpa [List.drop_drop, Nat.add_comm] using drop
  have authorizedNext : nextState.authorized.val + n ≤ Usize.max := by
    have count := congrArg Summary.authorized nextEq
    cases h : outcome <;> simp_all [view, record] <;> omega
  have indeterminateNext : nextState.indeterminate.val + n ≤ Usize.max := by
    have count := congrArg Summary.indeterminate nextEq
    cases h : outcome <;> simp_all [view, record] <;> omega
  have continuation := tailCorrect members nextIndex nextBranch nextObserver nextState
    remainingTail authorizedNext indeterminateNext
  apply spec_mono continuation
  intro actual meaning
  simpa only [viewElements, evaluateChildren, expected, List.foldl_cons, nextEq, Prod.mk.injEq] using meaning

omit branchContract observerContract in
 @[step] theorem members_exact (members : auths_composition.alloc.vec.Vec auths_model.AuthorizationPlan)
    (correct : ElementsCorrect nativeBranch nativeObserver modelBranch modelObserver members.elements)
    (branch : B) (observer : O) :
    evaluate_members nativeBranch nativeObserver (auths_composition.alloc.vec.Vec.deref members) branch observer
      ⦃ result =>
        let expected := evaluateChildren modelBranch modelObserver (viewMembers members) branch observer
        (view result.1, result.2.1, result.2.2) =
          (summarize expected.1, expected.2.1, expected.2.2) ⦄ := by
  rw [evaluate_members.eq_def]
  step as ⟨initial, initialEq⟩
  have remaining :
      (auths_composition.alloc.vec.Vec.deref members).val.drop (0#usize).val = members.elements.toList := by
    simp [auths_composition.alloc.vec.Vec.deref, auths_composition.alloc.vec.Vec.toBase,
      Aeneas.Std.alloc.vec.Vec.deref]
  have authorizedFits : initial.authorized.val + members.size ≤ Usize.max := by
    have count := congrArg Summary.authorized initialEq
    simp only [view, empty] at count
    simpa only [count, Nat.zero_add] using members.bound
  have indeterminateFits : initial.indeterminate.val + members.size ≤ Usize.max := by
    have count := congrArg Summary.indeterminate initialEq
    simp only [view, empty] at count
    simpa only [count, Nat.zero_add] using members.bound
  have continuation := correct _ 0#usize branch observer initial remaining authorizedFits indeterminateFits
  apply spec_mono continuation
  intro actual meaning
  have mapped : viewElements members.elements = viewMembers members := by
    cases members
    simp [viewMembers]
  simpa only [mapped, initialEq, summarize, Prod.mk.injEq] using meaning

omit branchContract in
theorem all_node_exact (members : auths_composition.alloc.vec.Vec auths_model.AuthorizationPlan)
    (correct : ElementsCorrect nativeBranch nativeObserver modelBranch modelObserver members.elements) :
    NodeCorrect nativeBranch nativeObserver modelBranch modelObserver (.mk (.AllOf members)) := by
  intro branch observer
  apply eq_of_spec
  rw [evaluate_node.eq_def]
  simp only [auths_model.AuthorizationPlan.as_ref, auths_model.AuthorizationPlan._0, bind_tc_ok]
  step as ⟨state, nextBranch, nextObserver, agreement⟩
  rename_i branchEq observerEq
  rw [count_bind]
  step as ⟨required, requiredEq⟩
  rw [all_exact, agreement]
  simp only [bind_tc_ok, observe_aggregate, observerContract]
  have authorizedEq := congrArg Summary.authorized agreement
  have indeterminateEq := congrArg Summary.indeterminate agreement
  simp only [view] at authorizedEq indeterminateEq
  simp only [viewPlan, viewNode, evaluate, branchEq, observerEq,
    eventView, authorizedEq, indeterminateEq, requiredEq, Slice.len_val, Slice.length,
    auths_composition.alloc.vec.Vec.deref_exact,
    auths_composition.alloc.vec.SizedList.length, view_members_length]
  dsimp only [Bind.bind, Aeneas.Std.bind]
  rfl


omit branchContract in
theorem any_node_exact (members : auths_composition.alloc.vec.Vec auths_model.AuthorizationPlan)
    (correct : ElementsCorrect nativeBranch nativeObserver modelBranch modelObserver members.elements) :
    NodeCorrect nativeBranch nativeObserver modelBranch modelObserver (.mk (.AnyOf members)) := by
  intro branch observer
  apply eq_of_spec
  rw [evaluate_node.eq_def]
  simp only [auths_model.AuthorizationPlan.as_ref, auths_model.AuthorizationPlan._0, bind_tc_ok]
  step as ⟨state, nextBranch, nextObserver, agreement⟩
  rename_i branchEq observerEq
  rw [threshold_exact, agreement]
  simp only [bind_tc_ok, observe_aggregate, observerContract]
  have authorizedEq := congrArg Summary.authorized agreement
  have indeterminateEq := congrArg Summary.indeterminate agreement
  simp only [view] at authorizedEq indeterminateEq
  simp only [viewPlan, viewNode, evaluate, branchEq, observerEq,
    eventView, authorizedEq, indeterminateEq, Slice.len_val, Slice.length,
    auths_composition.alloc.vec.Vec.deref_exact,
    auths_composition.alloc.vec.SizedList.length, view_members_length]
  dsimp only [Bind.bind, Aeneas.Std.bind]
  rfl


omit branchContract in
theorem threshold_node_exact (required : Std.U16) (members : auths_composition.alloc.vec.Vec auths_model.AuthorizationPlan)
    (correct : ElementsCorrect nativeBranch nativeObserver modelBranch modelObserver members.elements) :
    NodeCorrect nativeBranch nativeObserver modelBranch modelObserver (.mk (.KOfN required members)) := by
  intro branch observer
  apply eq_of_spec
  rw [evaluate_node.eq_def]
  simp only [auths_model.AuthorizationPlan.as_ref, auths_model.AuthorizationPlan._0, bind_tc_ok]
  step as ⟨state, nextBranch, nextObserver, agreement⟩
  rename_i branchEq observerEq
  rw [threshold_exact, agreement]
  simp only [bind_tc_ok, observe_aggregate, observerContract]
  have authorizedEq := congrArg Summary.authorized agreement
  have indeterminateEq := congrArg Summary.indeterminate agreement
  simp only [view] at authorizedEq indeterminateEq
  simp only [viewPlan, viewNode, evaluate, branchEq, observerEq,
    eventView, authorizedEq, indeterminateEq, Slice.len_val, Slice.length,
    auths_composition.alloc.vec.Vec.deref_exact,
    auths_composition.alloc.vec.SizedList.length, view_members_length]
  dsimp only [Bind.bind, Aeneas.Std.bind]
  rfl

theorem all_nodes_correct (plan : auths_model.AuthorizationPlan) :
    NodeCorrect nativeBranch nativeObserver modelBranch modelObserver plan := by
  refine auths_model.AuthorizationPlan.rec
    (motive_1 := fun plan => NodeCorrect nativeBranch nativeObserver modelBranch modelObserver plan)
    (motive_2 := fun node => NodeCorrect nativeBranch nativeObserver modelBranch modelObserver (.mk node))
    (motive_3 := fun members => ElementsCorrect nativeBranch nativeObserver modelBranch modelObserver members.elements)
    (motive_4 := fun _ elements => ElementsCorrect nativeBranch nativeObserver modelBranch modelObserver elements)
    ?_ ?_ ?_ ?_ ?_ ?_ ?_ ?_ plan
  · intro node correct
    exact correct
  · intro reference branch observer
    simpa only [viewPlan, viewNode] using
      proof_leaf_exact nativeBranch nativeObserver modelBranch modelObserver
        branchContract observerContract reference branch observer
  · intro members correct
    exact all_node_exact nativeBranch nativeObserver modelBranch modelObserver observerContract members correct
  · intro members correct
    exact any_node_exact nativeBranch nativeObserver modelBranch modelObserver observerContract members correct
  · intro required members correct
    exact threshold_node_exact nativeBranch nativeObserver modelBranch modelObserver observerContract required members correct
  · intro size elements bound correct
    exact correct
  · exact nil_correct nativeBranch nativeObserver modelBranch modelObserver
  · intro size head tail headCorrect tailCorrect
    exact cons_correct nativeBranch nativeObserver modelBranch modelObserver head tail headCorrect tailCorrect

theorem evaluator_refines (plan : auths_model.AuthorizationPlan) (branch : B) (observer : O) :
    evaluate_node nativeBranch nativeObserver plan branch observer =
      ok (evaluate modelBranch modelObserver (viewPlan plan) branch observer) := by
  exact all_nodes_correct nativeBranch nativeObserver modelBranch modelObserver
    branchContract observerContract plan branch observer

end
end Auths.Composition.Traversal
