import Auths.Composition.Refinement
import Auths.Codec.Evaluation
import Lean.Elab.Tactic.Cbv
open Aeneas Aeneas.Std Result
open auths_composition
set_option cbv.warning false
set_option maxRecDepth 16384
set_option maxHeartbeats 2000000
namespace Auths.Composition.PlanExamples

def branch : core.ops.function.FnMut Nat auths_model.ProofRef BranchOutcome where
  FnOnceInst := ⟨fun _ _ => ok .Authorized⟩
  call_mut := fun count _ => ok (.Authorized, count + 1)

def observer : core.ops.function.FnMut Nat EvaluationEvent Unit where
  FnOnceInst := ⟨fun _ _ => ok ()⟩
  call_mut := fun count _ => ok ((), count + 1)

def reference (tag : Std.U8) : auths_model.ProofRef :=
  ⟨List.replicate 32 tag, by simp⟩

def leaf (tag : Std.U8) : auths_model.AuthorizationPlan :=
  .mk (.Proof (reference tag))

def twoLeaves : auths_model.AuthorizationPlan :=
  .mk (.AllOf (auths_composition.alloc.vec.Vec.ofBase
    ⟨[leaf 1#u8, leaf 2#u8], by scalar_tac⟩))

attribute [local cbv_eval] Auths.Composition.Refinement.threshold_exact
attribute [local cbv_eval] evaluate_node.eq_def evaluate_members.eq_def evaluate_members_loop.eq_def

theorem two_leaf_conjunction : evaluate_node branch observer twoLeaves 0 0 =
    ok (.Authorized, 2, 3) := by
  cbv

def mixedOutcome : Nat → BranchOutcome
  | 0 => .Denied .PermissionNotGranted
  | 1 => .Authorized
  | _ => .Indeterminate .ExternalFactUnavailable

def mixedBranch : core.ops.function.FnMut Nat auths_model.ProofRef BranchOutcome where
  FnOnceInst := ⟨fun count _ => ok (mixedOutcome count)⟩
  call_mut := fun count _ => ok (mixedOutcome count, count + 1)

def events : core.ops.function.FnMut (List EvaluationEvent) EvaluationEvent Unit where
  FnOnceInst := ⟨fun _ _ => ok ()⟩
  call_mut := fun trace event => ok ((), trace ++ [event])

def threeMembers : auths_composition.alloc.vec.Vec auths_model.AuthorizationPlan :=
  auths_composition.alloc.vec.Vec.ofBase
    ⟨[leaf 1#u8, leaf 2#u8, leaf 3#u8], by scalar_tac⟩

def mixedLeaves : List EvaluationEvent :=
  [.Proof (reference 1#u8) (.Denied .PermissionNotGranted),
   .Proof (reference 2#u8) .Authorized,
   .Proof (reference 3#u8) (.Indeterminate .ExternalFactUnavailable)]

theorem all_visits_after_denial :
    evaluate_node mixedBranch events (.mk (.AllOf threeMembers)) 0 [] =
      ok (.Denied .PermissionNotGranted, 3,
        mixedLeaves ++ [.Aggregate 3#usize 3#u16 1#usize 1#usize (.Denied .PermissionNotGranted)]) := by
  cbv

theorem any_visits_after_authorization :
    evaluate_node mixedBranch events (.mk (.AnyOf threeMembers)) 0 [] =
      ok (.Authorized, 3,
        mixedLeaves ++ [.Aggregate 3#usize 1#u16 1#usize 1#usize .Authorized]) := by
  cbv

theorem threshold_indeterminate :
    evaluate_node mixedBranch events (.mk (.KOfN 2#u16 threeMembers)) 0 [] =
      ok (.Indeterminate .ExternalFactUnavailable, 3,
        mixedLeaves ++ [.Aggregate 3#usize 2#u16 1#usize 1#usize
          (.Indeterminate .ExternalFactUnavailable)]) := by
  cbv

theorem threshold_refused :
    evaluate_node mixedBranch events (.mk (.KOfN 3#u16 threeMembers)) 0 [] =
      ok (.Denied .PermissionNotGranted, 3,
        mixedLeaves ++ [.Aggregate 3#usize 3#u16 1#usize 1#usize (.Denied .PermissionNotGranted)]) := by
  cbv

end Auths.Composition.PlanExamples
