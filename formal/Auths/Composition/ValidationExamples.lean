import Auths.Composition.ValidationContract
import Auths.Composition.PlanExamples
open Aeneas Aeneas.Std Result
open auths_composition Auths.Composition.PlanModel Auths.Composition.ValidationModel
open Auths.Composition.ValidationRefinement Auths.Composition.ValidationContract
open Auths.Composition.PlanExamples
namespace Auths.Composition.ValidationExamples
set_option cbv.warning false
set_option maxRecDepth 16384
set_option maxHeartbeats 2000000

def limits : auths_model.VerifierLimits where
  bundle_bytes := 1#usize
  action_bytes := 1#usize
  context_bytes := 1#usize
  grants := 1#usize
  actions := 1#usize
  plan_leaves := 128#usize
  plan_depth := 16#usize
  plan_branching := 128#usize
  evidence := 1#usize
  evidence_bytes := 1#usize
  bindings := 1#usize
  principal_status := 1#usize
  grant_status := 1#usize
  attachments := 1#usize
  attachment_bytes := 1#usize
  signatures := 1#usize
  signature_bytes := 1#usize
  permissions := 1#usize
  audiences := 1#usize
  extensions := 1#usize
  extension_bytes := 1#usize
  body_digests := 1#usize
  binding_evidence := 1#usize
  canonical_body_bytes := 1#usize
  registry_entries := 1#usize
  trust_anchors := 1#usize
  work_units := 10000#u64
  approvals := 1#usize
  approver_anchors := 1#usize
  approval_requirements := 1#usize

theorem limits_bounded : LimitsBounded limits := by unfold LimitsBounded; decide

theorem conjunction_valid : Valid (sourceLimits limits) (viewPlan twoLeaves) := by cbv; simp; decide

/-- Exercises public validation and the actual evaluator, with two distinct
    references and all three resulting postorder events. -/
theorem public_conjunction : evaluate_observed branch observer twoLeaves limits 0 0 =
    ok (.Ok .Authorized, 2, 3) := by
  obtain ⟨shape, validated⟩ := (source_accepts_iff_valid twoLeaves limits limits_bounded).mpr conjunction_valid
  simp only [evaluate_observed, validated, bind_tc_ok, two_leaf_conjunction]
  rfl

def duplicate : auths_model.AuthorizationPlan :=
  .mk (.AllOf (auths_composition.alloc.vec.Vec.ofBase
    ⟨[leaf 1#u8, leaf 1#u8], by scalar_tac⟩))

theorem duplicate_invalid : ¬ Valid (sourceLimits limits) (viewPlan duplicate) := by cbv; simp

theorem duplicate_refused : evaluate_observed branch observer duplicate limits 5 9 =
    ok (.Err .AuthorizationPlanInvalid, 5, 9) :=
  invalid_plan_preserves_callbacks branch observer duplicate limits limits_bounded duplicate_invalid 5 9

def impossibleThreshold : auths_model.AuthorizationPlan := .mk (.KOfN 0#u16 threeMembers)

theorem zero_threshold_invalid : ¬ Valid (sourceLimits limits) (viewPlan impossibleThreshold) := by cbv

theorem zero_threshold_refused : evaluate_observed mixedBranch events impossibleThreshold limits 4 [] =
    ok (.Err .AuthorizationPlanInvalid, 4, []) :=
  invalid_plan_preserves_callbacks mixedBranch events impossibleThreshold limits limits_bounded
    zero_threshold_invalid 4 []

theorem empty_invalid : ¬ Valid (sourceLimits limits)
    (viewPlan (.mk (.AnyOf (auths_composition.alloc.vec.Vec.ofBase ⟨[], by scalar_tac⟩)))) := by cbv

theorem mixed_threshold_valid : Valid (sourceLimits limits) (viewPlan (.mk (.KOfN 2#u16 threeMembers))) := by cbv; simp; decide

theorem public_threshold_indeterminate :
    evaluate_observed mixedBranch events (.mk (.KOfN 2#u16 threeMembers)) limits 0 [] =
      ok (.Ok (.Indeterminate .ExternalFactUnavailable), 3,
        mixedLeaves ++ [.Aggregate 3#usize 2#u16 1#usize 1#usize
          (.Indeterminate .ExternalFactUnavailable)]) := by
  obtain ⟨shape, validated⟩ := (source_accepts_iff_valid _ limits limits_bounded).mpr mixed_threshold_valid
  simp only [evaluate_observed, validated, bind_tc_ok, threshold_indeterminate]
  rfl


def narrow : auths_model.VerifierLimits := { limits with plan_branching := 1#usize }

theorem narrow_bounded : LimitsBounded narrow := by unfold LimitsBounded; decide

theorem narrow_invalid : ¬ Valid (sourceLimits narrow) (viewPlan twoLeaves) := by cbv; simp

theorem narrow_refused : evaluate_observed branch observer twoLeaves narrow 5 9 =
    ok (.Err .AuthorizationPlanInvalid, 5, 9) :=
  invalid_plan_preserves_callbacks branch observer twoLeaves narrow narrow_bounded narrow_invalid 5 9

def shallow : auths_model.VerifierLimits := { limits with plan_depth := 1#usize }

theorem shallow_bounded : LimitsBounded shallow := by unfold LimitsBounded; decide

theorem shallow_invalid : ¬ Valid (sourceLimits shallow) (viewPlan twoLeaves) := by cbv; simp

theorem shallow_refused : evaluate_observed branch observer twoLeaves shallow 5 9 =
    ok (.Err .AuthorizationPlanInvalid, 5, 9) :=
  invalid_plan_preserves_callbacks branch observer twoLeaves shallow shallow_bounded shallow_invalid 5 9

end Auths.Composition.ValidationExamples
