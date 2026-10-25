import Auths.Codec.Action
import Auths.Codec.Constructors
import Auths.Codec.ByteFields

open Aeneas Aeneas.Std Result
set_option maxHeartbeats 2000000
set_option maxRecDepth 2048

open auths_codec
open Auths.Codec.Constructors
namespace Auths.Codec.Action

theorem attachments_preserve_body (action : auths_codec.auths_model.CanonicalAction)
    (attachments : alloc.vec.Vec auths_codec.auths_model.DetachedAttachment)
    (output : auths_codec.auths_model.CanonicalAction)
    (accepted : auths_codec.auths_model.CanonicalAction.with_detached_attachments action attachments = ok (.Ok output)) :
    output.body = action.body := by
  unfold auths_codec.auths_model.CanonicalAction.with_detached_attachments at accepted
  simp only [Bind.bind, Aeneas.Std.bind] at accepted
  repeat' first
    | casesm* _ × _
    | dsimp only at accepted
    | split at accepted
    | simp (failIfUnchanged := true) only [uncurry, Bind.bind, Aeneas.Std.bind,
        core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame.from,
        Result.ok.injEq, core.result.Result.Ok.injEq, reduceCtorEq] at accepted
    | contradiction
  all_goals subst output; rfl

theorem constructor_body_valid
    (profile : auths_codec.auths_model.ProfileRef) (mediaType : auths_codec.auths_model.MediaType)
    (body : alloc.vec.Vec Std.U8) (permission : auths_codec.auths_model.Permission)
    (budget : Option auths_codec.auths_model.BudgetCeiling) (output : auths_codec.auths_model.CanonicalAction)
    (accepted : auths_codec.auths_model.CanonicalAction.new profile mediaType body permission budget = ok (.Ok output)) :
    0 < output.body.val.length ∧ output.body.val.length ≤ 8388608 := by
  rw [canonical_action_new_exact] at accepted
  split at accepted
  · rename_i valid
    have same : (⟨profile, mediaType, body, permission, budget, alloc.vec.Vec.new _⟩ :
        auths_codec.auths_model.CanonicalAction) = output := by simpa using accepted
    subst output
    exact valid
  · simp at accepted

theorem decoded_body_valid (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits) (action : auths_codec.auths_model.CanonicalAction)
    (accepted : decode.decode_canonical_action input limits = ok (.Ok action)) :
    0 < action.body.val.length ∧ action.body.val.length ≤ 8388608 := by
  unfold decode.decode_canonical_action canonical.accept canonical.accept_with_error at accepted
  simp only [Bind.bind, Aeneas.Std.bind] at accepted
  repeat' first
    | casesm* _ × _
    | dsimp only at accepted
    | split at accepted
    | simp (failIfUnchanged := true) only [uncurry, Bind.bind, Aeneas.Std.bind,
        core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, bind_tc_fail, bind_tc_div,
        Result.ok.injEq, core.result.Result.Ok.injEq, reduceCtorEq] at accepted
    | contradiction
  all_goals subst action
  all_goals casesm* core.result.Result auths_codec.auths_model.CanonicalAction _
  all_goals simp_all only [Result.ok.injEq, core.result.Result.Ok.injEq,
    core.ops.control_flow.ControlFlow.Continue.injEq, reduceCtorEq]
  all_goals
    aesop (add safe forward constructor_body_valid)
      (add safe forward attachments_preserve_body)



theorem constructor_preserves_body
    (profile : auths_codec.auths_model.ProfileRef) (mediaType : auths_codec.auths_model.MediaType)
    (body : alloc.vec.Vec Std.U8) (permission : auths_codec.auths_model.Permission)
    (budget : Option auths_codec.auths_model.BudgetCeiling) (output : auths_codec.auths_model.CanonicalAction)
    (accepted : auths_codec.auths_model.CanonicalAction.new profile mediaType body permission budget = ok (.Ok output)) :
    output.body = body := by
  rw [canonical_action_new_exact] at accepted
  split at accepted
  · have same : (⟨profile, mediaType, body, permission, budget, alloc.vec.Vec.new _⟩ :
        auths_codec.auths_model.CanonicalAction) = output := by simpa using accepted
    subst output
    rfl
  · simp at accepted

theorem decoded_body_within_deployment (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits) (action : auths_codec.auths_model.CanonicalAction)
    (accepted : decode.decode_canonical_action input limits = ok (.Ok action)) :
    action.body.val.length ≤ limits.canonical_body_bytes.val := by
  unfold decode.decode_canonical_action canonical.accept canonical.accept_with_error at accepted
  simp only [Bind.bind, Aeneas.Std.bind, auths_codec.auths_model.VerifierLimits.get] at accepted
  repeat' first
    | casesm* _ × _
    | dsimp only at accepted
    | split at accepted
    | simp (failIfUnchanged := true) only [uncurry, Bind.bind, Aeneas.Std.bind,
        core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, bind_tc_fail, bind_tc_div,
        Result.ok.injEq, core.result.Result.Ok.injEq, reduceCtorEq] at accepted
    | contradiction
  all_goals subst action
  all_goals casesm* core.result.Result auths_codec.auths_model.CanonicalAction _
  all_goals casesm* core.result.Result (alloc.vec.Vec Std.U8) _
  all_goals simp_all only [Result.ok.injEq, core.result.Result.Ok.injEq,
    core.ops.control_flow.ControlFlow.Continue.injEq, reduceCtorEq]
  all_goals
    aesop (add safe forward constructor_preserves_body)
      (add safe forward attachments_preserve_body)
      (add safe forward bounded_bytes_valid)

end Auths.Codec.Action
