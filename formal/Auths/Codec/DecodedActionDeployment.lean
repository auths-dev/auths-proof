import Auths.Codec.DecodedActionCarrier
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.DecodedActionDeployment
set_option maxHeartbeats 2000000

private theorem array_model_bound (input : List Nat) (position maximum count next : Nat)
    (accepted : Fields.arrayAt input position maximum = (.Ok count, next)) : count ≤ maximum := by
  unfold Fields.arrayAt at accepted
  cases header : Collection.collectionAt input position 4 with
  | mk raw finish =>
    cases raw with
    | none => simp [header] at accepted
    | some raw =>
      cases raw with
      | none => simp [header] at accepted
      | some found =>
        by_cases within : found ≤ maximum
        · have same : found = count ∧ finish = next := by simpa [header, within] using accepted
          omega
        · simp [header, within] at accepted

theorem array_accepted_bound (self next : cbor.Decoder) (maximum count : Std.Usize)
    (accepted : decode.array self maximum = ok (.Ok count, next)) : count.val ≤ maximum.val := by
  have contract := Fields.array_exact self maximum
  rw [accepted] at contract
  simp only [spec_ok] at contract
  exact array_model_bound _ _ _ _ _ contract.1.symm

theorem batch_accepted_bounds (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits) (position count : Std.Usize)
    (batch : decode.AttachmentBatch)
    (accepted : decode.attachment_batch input limits position count = ok (.Ok batch)) :
    batch.attachments.val.length = count.val ∧
      AttachmentResources.byteSum batch.attachments.val ≤ limits.attachment_bytes.val := by
  have contract := AttachmentDecodeSafety.source_batch_success input limits position count
  rw [accepted] at contract
  simp only [spec_ok] at contract
  have facts := contract batch rfl
  have total : batch.attachment_bytes.val = AttachmentResources.byteSum batch.attachments.val := by
    simpa only [AttachmentDecodeSafety.Valid, AttachmentDecode.batchView,
      AttachmentDecodeSafety.byteSum, AttachmentResources.byteSum, List.map_map, Function.comp_def,
      Refinement.byteList, List.length_map] using facts.1.1
  exact ⟨facts.2, by simpa only [total] using facts.1.2.1⟩

def Bounds (limits : auths_codec.auths_model.VerifierLimits)
    (action : auths_codec.auths_model.CanonicalAction) : Prop :=
  action.detached_attachments.val.length ≤ limits.attachments.val ∧
    AttachmentResources.byteSum action.detached_attachments.val ≤ limits.attachment_bytes.val

theorem normalized_bounds (action : auths_codec.auths_model.CanonicalAction)
    (values : alloc.vec.Vec auths_codec.auths_model.DetachedAttachment)
    (output : auths_codec.auths_model.CanonicalAction) (limits : auths_codec.auths_model.VerifierLimits)
    (count : values.val.length ≤ limits.attachments.val)
    (bytes : AttachmentResources.byteSum values.val ≤ limits.attachment_bytes.val)
    (accepted : auths_model.CanonicalAction.with_detached_attachments action values = ok (.Ok output)) :
    Bounds limits output := by
  have permutation := (AttachmentCanonical.constructor_canonical action values output accepted).2.2
  constructor
  · rw [permutation.length_eq]
    exact count
  · have unchanged := (permutation.map fun value => value.bytes.val.length).sum_eq
    simpa only [AttachmentResources.byteSum, unchanged] using bytes

theorem decoded_attachment_bounds (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits) (action : auths_codec.auths_model.CanonicalAction)
    (accepted : decode.decode_canonical_action input limits = ok (.Ok action)) : Bounds limits action := by
  unfold decode.decode_canonical_action canonical.accept canonical.accept_with_error at accepted
  simp only [Bind.bind, Aeneas.Std.bind, auths_model.VerifierLimits.get] at accepted
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
    aesop (add safe forward array_accepted_bound)
      (add safe forward batch_accepted_bounds)
      (add safe forward normalized_bounds)

/-- All completeness premises about limits are earned by an actual accepted
public action, including aggregate bytes after attachment normalization. -/
theorem decoded_fits (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits) (action : auths_codec.auths_model.CanonicalAction)
    (accepted : decode.decode_canonical_action input limits = ok (.Ok action)) : ActionCarrier.Fits limits action := by
  have bytes := ActionResources.decoded_wire_exact input limits action accepted
  have inputBound := DecodedActionCarrier.decoded_input_bound input limits action accepted
  have encodedLength : (ActionEncode.actionEncoding action).length = input.val.length := by
    simpa [Refinement.byteList] using (congrArg List.length bytes).symm
  have attachments := decoded_attachment_bounds input limits action accepted
  exact ⟨DecodedActionCarrier.decoded_limits_valid input limits action accepted,
    by simpa only [encodedLength] using inputBound,
    Action.decoded_body_within_deployment input limits action accepted,
    attachments.1, attachments.2⟩

end Auths.Codec.DecodedActionDeployment
