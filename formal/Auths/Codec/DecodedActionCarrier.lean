import Auths.Codec.AttachmentCanonical
import Auths.Codec.ActionInverse
import Mathlib.Tactic.CasesM
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.DecodedActionCarrier
set_option maxHeartbeats 2000000

/-- An accepted public object earns validation of the complete operator limit
record; validity of action-related fields alone does not replace this gate. -/
theorem decoded_limits_valid (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits) (action : auths_codec.auths_model.CanonicalAction)
    (accepted : decode.decode_canonical_action input limits = ok (.Ok action)) : Limits.Valid limits := by
  obtain ⟨decision, evaluates, meaning⟩ := spec_imp_exists (Limits.validate_exact limits)
  by_contra invalid
  have refusal : decision = .Err .CollectionLimitExceeded := by simpa [invalid] using meaning
  unfold decode.decode_canonical_action canonical.accept canonical.accept_with_error at accepted
  rw [evaluates] at accepted
  simp [refusal, core.result.Result.Insts.CoreOpsTry.branch,
    core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
    error.CodecError.Insts.CoreConvertFromModelError.from] at accepted

def CanonicalPayloads (action : auths_codec.auths_model.CanonicalAction) : Prop :=
  action.detached_attachments.val.Pairwise AttachmentSort.digestLE ∧
  (action.detached_attachments.val.map fun value => value.digest).Nodup ∧
  AttachmentInverse.WellFormed action.detached_attachments.val

theorem constructed_canonical_payloads (action : auths_codec.auths_model.CanonicalAction)
    (values : alloc.vec.Vec auths_codec.auths_model.DetachedAttachment)
    (output : auths_codec.auths_model.CanonicalAction)
    (payloads : AttachmentInverse.WellFormed values.val)
    (accepted : auths_model.CanonicalAction.with_detached_attachments action values = ok (.Ok output)) :
    CanonicalPayloads output := by
  have canonical := AttachmentCanonical.constructor_canonical action values output accepted
  exact ⟨canonical.1, canonical.2.1,
    AttachmentCanonical.constructor_preserves_payloads action values output payloads accepted⟩

theorem decoded_canonical_payloads (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits) (action : auths_codec.auths_model.CanonicalAction)
    (accepted : decode.decode_canonical_action input limits = ok (.Ok action)) : CanonicalPayloads action := by
  have validated := decoded_limits_valid input limits action accepted
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
    aesop (add safe forward AttachmentCanonical.batch_payloads)
      (add safe forward constructed_canonical_payloads)

/-- The full independently stated valid carrier relation is earned from
successful source decoding, including original field constructors, normalized
order, global digest uniqueness and each individual attachment payload. -/
theorem decoded_valid (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits) (action : auths_codec.auths_model.CanonicalAction)
    (accepted : decode.decode_canonical_action input limits = ok (.Ok action)) : ActionCarrier.Valid action := by
  have fields := ActionDecodedFields.decoded_fields_valid input limits action accepted
  have body := Action.decoded_body_valid input limits action accepted
  have attachments := AttachmentResources.decoded_earns_bounds input limits action accepted
  have canonical := decoded_canonical_payloads input limits action accepted
  exact ⟨fields, body.1, body.2, attachments.1, attachments.2, canonical.2.2, canonical.1, canonical.2.1⟩

theorem decoded_input_bound (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits) (action : auths_codec.auths_model.CanonicalAction)
    (accepted : decode.decode_canonical_action input limits = ok (.Ok action)) :
    input.val.length ≤ limits.action_bytes.val := by
  have valid := decoded_limits_valid input limits action accepted
  obtain ⟨decision, evaluates, meaning⟩ := spec_imp_exists (Limits.validate_exact limits)
  have allowed : decision = .Ok () := by simpa [valid] using meaning
  by_contra oversized
  have exceeds : Slice.len input > limits.action_bytes := by
    simp only [UScalar.lt_equiv, Slice.len_val]
    omega
  unfold decode.decode_canonical_action canonical.accept canonical.accept_with_error at accepted
  rw [evaluates] at accepted
  simp [allowed, core.result.Result.Insts.CoreOpsTry.branch,
    auths_model.VerifierLimits.get, exceeds] at accepted

end Auths.Codec.DecodedActionCarrier
