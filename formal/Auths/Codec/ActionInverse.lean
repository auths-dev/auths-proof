import Auths.Codec.ActionWireParts
import Auths.Codec.ActionTotal
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.ActionInverse
open Refinement ProtocolEncode ObjectEncode EncoderState AttachmentEncode
open ActionWireParts PrimitiveInverse NativeFieldInverse

/-- Complete public decoder inverse for the independent canonical action
encoding. Well-formedness and deployment fit are independent semantic
predicates; no expected decoder, constructor or encoder outcome is assumed. -/
@[step] theorem decode_encoding (input : Slice Std.U8) (limits : auths_codec.auths_model.VerifierLimits)
    (action : auths_codec.auths_model.CanonicalAction)
    (valid : ActionCarrier.Valid action) (fits : ActionCarrier.Fits limits action)
    (wire : byteList input.val = ActionEncode.actionEncoding action) :
    decode.decode_canonical_action input limits ⦃ actual => actual = .Ok action ⦄ := by
  have bodyBound := valid.body_bound
  have deploymentBytes := fits.encoded_bytes
  have inputLength : input.val.length = (ActionEncode.actionEncoding action).length := by
    simpa [byteList] using congrArg List.length wire
  have withinBytes : ¬ Slice.len input > limits.action_bytes := by
    simp only [UScalar.lt_equiv, Slice.len_val]
    omega
  have strings := ActionCarrier.strings_bounded action valid
  unfold decode.decode_canonical_action canonical.accept canonical.accept_with_error
  step with Limits.validate_exact limits as ⟨limitResult, limitMeaning⟩
  simp only [fits.limits_valid, ↓reduceIte] at limitMeaning
  simp only [limitMeaning, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
    auths_model.VerifierLimits.get, withinBytes, ↓reduceIte]
  step with Cursor.new_exact input as ⟨decoder, decoderInput, decoderPosition⟩
  have at0 : At input action decoder 0 := by
    exact ⟨decoderInput, by simpa [before, parts] using decoderPosition⟩
  have piece0 : (parts action)[0]? = some (encodeHead ⟨5, 6⟩) := rfl
  have input0 := input_piece input action decoder 0 (encodeHead ⟨5, 6⟩) wire at0 piece0
  step with PrimitiveInverse.map_inverse decoder 6#u64 (before action 0) (after action 0) input0 at0.2 
    as ⟨r0, d0, success0, position0, inputSame0⟩
  have at1 : At input action d0 1 :=
    advance input action decoder d0 0 (encodeHead ⟨5, 6⟩) at0 piece0 position0 inputSame0
  simp only [success0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  have piece1 : (parts action)[1]? = some (encodeHead ⟨0, 0⟩) := rfl
  have input1 := input_piece input action d0 1 (encodeHead ⟨0, 0⟩) wire at1 piece1
  step with PrimitiveInverse.key_inverse d0 0#u8 (before action 1) (after action 1) input1 at1.2 
    as ⟨r1, d1, success1, position1, inputSame1⟩
  have at2 : At input action d1 2 :=
    advance input action d0 d1 1 (encodeHead ⟨0, 0⟩) at1 piece1 position1 inputSame1
  simp only [success1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  have piece2 : (parts action)[2]? = some (profileEncoding (stringBytes action.profile.id) action.profile.version.val) := rfl
  have input2 := input_piece input action d1 2 (profileEncoding (stringBytes action.profile.id) action.profile.version.val) wire at2 piece2
  step with NativeFieldInverse.profile_inverse d1 action.profile (before action 2) (after action 2) input2 at2.2 valid.fields.1
    as ⟨r2, d2, success2, position2, inputSame2⟩
  have at3 : At input action d2 3 :=
    advance input action d1 d2 2 (profileEncoding (stringBytes action.profile.id) action.profile.version.val) at2 piece2 position2 inputSame2
  simp only [success2, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  have piece3 : (parts action)[3]? = some (encodeHead ⟨0, 1⟩) := rfl
  have input3 := input_piece input action d2 3 (encodeHead ⟨0, 1⟩) wire at3 piece3
  step with PrimitiveInverse.key_inverse d2 1#u8 (before action 3) (after action 3) input3 at3.2 
    as ⟨r3, d3, success3, position3, inputSame3⟩
  have at4 : At input action d3 4 :=
    advance input action d2 d3 3 (encodeHead ⟨0, 1⟩) at3 piece3 position3 inputSame3
  simp only [success3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  have piece4 : (parts action)[4]? = some (payloadEncoding 3 (stringBytes action.media_type)) := rfl
  have input4 := input_piece input action d3 4 (payloadEncoding 3 (stringBytes action.media_type)) wire at4 piece4
  step with PrimitiveInverse.text_inverse d3 action.media_type strings.media (before action 4) (after action 4) input4 at4.2 
    as ⟨r4, d4, success4, position4, inputSame4⟩
  have at5 : At input action d4 5 :=
    advance input action d3 d4 4 (payloadEncoding 3 (stringBytes action.media_type)) at4 piece4 position4 inputSame4
  simp only [success4, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with NativeFieldInverse.media_parse_inverse action.media_type strings.media valid.fields.2.1
    as ⟨mediaResult, mediaSuccess⟩
  simp only [mediaSuccess, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  have piece5 : (parts action)[5]? = some (encodeHead ⟨0, 2⟩) := rfl
  have input5 := input_piece input action d4 5 (encodeHead ⟨0, 2⟩) wire at5 piece5
  step with PrimitiveInverse.key_inverse d4 2#u8 (before action 5) (after action 5) input5 at5.2 
    as ⟨r5, d5, success5, position5, inputSame5⟩
  have at6 : At input action d5 6 :=
    advance input action d4 d5 5 (encodeHead ⟨0, 2⟩) at5 piece5 position5 inputSame5
  simp only [success5, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  have piece6 : (parts action)[6]? = some (payloadEncoding 2 (byteList action.body.val)) := rfl
  have input6 := input_piece input action d5 6 (payloadEncoding 2 (byteList action.body.val)) wire at6 piece6
  simp only [auths_model.VerifierLimits.get, bind_tc_ok]
  step with PrimitiveInverse.bytes_inverse d5 limits.canonical_body_bytes action.body (before action 6) (after action 6) input6 at6.2 valid.body_nonempty fits.body_bytes (by omega)
    as ⟨r6, d6, success6, position6, inputSame6⟩
  have at7 : At input action d6 7 :=
    advance input action d5 d6 6 (payloadEncoding 2 (byteList action.body.val)) at6 piece6 position6 inputSame6
  simp only [success6, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  have piece7 : (parts action)[7]? = some (encodeHead ⟨0, 3⟩) := rfl
  have input7 := input_piece input action d6 7 (encodeHead ⟨0, 3⟩) wire at7 piece7
  step with PrimitiveInverse.key_inverse d6 3#u8 (before action 7) (after action 7) input7 at7.2 
    as ⟨r7, d7, success7, position7, inputSame7⟩
  have at8 : At input action d7 8 :=
    advance input action d6 d7 7 (encodeHead ⟨0, 3⟩) at7 piece7 position7 inputSame7
  simp only [success7, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  have piece8 : (parts action)[8]? = some (permissionEncoding (stringBytes action.permission.capability) (stringBytes action.permission.resource)) := rfl
  have input8 := input_piece input action d7 8 (permissionEncoding (stringBytes action.permission.capability) (stringBytes action.permission.resource)) wire at8 piece8
  step with NativeFieldInverse.permission_inverse d7 action.permission (before action 8) (after action 8) input8 at8.2 valid.fields.2.2.1
    as ⟨r8, d8, success8, position8, inputSame8⟩
  have at9 : At input action d8 9 :=
    advance input action d7 d8 8 (permissionEncoding (stringBytes action.permission.capability) (stringBytes action.permission.resource)) at8 piece8 position8 inputSame8
  simp only [success8, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  have piece9 : (parts action)[9]? = some (encodeHead ⟨0, 4⟩) := rfl
  have input9 := input_piece input action d8 9 (encodeHead ⟨0, 4⟩) wire at9 piece9
  step with PrimitiveInverse.key_inverse d8 4#u8 (before action 9) (after action 9) input9 at9.2 
    as ⟨r9, d9, success9, position9, inputSame9⟩
  have at10 : At input action d9 10 :=
    advance input action d8 d9 9 (encodeHead ⟨0, 4⟩) at9 piece9 position9 inputSame9
  simp only [success9, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  have piece10 : (parts action)[10]? = some (optionalBudgetEncoding (action.requested_budget.map ObjectEncode.budgetView)) := rfl
  have input10 := input_piece input action d9 10 (optionalBudgetEncoding (action.requested_budget.map ObjectEncode.budgetView)) wire at10 piece10
  step with NativeFieldInverse.optional_budget_inverse d9 action.requested_budget (before action 10) (after action 10) input10 at10.2 valid.fields.2.2.2
    as ⟨r10, d10, success10, position10, inputSame10⟩
  have at11 : At input action d10 11 :=
    advance input action d9 d10 10 (optionalBudgetEncoding (action.requested_budget.map ObjectEncode.budgetView)) at10 piece10 position10 inputSame10
  simp only [success10, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  have piece11 : (parts action)[11]? = some (encodeHead ⟨0, 5⟩) := rfl
  have input11 := input_piece input action d10 11 (encodeHead ⟨0, 5⟩) wire at11 piece11
  step with PrimitiveInverse.key_inverse d10 5#u8 (before action 11) (after action 11) input11 at11.2 
    as ⟨r11, d11, success11, position11, inputSame11⟩
  have at12 : At input action d11 12 :=
    advance input action d10 d11 11 (encodeHead ⟨0, 5⟩) at11 piece11 position11 inputSame11
  simp only [success11, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  have piece12 : (parts action)[12]? = some (encodeHead ⟨4, action.detached_attachments.val.length⟩) := rfl
  have input12 := input_piece input action d11 12 (encodeHead ⟨4, action.detached_attachments.val.length⟩) wire at12 piece12
  simp only [auths_model.VerifierLimits.get, bind_tc_ok]
  step with PrimitiveInverse.array_inverse d11 limits.attachments (alloc.vec.Vec.len action.detached_attachments) (before action 12) (after action 12) input12 at12.2 (by simpa only [alloc.vec.Vec.len_val] using fits.attachment_count)
    as ⟨r12, d12, success12, position12, inputSame12⟩
  have at13 : At input action d12 13 :=
    advance input action d11 d12 12 (encodeHead ⟨4, action.detached_attachments.val.length⟩) at12 piece12 position12 inputSame12
  simp only [success12, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [cbor.Decoder.impl.position, bind_tc_ok]
  have piece13 : (parts action)[13]? = some (attachmentsEncoding action.detached_attachments.val) := rfl
  have input13 : byteList input.val = before action 13 ++ attachmentsEncoding action.detached_attachments.val ++ after action 13 := by
    rw [wire, decompose action 13 _ piece13]
  step with AttachmentInverse.source_batch_inverse input limits d12.position
    (alloc.vec.Vec.len action.detached_attachments) action.detached_attachments.val
    (before action 13) (after action 13) input13 at13.2 (by simp [alloc.vec.Vec.len_val])
    valid.attachment_payloads fits.attachment_bytes
    as ⟨batchResult, batch, batchSuccess, batchValues, batchBytes, batchPosition⟩
  have completed : batch.position.val = input.val.length := by
    have totalPosition := final_position input action wire
    rw [before_next action 13 _ piece13, List.length_append] at totalPosition
    omega
  simp only [batchSuccess, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with Cursor.at_exact input batch.position as ⟨finalResult, finalMeaning⟩
  have within : batch.position.val ≤ input.val.length := by omega
  simp only [within, ↓reduceIte] at finalMeaning
  simp only [finalMeaning]
  have sameAttachments : batch.attachments = action.detached_attachments := Subtype.ext batchValues
  rw [ActionCarrier.initial_constructor action valid]
  simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [sameAttachments]
  step with ActionCarrier.normalization_identity action valid as ⟨normalized, normalizationMeaning⟩
  simp only [normalizationMeaning, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with Cursor.ensure_complete_exact ⟨input, batch.position⟩ input as ⟨complete, completionMeaning⟩
  simp only [completed, ↓reduceIte] at completionMeaning
  simp only [completionMeaning, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ActionEncode.action_exact action strings (ActionCarrier.buffer_room action valid)
    as ⟨encoded, encodeMeaning⟩
  cases encoded with
  | Err error => simp [ActionEncode.resultView] at encodeMeaning
  | Ok bytes =>
    have sameBytes : bytes.val = input.val := AttachmentInverse.bytes_injective (by
      simpa only [ActionEncode.resultView, core.result.Result.Ok.injEq, ← wire] using encodeMeaning)
    have sameSlice : alloc.vec.Vec.deref bytes = input := Subtype.ext sameBytes
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok, alloc.vec.Vec.as_slice]
    step with Action.bytes_ne_exact as ⟨different, comparisonMeaning⟩
    simp only [sameSlice, ne_self_iff_false, decide_false] at comparisonMeaning
    simp [comparisonMeaning]

/-- Actual source writer-to-reader completeness, including every field,
attachment, constructor, limit and final canonicality check. -/
@[step] theorem encode_decode (action : auths_codec.auths_model.CanonicalAction)
    (limits : auths_codec.auths_model.VerifierLimits)
    (valid : ActionCarrier.Valid action) (fits : ActionCarrier.Fits limits action) :
    encode.encode_canonical_action action ⦃ encoded =>
      ∃ bytes, encoded = .Ok bytes ∧
        decode.decode_canonical_action (alloc.vec.Vec.deref bytes) limits ⦃ decoded => decoded = .Ok action ⦄ ⦄ := by
  apply spec_mono (ActionEncode.action_exact action (ActionCarrier.strings_bounded action valid)
    (ActionCarrier.buffer_room action valid))
  intro encoded meaning
  cases encoded with
  | Err error => simp [ActionEncode.resultView] at meaning
  | Ok bytes =>
    refine ⟨bytes, rfl, ?_⟩
    apply decode_encoding (alloc.vec.Vec.deref bytes) limits action valid fits
    simpa [ActionEncode.resultView, alloc.vec.Vec.deref] using meaning

end Auths.Codec.ActionInverse
