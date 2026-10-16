import Auths.Crypto.CommitmentRefinement
open Aeneas Aeneas.Std Result
open auths_codec Auths.Crypto.Refinement Auths.Crypto.CommitmentRefinement
set_option maxHeartbeats 2000000
set_option maxRecDepth 4096
namespace Auths.Crypto.CommitmentValidity

theorem application_frame_valid_from_bounds (domain : Str) (payload : Slice Std.U8)
    (nonempty : 0 < domain.val.length) (bounded : domain.val.length ≤ 128)
    (payloadLength : Std.U64)
    (converted : core.num.tryFromUScalar .U64 (Slice.len payload) = ok (.Ok payloadLength)) :
    (applicationFrame domain payload).Valid := by
  have bound := conversion_bound (Slice.len payload) payloadLength converted
  refine ⟨?_, ?_, ?_, byte_values_valid _, byte_values_valid _⟩
  · simpa only [applicationFrame, List.length_map] using nonempty
  · simpa only [applicationFrame, List.length_map] using bounded
  · simpa only [applicationFrame, List.length_map, Slice.len_val, Slice.length,
      UScalarTy.numBits, Nat.reducePow] using bound

theorem identifier_frame_valid_from_conversion (kind : hash.IdentifierType)
    (payload : Slice Std.U8) (payloadLength : Std.U64)
    (converted : core.num.tryFromUScalar .U64 (Slice.len payload) = ok (.Ok payloadLength)) :
    (identifierFrame kind payload).Valid := by
  have bound := conversion_bound (Slice.len payload) payloadLength converted
  refine ⟨?_, ?_, byte_values_valid _⟩
  · cases kind <;> simp [identifierFrame, identifierTag]
  · simpa only [identifierFrame, List.length_map, Slice.len_val, Slice.length,
      UScalarTy.numBits, Nat.reducePow] using bound

theorem application_accepted_frame_valid (domain : Str) (payload : Slice Std.U8)
    (output : alloc.vec.Vec Std.U8)
    (accepted : hash.commitment_preimage domain payload = ok (.Ok output)) :
    (applicationFrame domain payload).Valid := by
  unfold hash.commitment_preimage at accepted
  simp only [BufferAllocation.buffer_refines, core.str.Str.len, core.str.Str.as_bytes,
    core.option.Option.and_then,
    hash.commitment_preimage.closure.Insts.CoreOpsFunctionFnOnceTupleUsizeOptionUsize,
    hash.commitment_preimage.closure.Insts.CoreOpsFunctionFnOnceTupleUsizeOptionUsize.call_once,
    hash.commitment_preimage.closure_1.Insts.CoreOpsFunctionFnOnceTupleUsizeOptionUsize,
    hash.commitment_preimage.closure_1.Insts.CoreOpsFunctionFnOnceTupleUsizeOptionUsize.call_once,
    U16.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from,
    U64.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from,
    error.limit_error, BuiltinFnOnce, core.result.Result.map_err, core.option.Option.ok_or,
    Bind.bind, Aeneas.Std.bind] at accepted
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
  all_goals subst output
  all_goals casesm* core.result.Result (UScalar _) _
  all_goals split_ifs at *
  all_goals simp_all only [lift, core.result.Result.Insts.CoreOpsTry.branch,
    Result.ok.injEq, core.result.Result.Ok.injEq,
    core.ops.control_flow.ControlFlow.Continue.injEq, reduceCtorEq]
  all_goals
    aesop (add safe forward conversion_bound)
      (add safe apply byte_values_valid)
      (add norm simp [CommitmentFrames.Application.Valid, applicationFrame,
        core.slice.Slice.is_empty, Slice.len_val, Slice.length,
        hash.MAX_COMMITMENT_DOMAIN_BYTES, List.length_map, List.length_pos_iff])

theorem identifier_accepted_frame_valid (kind : hash.IdentifierType) (payload : Slice Std.U8)
    (output : alloc.vec.Vec Std.U8)
    (accepted : hash.identifier_preimage kind payload = ok (.Ok output)) :
    (identifierFrame kind payload).Valid := by
  unfold hash.identifier_preimage at accepted
  simp only [BufferAllocation.buffer_refines,
    core.option.Option.and_then,
    hash.identifier_preimage.closure.Insts.CoreOpsFunctionFnOnceTupleUsizeOptionUsize,
    hash.identifier_preimage.closure.Insts.CoreOpsFunctionFnOnceTupleUsizeOptionUsize.call_once,
    U64.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from,
    error.limit_error, BuiltinFnOnce, core.result.Result.map_err, core.option.Option.ok_or,
    Bind.bind, Aeneas.Std.bind] at accepted
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
  all_goals subst output
  all_goals casesm* core.result.Result (UScalar _) _
  all_goals split_ifs at *
  all_goals simp_all only [lift, core.result.Result.Insts.CoreOpsTry.branch,
    Result.ok.injEq, core.result.Result.Ok.injEq,
    core.ops.control_flow.ControlFlow.Continue.injEq, reduceCtorEq]
  all_goals
    aesop (add safe forward identifier_frame_valid_from_conversion)

theorem identifier_tag_injective : Function.Injective identifierTag := by
  intro left right same
  cases left <;> cases right <;> simp_all [identifierTag]

theorem accepted_application_inputs_bind
    (leftDomain rightDomain : Str) (leftPayload rightPayload : Slice Std.U8)
    (leftOutput rightOutput : alloc.vec.Vec Std.U8)
    (leftAccepted : hash.commitment_preimage leftDomain leftPayload = ok (.Ok leftOutput))
    (rightAccepted : hash.commitment_preimage rightDomain rightPayload = ok (.Ok rightOutput))
    (same : leftOutput.val = rightOutput.val) :
    leftDomain = rightDomain ∧ leftPayload = rightPayload := by
  have frames := CommitmentFrames.application_unambiguous _ _
    (application_accepted_frame_valid _ _ _ leftAccepted)
    (application_accepted_frame_valid _ _ _ rightAccepted)
    ((application_preimage_exact _ _ _ leftAccepted).symm.trans
      ((congrArg (fun bytes : List Std.U8 => bytes.map UScalar.val) same).trans
        (application_preimage_exact _ _ _ rightAccepted)))
  constructor
  · apply Subtype.ext
    exact byte_values_injective (congrArg CommitmentFrames.Application.domain frames)
  · apply Subtype.ext
    exact byte_values_injective (congrArg CommitmentFrames.Application.payload frames)

theorem accepted_identifier_inputs_bind
    (leftKind rightKind : hash.IdentifierType) (leftPayload rightPayload : Slice Std.U8)
    (leftOutput rightOutput : alloc.vec.Vec Std.U8)
    (leftAccepted : hash.identifier_preimage leftKind leftPayload = ok (.Ok leftOutput))
    (rightAccepted : hash.identifier_preimage rightKind rightPayload = ok (.Ok rightOutput))
    (same : leftOutput.val = rightOutput.val) :
    leftKind = rightKind ∧ leftPayload = rightPayload := by
  have frames := CommitmentFrames.identifier_unambiguous _ _
    (identifier_accepted_frame_valid _ _ _ leftAccepted)
    (identifier_accepted_frame_valid _ _ _ rightAccepted)
    ((identifier_preimage_exact _ _ _ leftAccepted).symm.trans
      ((congrArg (fun bytes : List Std.U8 => bytes.map UScalar.val) same).trans
        (identifier_preimage_exact _ _ _ rightAccepted)))
  constructor
  · exact identifier_tag_injective (congrArg CommitmentFrames.Identifier.kind frames)
  · apply Subtype.ext
    exact byte_values_injective (congrArg CommitmentFrames.Identifier.payload frames)

theorem application_output_length (domain : Str) (payload : Slice Std.U8)
    (output : alloc.vec.Vec Std.U8)
    (accepted : hash.commitment_preimage domain payload = ok (.Ok output)) :
    output.val.length = 28 + domain.val.length + payload.val.length := by
  have length := congrArg List.length (application_preimage_exact _ _ _ accepted)
  simpa only [List.length_map, CommitmentFrames.application_length, applicationFrame] using length

theorem identifier_output_length (kind : hash.IdentifierType) (payload : Slice Std.U8)
    (output : alloc.vec.Vec Std.U8)
    (accepted : hash.identifier_preimage kind payload = ok (.Ok output)) :
    output.val.length = 20 + payload.val.length := by
  have length := congrArg List.length (identifier_preimage_exact _ _ _ accepted)
  simpa only [List.length_map, CommitmentFrames.identifier_length, identifierFrame] using length

end Auths.Crypto.CommitmentValidity
