import qualification.aeneas.generated.protocol_codec.Funs
import Auths.Crypto.Refinement
import Auths.Crypto.CommitmentFrames
import Auths.Crypto.BufferAllocation

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec
open Auths.Crypto.Endian
set_option maxHeartbeats 2000000
set_option maxRecDepth 4096

namespace Auths.Crypto.ProtocolFraming

/- The complete protocol source contains the actual framing bodies. These
proofs port the independent byte specifications across its positive-vector
representation. No Auths preimage or constructor is replaced by a foreign
function. SHA correctness, totality and security remain explicit contracts. -/

abbrev conversion_value := @Auths.Crypto.Refinement.conversion_value
abbrev conversion_bound := @Auths.Crypto.Refinement.conversion_bound
abbrev byte_values_valid := Auths.Crypto.Refinement.byte_values_valid
abbrev byte_values_injective := Auths.Crypto.Refinement.byte_values_injective

theorem append_result_exact (left : alloc.vec.Vec Std.U8) (right : Slice Std.U8)
    (output : alloc.vec.Vec Std.U8)
    (accepted : alloc.vec.Vec.extend_from_slice core.clone.CloneU8 left right = ok output) :
    output.val = left.val ++ right.val := by
  unfold alloc.vec.Vec.extend_from_slice at accepted
  rw [Auths.Codec.Evaluation.append_bytes] at accepted
  split at accepted
  · simp only [bind_tc_ok, Result.ok.injEq] at accepted
    subst output
    simp [alloc.vec.Vec.ofBase, alloc.vec.Vec.toBase, alloc.vec.Vec.val,
      auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.toBase,
      auths_composition.alloc.vec.Vec.val, auths_composition.alloc.vec.SizedList.toList_ofList]
  · split at accepted
    · simp only [bind_tc_ok, Result.ok.injEq] at accepted
      subst output
      simp [alloc.vec.Vec.ofBase, alloc.vec.Vec.toBase, alloc.vec.Vec.val,
        auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.toBase,
        auths_composition.alloc.vec.Vec.val, auths_composition.alloc.vec.SizedList.toList_ofList]
    · simp only [bind_tc_fail, reduceCtorEq] at accepted

theorem buffer_refines (capacity : Std.Usize) :
    hash.preimage_buffer capacity =
      ok (if BufferAllocation.Fits capacity then .Ok (alloc.vec.Vec.new Std.U8) else .Err .LimitExceeded) := by
  unfold hash.preimage_buffer Isize.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from
  have conversion := IScalar.tryMkOpt_eq .Isize capacity.val
  cases converted : IScalar.tryMkOpt .Isize capacity.val with
  | none =>
    simp only [converted] at conversion
    have refused : ¬ BufferAllocation.Fits capacity := fun fits => conversion ((BufferAllocation.signed_bounds_iff capacity).mpr fits)
    simp [converted, refused, core.result.Result.map_err, error.limit_error, BuiltinFnOnce,
      core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from]
  | some signed =>
    simp only [converted] at conversion
    have fits : BufferAllocation.Fits capacity := (BufferAllocation.signed_bounds_iff capacity).mp conversion.2
    simp [converted, fits, core.result.Result.map_err, error.limit_error, BuiltinFnOnce,
      core.result.Result.Insts.CoreOpsTry.branch, alloc.vec.Vec.with_capacity, alloc.vec.Vec.new,
        alloc.vec.Vec.ofBase, alloc.vec.Vec.toBase, alloc.vec.Vec.val,
        auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.toBase,
        auths_composition.alloc.vec.Vec.val,
        auths_composition.alloc.vec.SizedList.toList_ofList]


@[cbv_eval] theorem object_tag (kind : hash.ObjectType) :
    IScalar.hcast .U16 (read_discriminant kind) =
      match kind with
      | .Grant => 1#u16
      | .Action => 2#u16
      | .PrincipalStatus => 3#u16
      | .GrantStatus => 4#u16
      | .Observation => 9#u16
      | .Approval => 10#u16 := by
  have discriminant (kind : hash.ObjectType) :
      (read_discriminant kind).val = (match kind with
        | .Grant => 1 | .Action => 2 | .PrincipalStatus => 3
        | .GrantStatus => 4 | .Observation => 9 | .Approval => 10 : Int) := by
    cases kind <;> simp [read_discriminant, instDiscriminantObjectTypeIsize,
      hash.ObjectType.read_discriminant, IScalar.ofInt, IScalar.ofInt_val_eq]
  cases kind
  · apply UScalar.eq_of_val_eq
    have contract := IScalar.hcast_inBounds_spec .U16
      (read_discriminant hash.ObjectType.Grant) (by rw [discriminant]; scalar_tac)
    simp only [lift, Aeneas.Std.WP.spec_ok, discriminant] at contract
    exact_mod_cast contract
  · apply UScalar.eq_of_val_eq
    have contract := IScalar.hcast_inBounds_spec .U16
      (read_discriminant hash.ObjectType.Action) (by rw [discriminant]; scalar_tac)
    simp only [lift, Aeneas.Std.WP.spec_ok, discriminant] at contract
    exact_mod_cast contract
  · apply UScalar.eq_of_val_eq
    have contract := IScalar.hcast_inBounds_spec .U16
      (read_discriminant hash.ObjectType.PrincipalStatus) (by rw [discriminant]; scalar_tac)
    simp only [lift, Aeneas.Std.WP.spec_ok, discriminant] at contract
    exact_mod_cast contract
  · apply UScalar.eq_of_val_eq
    have contract := IScalar.hcast_inBounds_spec .U16
      (read_discriminant hash.ObjectType.GrantStatus) (by rw [discriminant]; scalar_tac)
    simp only [lift, Aeneas.Std.WP.spec_ok, discriminant] at contract
    exact_mod_cast contract
  · apply UScalar.eq_of_val_eq
    have contract := IScalar.hcast_inBounds_spec .U16
      (read_discriminant hash.ObjectType.Observation) (by rw [discriminant]; scalar_tac)
    simp only [lift, Aeneas.Std.WP.spec_ok, discriminant] at contract
    exact_mod_cast contract
  · apply UScalar.eq_of_val_eq
    have contract := IScalar.hcast_inBounds_spec .U16
      (read_discriminant hash.ObjectType.Approval) (by rw [discriminant]; scalar_tac)
    simp only [lift, Aeneas.Std.WP.spec_ok, discriminant] at contract
    exact_mod_cast contract



def tagValue : hash.ObjectType → Nat
  | .Grant => 1 | .Action => 2 | .PrincipalStatus => 3
  | .GrantStatus => 4 | .Observation => 9 | .Approval => 10

def inputFrame (kind : hash.ObjectType) (profile : Str)
    (version : Std.U16) (statement : Slice Std.U8) : Auths.Crypto.Framing.Frame :=
  ⟨tagValue kind, profile.val.map (·.val), version.val, statement.val.map (·.val)⟩


theorem input_frame_valid_from_conversions
    (kind : hash.ObjectType) (profile : Str) (version : Std.U16) (statement : Slice Std.U8)
    (profileLength : Std.U16) (statementLength : Std.U64)
    (profileConverted : core.num.tryFromUScalar .U16 (Slice.len profile) = ok (.Ok profileLength))
    (statementConverted : core.num.tryFromUScalar .U64 (Slice.len statement) = ok (.Ok statementLength)) :
    (inputFrame kind profile version statement).Valid := by
  have profileBound := conversion_bound (Slice.len profile) profileLength profileConverted
  have statementBound := conversion_bound (Slice.len statement) statementLength statementConverted
  refine ⟨?_, ?_, version.bv.isLt, ?_, byte_values_valid _, byte_values_valid _⟩
  · cases kind <;> simp only [inputFrame, tagValue] <;> decide
  · simpa only [inputFrame, List.length_map, Slice.len_val, Slice.length, UScalarTy.numBits, Nat.reducePow] using profileBound
  · simpa only [inputFrame, List.length_map, Slice.len_val, Slice.length, UScalarTy.numBits, Nat.reducePow] using statementBound

theorem signing_preimage_exact (kind : hash.ObjectType) (profile : Str)
    (version : Std.U16) (statement : Slice Std.U8) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.signing_preimage kind profile version statement = ok (.Ok output)) :
    output.val.map (·.val) = Auths.Crypto.Framing.encode (inputFrame kind profile version statement) := by
  unfold hash.signing_preimage at accepted
  simp only [buffer_refines] at accepted
  simp only [core.str.Str.len, core.str.Str.as_bytes,
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
    aesop (add safe forward append_result_exact)
      (add safe forward conversion_value)
      (add norm simp [inputFrame, Auths.Crypto.Framing.encode,
        List.map_append, be16_exact, be64_exact,
        hash.SIGNING_PREFIX, auths_model.PROTOCOL_V1,
        alloc.vec.Vec.with_capacity, alloc.vec.Vec.new,
        alloc.vec.Vec.ofBase, alloc.vec.Vec.toBase, alloc.vec.Vec.val,
        auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.toBase,
        auths_composition.alloc.vec.Vec.val,
        auths_composition.alloc.vec.SizedList.toList_ofList,
        object_tag, tagValue])


theorem accepted_frame_valid (kind : hash.ObjectType) (profile : Str)
    (version : Std.U16) (statement : Slice Std.U8) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.signing_preimage kind profile version statement = ok (.Ok output)) :
    (inputFrame kind profile version statement).Valid := by
  unfold hash.signing_preimage at accepted
  simp only [buffer_refines] at accepted
  simp only [core.str.Str.len, core.str.Str.as_bytes,
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
  all_goals simp_all only [lift, core.result.Result.Insts.CoreOpsTry.branch,
    Result.ok.injEq, core.result.Result.Ok.injEq,
    core.ops.control_flow.ControlFlow.Continue.injEq, reduceCtorEq]
  all_goals
    aesop (add safe forward input_frame_valid_from_conversions)


theorem tag_value_injective : Function.Injective tagValue := by
  intro left right same
  cases left <;> cases right <;> simp_all [tagValue]


theorem accepted_preimages_bind_inputs
    (leftKind rightKind : hash.ObjectType) (leftProfile rightProfile : Str)
    (leftVersion rightVersion : Std.U16) (leftStatement rightStatement : Slice Std.U8)
    (leftOutput rightOutput : alloc.vec.Vec Std.U8)
    (leftAccepted : hash.signing_preimage leftKind leftProfile leftVersion leftStatement = ok (.Ok leftOutput))
    (rightAccepted : hash.signing_preimage rightKind rightProfile rightVersion rightStatement = ok (.Ok rightOutput))
    (same : leftOutput.val = rightOutput.val) :
    leftKind = rightKind ∧ leftProfile = rightProfile ∧
      leftVersion = rightVersion ∧ leftStatement = rightStatement := by
  have leftExact := signing_preimage_exact _ _ _ _ _ leftAccepted
  have rightExact := signing_preimage_exact _ _ _ _ _ rightAccepted
  have sameBytes := congrArg (fun bytes : List Std.U8 => bytes.map (·.val)) same
  have frames := Auths.Crypto.Framing.framing_is_unambiguous _ _
    (accepted_frame_valid _ _ _ _ _ leftAccepted)
    (accepted_frame_valid _ _ _ _ _ rightAccepted)
    (leftExact.symm.trans (sameBytes.trans rightExact))
  refine ⟨tag_value_injective (congrArg Auths.Crypto.Framing.Frame.objectTag frames), ?_, ?_, ?_⟩
  · apply Subtype.ext
    exact byte_values_injective (congrArg Auths.Crypto.Framing.Frame.profile frames)
  · apply UScalar.eq_of_val_eq
    exact congrArg Auths.Crypto.Framing.Frame.profileVersion frames
  · apply Subtype.ext
    exact byte_values_injective (congrArg Auths.Crypto.Framing.Frame.statement frames)

theorem preimage_length_exact (kind : hash.ObjectType) (profile : Str)
    (version : Std.U16) (statement : Slice Std.U8) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.signing_preimage kind profile version statement = ok (.Ok output)) :
    output.val.length = 21 + profile.val.length + statement.val.length := by
  have length := congrArg List.length (signing_preimage_exact _ _ _ _ _ accepted)
  simpa only [List.length_map, Auths.Crypto.Framing.length_exact, inputFrame] using length


theorem object_domains_separate
    (leftKind rightKind : hash.ObjectType) (leftProfile rightProfile : Str)
    (leftVersion rightVersion : Std.U16) (leftStatement rightStatement : Slice Std.U8)
    (leftOutput rightOutput : alloc.vec.Vec Std.U8)
    (leftAccepted : hash.signing_preimage leftKind leftProfile leftVersion leftStatement = ok (.Ok leftOutput))
    (rightAccepted : hash.signing_preimage rightKind rightProfile rightVersion rightStatement = ok (.Ok rightOutput))
    (different : leftKind ≠ rightKind) : leftOutput.val ≠ rightOutput.val := by
  intro same
  exact different (accepted_preimages_bind_inputs _ _ _ _ _ _ _ _ _ _ leftAccepted rightAccepted same).1


def applicationFrame (domain : Str) (payload : Slice Std.U8) : CommitmentFrames.Application :=
  ⟨domain.val.map UScalar.val, payload.val.map UScalar.val⟩

def identifierTag : hash.IdentifierType → Nat
  | .Grant => 1 | .Action => 2 | .Plan => 3 | .Evidence => 4
  | .PrincipalStatus => 5 | .GrantStatus => 6 | .Context => 9
  | .ObservationRequirement => 11 | .ApprovalRequirement => 12

def identifierFrame (kind : hash.IdentifierType) (payload : Slice Std.U8) : CommitmentFrames.Identifier :=
  ⟨identifierTag kind, payload.val.map UScalar.val⟩


@[cbv_eval] theorem identifier_tag_word (kind : hash.IdentifierType) :
    IScalar.hcast .U16 (read_discriminant kind) =
      match kind with
      | .Grant => 1#u16
      | .Action => 2#u16
      | .Plan => 3#u16
      | .Evidence => 4#u16
      | .PrincipalStatus => 5#u16
      | .GrantStatus => 6#u16
      | .Context => 9#u16
      | .ObservationRequirement => 11#u16
      | .ApprovalRequirement => 12#u16
 := by
  have discriminant (kind : hash.IdentifierType) :
      (read_discriminant kind).val = (match kind with
        | .Grant => 1
        | .Action => 2
        | .Plan => 3
        | .Evidence => 4
        | .PrincipalStatus => 5
        | .GrantStatus => 6
        | .Context => 9
        | .ObservationRequirement => 11
        | .ApprovalRequirement => 12
        : Int) := by
    cases kind <;> simp [read_discriminant, instDiscriminantIdentifierTypeIsize,
      hash.IdentifierType.read_discriminant, IScalar.ofInt, IScalar.ofInt_val_eq]
  cases kind
  · apply UScalar.eq_of_val_eq
    have contract := IScalar.hcast_inBounds_spec .U16
      (read_discriminant hash.IdentifierType.Grant) (by rw [discriminant]; scalar_tac)
    simp only [lift, Aeneas.Std.WP.spec_ok, discriminant] at contract
    exact_mod_cast contract
  · apply UScalar.eq_of_val_eq
    have contract := IScalar.hcast_inBounds_spec .U16
      (read_discriminant hash.IdentifierType.Action) (by rw [discriminant]; scalar_tac)
    simp only [lift, Aeneas.Std.WP.spec_ok, discriminant] at contract
    exact_mod_cast contract
  · apply UScalar.eq_of_val_eq
    have contract := IScalar.hcast_inBounds_spec .U16
      (read_discriminant hash.IdentifierType.Plan) (by rw [discriminant]; scalar_tac)
    simp only [lift, Aeneas.Std.WP.spec_ok, discriminant] at contract
    exact_mod_cast contract
  · apply UScalar.eq_of_val_eq
    have contract := IScalar.hcast_inBounds_spec .U16
      (read_discriminant hash.IdentifierType.Evidence) (by rw [discriminant]; scalar_tac)
    simp only [lift, Aeneas.Std.WP.spec_ok, discriminant] at contract
    exact_mod_cast contract
  · apply UScalar.eq_of_val_eq
    have contract := IScalar.hcast_inBounds_spec .U16
      (read_discriminant hash.IdentifierType.PrincipalStatus) (by rw [discriminant]; scalar_tac)
    simp only [lift, Aeneas.Std.WP.spec_ok, discriminant] at contract
    exact_mod_cast contract
  · apply UScalar.eq_of_val_eq
    have contract := IScalar.hcast_inBounds_spec .U16
      (read_discriminant hash.IdentifierType.GrantStatus) (by rw [discriminant]; scalar_tac)
    simp only [lift, Aeneas.Std.WP.spec_ok, discriminant] at contract
    exact_mod_cast contract
  · apply UScalar.eq_of_val_eq
    have contract := IScalar.hcast_inBounds_spec .U16
      (read_discriminant hash.IdentifierType.Context) (by rw [discriminant]; scalar_tac)
    simp only [lift, Aeneas.Std.WP.spec_ok, discriminant] at contract
    exact_mod_cast contract
  · apply UScalar.eq_of_val_eq
    have contract := IScalar.hcast_inBounds_spec .U16
      (read_discriminant hash.IdentifierType.ObservationRequirement) (by rw [discriminant]; scalar_tac)
    simp only [lift, Aeneas.Std.WP.spec_ok, discriminant] at contract
    exact_mod_cast contract
  · apply UScalar.eq_of_val_eq
    have contract := IScalar.hcast_inBounds_spec .U16
      (read_discriminant hash.IdentifierType.ApprovalRequirement) (by rw [discriminant]; scalar_tac)
    simp only [lift, Aeneas.Std.WP.spec_ok, discriminant] at contract
    exact_mod_cast contract

theorem application_preimage_exact (domain : Str) (payload : Slice Std.U8)
    (output : alloc.vec.Vec Std.U8)
    (accepted : hash.commitment_preimage domain payload = ok (.Ok output)) :
    output.val.map UScalar.val = CommitmentFrames.application (applicationFrame domain payload) := by
  unfold hash.commitment_preimage at accepted
  simp only [buffer_refines, core.str.Str.len, core.str.Str.as_bytes,
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
    aesop (add safe forward append_result_exact)
      (add safe forward conversion_value)
      (add norm simp [applicationFrame, CommitmentFrames.application, List.map_append,
        be16_exact, be64_exact, hash.COMMITMENT_PREFIX, auths_model.PROTOCOL_V1,
        alloc.vec.Vec.with_capacity, alloc.vec.Vec.new,
        alloc.vec.Vec.ofBase, alloc.vec.Vec.toBase, alloc.vec.Vec.val,
        auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.toBase,
        auths_composition.alloc.vec.Vec.val,
        auths_composition.alloc.vec.SizedList.toList_ofList])

theorem identifier_preimage_exact (kind : hash.IdentifierType) (payload : Slice Std.U8)
    (output : alloc.vec.Vec Std.U8)
    (accepted : hash.identifier_preimage kind payload = ok (.Ok output)) :
    output.val.map UScalar.val = CommitmentFrames.identifier (identifierFrame kind payload) := by
  unfold hash.identifier_preimage at accepted
  simp only [buffer_refines,
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
    aesop (add safe forward append_result_exact)
      (add safe forward conversion_value)
      (add norm simp [identifierFrame, CommitmentFrames.identifier, List.map_append,
        be16_exact, be64_exact, hash.IDENTIFIER_PREFIX, auths_model.PROTOCOL_V1,
        alloc.vec.Vec.with_capacity, alloc.vec.Vec.new,
        alloc.vec.Vec.ofBase, alloc.vec.Vec.toBase, alloc.vec.Vec.val,
        auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.toBase,
        auths_composition.alloc.vec.Vec.val,
        auths_composition.alloc.vec.SizedList.toList_ofList, identifier_tag_word, identifierTag])


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
  simp only [buffer_refines, core.str.Str.len, core.str.Str.as_bytes,
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
  simp only [buffer_refines,
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


end Auths.Crypto.ProtocolFraming
