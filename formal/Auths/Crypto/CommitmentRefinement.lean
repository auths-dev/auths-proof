import Auths.Crypto.Refinement
import Auths.Crypto.CommitmentFrames

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec Auths.Crypto.Endian Auths.Crypto.Refinement
set_option maxHeartbeats 2000000
set_option maxRecDepth 4096

namespace Auths.Crypto.CommitmentRefinement

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
    aesop (add safe forward append_result_exact)
      (add safe forward conversion_value)
      (add norm simp [applicationFrame, CommitmentFrames.application, List.map_append,
        be16_exact, be64_exact, hash.COMMITMENT_PREFIX, auths_model.PROTOCOL_V1,
        alloc.vec.Vec.with_capacity, alloc.vec.Vec.new])

theorem identifier_preimage_exact (kind : hash.IdentifierType) (payload : Slice Std.U8)
    (output : alloc.vec.Vec Std.U8)
    (accepted : hash.identifier_preimage kind payload = ok (.Ok output)) :
    output.val.map UScalar.val = CommitmentFrames.identifier (identifierFrame kind payload) := by
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
    aesop (add safe forward append_result_exact)
      (add safe forward conversion_value)
      (add norm simp [identifierFrame, CommitmentFrames.identifier, List.map_append,
        be16_exact, be64_exact, hash.IDENTIFIER_PREFIX, auths_model.PROTOCOL_V1,
        alloc.vec.Vec.with_capacity, alloc.vec.Vec.new, identifier_tag_word, identifierTag])

end Auths.Crypto.CommitmentRefinement
