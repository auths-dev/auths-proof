import qualification.aeneas.generated.codec.Funs
import Auths.Codec.Evaluation
import Auths.Crypto.Endian
import Auths.Crypto.Framing
import Mathlib.Tactic.CasesM
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
open Auths.Crypto.Endian
set_option maxHeartbeats 2000000
namespace Auths.Crypto.Refinement

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


theorem append_result_exact (left : alloc.vec.Vec Std.U8) (right : Slice Std.U8)
    (output : alloc.vec.Vec Std.U8)
    (accepted : alloc.vec.Vec.extend_from_slice core.clone.CloneU8 left right = ok output) :
    output.val = left.val ++ right.val := by
  rw [Auths.Codec.Evaluation.append_bytes] at accepted
  split at accepted
  · exact (congrArg Subtype.val (Result.ok.inj accepted)).symm
  · split at accepted
    · exact (congrArg Subtype.val (Result.ok.inj accepted)).symm
    · cases accepted

theorem conversion_value {source target : UScalarTy} (value : UScalar source)
    (output : UScalar target)
    (accepted : core.num.tryFromUScalar target value = ok (.Ok output)) :
    output.val = value.val := by
  unfold core.num.tryFromUScalar at accepted
  split at accepted
  · rename_i fits
    have same : UScalar.cast target value = output := by simpa using accepted
    rw [← same]
    have contract := UScalar.cast_inBounds_spec target value fits
    simpa only [lift, Aeneas.Std.WP.spec_ok] using contract
  · simp at accepted

def tagValue : hash.ObjectType → Nat
  | .Grant => 1 | .Action => 2 | .PrincipalStatus => 3
  | .GrantStatus => 4 | .Observation => 9 | .Approval => 10

def inputFrame (kind : hash.ObjectType) (profile : Str)
    (version : Std.U16) (statement : Slice Std.U8) : Auths.Crypto.Framing.Frame :=
  ⟨tagValue kind, profile.val.map (·.val), version.val, statement.val.map (·.val)⟩

theorem conversion_bound {source target : UScalarTy} (value : UScalar source)
    (output : UScalar target)
    (accepted : core.num.tryFromUScalar target value = ok (.Ok output)) :
    value.val < 2 ^ target.numBits := by
  rw [← conversion_value value output accepted]
  exact output.bv.isLt

theorem byte_values_valid (bytes : List Std.U8) :
    Auths.Codec.BytesValid (bytes.map (·.val)) := by
  intro byte present
  obtain ⟨value, _, rfl⟩ := List.mem_map.mp present
  exact value.bv.isLt

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
    aesop (add safe forward append_result_exact)
      (add safe forward conversion_value)
      (add norm simp [inputFrame, Auths.Crypto.Framing.encode,
        List.map_append, be16_exact, be64_exact,
        hash.SIGNING_PREFIX, auths_model.PROTOCOL_V1,
        alloc.vec.Vec.with_capacity, alloc.vec.Vec.new,
        object_tag, tagValue])


theorem accepted_frame_valid (kind : hash.ObjectType) (profile : Str)
    (version : Std.U16) (statement : Slice Std.U8) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.signing_preimage kind profile version statement = ok (.Ok output)) :
    (inputFrame kind profile version statement).Valid := by
  unfold hash.signing_preimage at accepted
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

theorem byte_values_injective :
    Function.Injective (fun bytes : List Std.U8 => bytes.map (·.val)) := by
  intro left right same
  induction left generalizing right with
  | nil => cases right <;> simp_all
  | cons first tail ih =>
    cases right with
    | nil => simp at same
    | cons next rest =>
      obtain ⟨head, tailEq⟩ := List.cons.inj same
      have equalHead := UScalar.eq_of_val_eq head
      exact congrArg₂ List.cons equalHead (ih tailEq)

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

theorem profile_limit_refused (kind : hash.ObjectType) (profile : Str)
    (version : Std.U16) (statement : Slice Std.U8)
    (oversized : 65535 < profile.val.length) :
    hash.signing_preimage kind profile version statement = ok (.Err error.CodecError.LimitExceeded) := by
  have tooLarge : ¬ (Slice.len profile).val ≤ UScalar.max .U16 := by
    simpa only [Slice.len_val, Slice.length, UScalar.max_UScalarTy_U16_eq, U16.max_eq] using
      Nat.not_le_of_lt oversized
  unfold hash.signing_preimage
  simp only [core.str.Str.len, U16.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from,
    core.num.tryFromUScalar, if_neg tooLarge, bind_tc_ok,
    core.result.Result.map_err, BuiltinFnOnce, error.limit_error,
    core.result.Result.Insts.CoreOpsTry.branch,
    core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
    core.convert.FromSame, core.convert.FromSame.from]


end Auths.Crypto.Refinement


