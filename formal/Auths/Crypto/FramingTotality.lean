import Auths.Crypto.CommitmentValidity
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec Auths.Crypto.Refinement Auths.Crypto.CommitmentRefinement
set_option maxHeartbeats 2000000
set_option maxRecDepth 4096
namespace Auths.Crypto.FramingTotality

@[step] theorem convert_total {source target : UScalarTy} (value : UScalar source) :
    core.num.tryFromUScalar target value ⦃ result =>
      match result with
      | .Ok converted => converted.val = value.val
      | .Err _ => UScalar.max target < value.val ⦄ := by
  unfold core.num.tryFromUScalar
  split
  · rename_i fits
    simp only [spec_ok]
    have contract := UScalar.cast_inBounds_spec target value fits
    simpa only [lift, spec_ok] using contract
  · simp only [spec_ok]
    omega

@[step] theorem append_total (left : alloc.vec.Vec Std.U8) (right : Slice Std.U8)
    (fits : left.val.length + right.val.length ≤ Usize.max) :
    alloc.vec.Vec.extend_from_slice core.clone.CloneU8 left right ⦃ output =>
      output.val = left.val ++ right.val ⦄ := by
  rw [Auths.Codec.Evaluation.append_bytes]
  split
  · simp [spec_ok]
  · simp [fits, spec_ok]

@[step] theorem buffer_total (capacity : Std.Usize) :
    hash.preimage_buffer capacity ⦃ result => match result with
      | .Ok output => output.val = [] ∧ BufferAllocation.Fits capacity
      | .Err reason => reason = .LimitExceeded ∧ ¬ BufferAllocation.Fits capacity ⦄ := by
  rw [BufferAllocation.buffer_refines]
  split <;> simp_all [spec_ok, alloc.vec.Vec.new]

def IdentifierAdmissible (payload : Slice Std.U8) : Prop :=
  payload.val.length ≤ U64.max ∧ 20 + payload.val.length ≤ Usize.max ∧
    (20 + payload.val.length : Int) ≤ Isize.max

def IdentifierResult (payload : Slice Std.U8)
    (result : core.result.Result (alloc.vec.Vec Std.U8) error.CodecError) : Prop :=
  match result with
  | .Ok _ => IdentifierAdmissible payload
  | .Err reason => reason = .LimitExceeded ∧ ¬ IdentifierAdmissible payload

theorem identifier_total (kind : hash.IdentifierType) (payload : Slice Std.U8) :
    hash.identifier_preimage kind payload ⦃ result => IdentifierResult payload result ⦄ := by
  unfold hash.identifier_preimage
  simp only [U64.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from]
  step as ⟨converted, convertedMeaning⟩
  cases converted with
  | Err conversionError =>
    simp only at convertedMeaning
    have refuses : ¬ IdentifierAdmissible payload := by
      intro admitted
      have tooLong : U64.max < payload.val.length := by
        simpa only [Slice.len_val, Slice.length, UScalar.max_UScalarTy_U64_eq] using convertedMeaning
      exact Nat.not_le_of_lt tooLong admitted.1
    simp [core.result.Result.map_err, BuiltinFnOnce, error.limit_error,
      core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, spec_ok, IdentifierResult, refuses]
  | Ok length =>
    simp only [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
      bind_tc_ok]
    step as ⟨four, fourEq⟩
    step as ⟨twelve, twelveEq⟩
    step as ⟨base, baseMeaning⟩
    cases base with
    | none =>
      simp [core.option.Option.and_then, core.option.Option.ok_or,
        core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame.from, bind_tc_ok, spec_ok, IdentifierResult, IdentifierAdmissible]
      simp only [hash.IDENTIFIER_PREFIX, Slice.len_val, Slice.length] at baseMeaning
      scalar_tac
    | some base =>
      simp only [core.option.Option.and_then,
        hash.identifier_preimage.closure.Insts.CoreOpsFunctionFnOnceTupleUsizeOptionUsize,
        hash.identifier_preimage.closure.Insts.CoreOpsFunctionFnOnceTupleUsizeOptionUsize.call_once,
        bind_tc_ok]
      have capacityMeaning := Usize.checked_add_bv_spec base (Slice.len payload)
      generalize capacityEq : Usize.checked_add base (Slice.len payload) = capacity at *
      cases capacity with
      | none =>
        simp [core.option.Option.ok_or, core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
          core.convert.FromSame.from, bind_tc_ok, spec_ok, IdentifierResult, IdentifierAdmissible]
        simp [hash.IDENTIFIER_PREFIX, Slice.len_val, Slice.length] at baseMeaning capacityMeaning
        scalar_tac
      | some capacity =>
        simp only [core.option.Option.ok_or, core.result.Result.Insts.CoreOpsTry.branch,
          bind_tc_ok]
        step as ⟨buffer, bufferMeaning⟩
        cases buffer with
        | Err reason =>
          simp [core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame.from, bind_tc_ok, spec_ok, IdentifierResult, IdentifierAdmissible]
          simp [hash.IDENTIFIER_PREFIX, Slice.len_val, Slice.length, BufferAllocation.Fits] at baseMeaning capacityMeaning bufferMeaning
          scalar_tac
        | Ok buffer =>
          simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
          simp only [Option.some.injEq] at baseMeaning capacityMeaning
          simp only at bufferMeaning
          have overall : 20 + payload.val.length ≤ Usize.max := by
            simp [hash.IDENTIFIER_PREFIX, Slice.len_val, Slice.length] at baseMeaning capacityMeaning
            scalar_tac
          step as ⟨out1, out1Meaning⟩
          simp only [lift, bind_tc_ok, identifier_tag_word]
          have out1Length : out1.val.length = 8 := by
            simp [out1Meaning, bufferMeaning.1, hash.IDENTIFIER_PREFIX]
          step as ⟨out2, out2Meaning⟩
          have out2Length : out2.val.length = 10 := by
            simp [out2Meaning, out1Length]
          step as ⟨out3, out3Meaning⟩
          have out3Length : out3.val.length = 12 := by
            simp [out3Meaning, out2Length]
          step as ⟨out4, out4Meaning⟩
          have out4Length : out4.val.length = 20 := by
            simp [out4Meaning, out3Length]
          step as ⟨out5, out5Meaning⟩
          simp only [spec_ok, IdentifierResult, IdentifierAdmissible]
          simp [hash.IDENTIFIER_PREFIX, Slice.len_val, Slice.length,
            BufferAllocation.Fits, UScalar.max_UScalarTy_U64_eq] at baseMeaning capacityMeaning bufferMeaning convertedMeaning
          constructor
          · scalar_tac
          · exact ⟨overall, by omega⟩

theorem identifier_accepts_iff (kind : hash.IdentifierType) (payload : Slice Std.U8) :
    (∃ output, hash.identifier_preimage kind payload = ok (.Ok output)) ↔
      IdentifierAdmissible payload := by
  obtain ⟨result, evaluated, classified⟩ := spec_imp_exists (identifier_total kind payload)
  cases result with
  | Ok output =>
    constructor
    · intro _; exact classified
    · intro _; exact ⟨output, evaluated⟩
  | Err reason =>
    constructor
    · rintro ⟨output, accepted⟩
      have impossible := evaluated.symm.trans accepted
      cases impossible
    · intro admitted
      exact False.elim (classified.2 admitted)

theorem identifier_refuses_iff (kind : hash.IdentifierType) (payload : Slice Std.U8) :
    hash.identifier_preimage kind payload = ok (.Err error.CodecError.LimitExceeded) ↔
      ¬ IdentifierAdmissible payload := by
  obtain ⟨result, evaluated, classified⟩ := spec_imp_exists (identifier_total kind payload)
  cases result with
  | Ok output =>
    constructor
    · intro refused
      have impossible := evaluated.symm.trans refused
      cases impossible
    · intro outside; exact False.elim (outside classified)
  | Err reason =>
    constructor
    · intro _; exact classified.2
    · intro _
      have exactReason : reason = .LimitExceeded := classified.1
      simpa only [exactReason] using evaluated

def ApplicationAdmissible (domain : Str) (payload : Slice Std.U8) : Prop :=
  0 < domain.val.length ∧ domain.val.length ≤ 128 ∧ payload.val.length ≤ U64.max ∧
    28 + domain.val.length + payload.val.length ≤ Usize.max ∧
    (28 + domain.val.length + payload.val.length : Int) ≤ Isize.max

def ApplicationResult (domain : Str) (payload : Slice Std.U8)
    (result : core.result.Result (alloc.vec.Vec Std.U8) error.CodecError) : Prop :=
  match result with
  | .Ok _ => ApplicationAdmissible domain payload
  | .Err reason => reason = .LimitExceeded ∧ ¬ ApplicationAdmissible domain payload

theorem application_total (domain : Str) (payload : Slice Std.U8) :
    hash.commitment_preimage domain payload ⦃ result => ApplicationResult domain payload result ⦄ := by
  unfold hash.commitment_preimage
  simp only [core.str.Str.as_bytes, core.slice.Slice.is_empty, bind_tc_ok]
  split
  · rename_i empty
    simp only [spec_ok, ApplicationResult, ApplicationAdmissible]
    have emptyLength : domain.val.length = 0 := by simpa [Slice.length] using empty
    simp [emptyLength]
  · rename_i nonempty
    split
    · rename_i oversized
      simp only [spec_ok, ApplicationResult, ApplicationAdmissible]
      simp [hash.MAX_COMMITMENT_DOMAIN_BYTES, Slice.len_val, Slice.length] at oversized
      scalar_tac
    · rename_i bounded
      simp only [U16.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from]
      step as ⟨domainLength, domainMeaning⟩
      cases domainLength with
      | Err conversionError =>
        simp only at domainMeaning
        simp [hash.MAX_COMMITMENT_DOMAIN_BYTES, Slice.len_val, Slice.length] at bounded
        scalar_tac
      | Ok domainLength =>
        simp only [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
          U64.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from]
        have domainPositive : 0 < domain.val.length := by
          change ¬ decide (domain.val.length = 0) = true at nonempty
          have notZero : domain.val.length ≠ 0 := by simpa using nonempty
          omega
        have domainBound : domain.val.length ≤ 128 := by
          simp [hash.MAX_COMMITMENT_DOMAIN_BYTES, Slice.len_val, Slice.length] at bounded
          scalar_tac
        step as ⟨converted, convertedMeaning⟩
        cases converted with
        | Err conversionError =>
          simp only at convertedMeaning
          have refuses : ¬ ApplicationAdmissible domain payload := by
            intro admitted
            have tooLong : U64.max < payload.val.length := by
              simpa only [Slice.len_val, Slice.length, UScalar.max_UScalarTy_U64_eq] using convertedMeaning
            exact Nat.not_le_of_lt tooLong admitted.2.2.1
          simp [core.result.Result.map_err, BuiltinFnOnce, error.limit_error,
            core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame.from, spec_ok, ApplicationResult, refuses]
        | Ok length =>
          simp only [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
          step as ⟨four, fourEq⟩
          step as ⟨twelve, twelveEq⟩
          step as ⟨base, baseMeaning⟩
          cases base with
          | none =>
            simp [core.option.Option.and_then, core.option.Option.ok_or,
              core.result.Result.Insts.CoreOpsTry.branch,
              core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
              core.convert.FromSame.from, spec_ok, ApplicationResult, ApplicationAdmissible]
            simp [hash.COMMITMENT_PREFIX, Slice.len_val, Slice.length] at baseMeaning
            scalar_tac
          | some base =>
            simp only [core.option.Option.and_then,
              hash.commitment_preimage.closure.Insts.CoreOpsFunctionFnOnceTupleUsizeOptionUsize,
              hash.commitment_preimage.closure.Insts.CoreOpsFunctionFnOnceTupleUsizeOptionUsize.call_once,
              bind_tc_ok]
            have domainCapacityMeaning := Usize.checked_add_bv_spec base (Slice.len domain)
            generalize domainCapacityEq : Usize.checked_add base (Slice.len domain) = domainCapacity at *
            cases domainCapacity with
            | none =>
              simp [core.option.Option.and_then, core.option.Option.ok_or,
                core.result.Result.Insts.CoreOpsTry.branch,
                core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                core.convert.FromSame.from, spec_ok, ApplicationResult, ApplicationAdmissible]
              simp [hash.COMMITMENT_PREFIX, Slice.len_val, Slice.length] at baseMeaning domainCapacityMeaning
              scalar_tac
            | some domainCapacity =>
              simp only [core.option.Option.and_then,
                hash.commitment_preimage.closure_1.Insts.CoreOpsFunctionFnOnceTupleUsizeOptionUsize,
                hash.commitment_preimage.closure_1.Insts.CoreOpsFunctionFnOnceTupleUsizeOptionUsize.call_once,
                bind_tc_ok]
              have capacityMeaning := Usize.checked_add_bv_spec domainCapacity (Slice.len payload)
              generalize capacityEq : Usize.checked_add domainCapacity (Slice.len payload) = capacity at *
              cases capacity with
              | none =>
                simp [core.option.Option.ok_or, core.result.Result.Insts.CoreOpsTry.branch,
                  core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                  core.convert.FromSame.from, spec_ok, ApplicationResult, ApplicationAdmissible]
                simp [hash.COMMITMENT_PREFIX, Slice.len_val, Slice.length] at baseMeaning domainCapacityMeaning capacityMeaning
                scalar_tac
              | some capacity =>
                simp only [core.option.Option.ok_or, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                step as ⟨buffer, bufferMeaning⟩
                cases buffer with
                | Err reason =>
                  simp [core.result.Result.Insts.CoreOpsTry.branch,
                    core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                    core.convert.FromSame.from, spec_ok, ApplicationResult, ApplicationAdmissible]
                  simp [hash.COMMITMENT_PREFIX, Slice.len_val, Slice.length, BufferAllocation.Fits] at baseMeaning domainCapacityMeaning capacityMeaning bufferMeaning
                  scalar_tac
                | Ok buffer =>
                  simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                  simp only at bufferMeaning
                  have overall : 28 + domain.val.length + payload.val.length ≤ Usize.max := by
                    simp [hash.COMMITMENT_PREFIX, Slice.len_val, Slice.length] at baseMeaning domainCapacityMeaning capacityMeaning
                    scalar_tac
                  step as ⟨out1, out1Meaning⟩
                  simp only [lift, bind_tc_ok]
                  have out1Length : out1.val.length = 16 := by
                    simp [out1Meaning, bufferMeaning.1, hash.COMMITMENT_PREFIX]
                  step as ⟨out2, out2Meaning⟩
                  have out2Length : out2.val.length = 18 := by simp [out2Meaning, out1Length]
                  step as ⟨out3, out3Meaning⟩
                  have out3Length : out3.val.length = 20 := by simp [out3Meaning, out2Length]
                  step as ⟨out4, out4Meaning⟩
                  have out4Length : out4.val.length = 20 + domain.val.length := by simp [out4Meaning, out3Length]
                  step as ⟨out5, out5Meaning⟩
                  · scalar_tac
                  · have out5Length : out5.val.length = 28 + domain.val.length := by simp [out5Meaning, out4Length]; omega
                    step as ⟨out6, out6Meaning⟩
                    simp only [spec_ok, ApplicationResult, ApplicationAdmissible]
                    simp [hash.COMMITMENT_PREFIX, Slice.len_val, Slice.length, BufferAllocation.Fits] at baseMeaning domainCapacityMeaning capacityMeaning bufferMeaning convertedMeaning
                    refine ⟨domainPositive, domainBound, ?_, overall, ?_⟩
                    · scalar_tac
                    · omega


theorem application_accepts_iff (domain : Str) (payload : Slice Std.U8) :
    (∃ output, hash.commitment_preimage domain payload = ok (.Ok output)) ↔
      ApplicationAdmissible domain payload := by
  obtain ⟨result, evaluated, classified⟩ := spec_imp_exists (application_total domain payload)
  cases result with
  | Ok output =>
    constructor
    · intro _; exact classified
    · intro _; exact ⟨output, evaluated⟩
  | Err reason =>
    constructor
    · rintro ⟨output, accepted⟩
      have impossible := evaluated.symm.trans accepted
      cases impossible
    · intro admitted
      exact False.elim (classified.2 admitted)

theorem application_refuses_iff (domain : Str) (payload : Slice Std.U8) :
    hash.commitment_preimage domain payload = ok (.Err error.CodecError.LimitExceeded) ↔
      ¬ ApplicationAdmissible domain payload := by
  obtain ⟨result, evaluated, classified⟩ := spec_imp_exists (application_total domain payload)
  cases result with
  | Ok output =>
    constructor
    · intro refused
      have impossible := evaluated.symm.trans refused
      cases impossible
    · intro outside; exact False.elim (outside classified)
  | Err reason =>
    constructor
    · intro _; exact classified.2
    · intro _
      have exactReason : reason = .LimitExceeded := classified.1
      simpa only [exactReason] using evaluated


def SigningAdmissible (profile : Str) (payload : Slice Std.U8) : Prop :=
  profile.val.length ≤ U16.max ∧ payload.val.length ≤ U64.max ∧
    21 + profile.val.length + payload.val.length ≤ Usize.max ∧
    (21 + profile.val.length + payload.val.length : Int) ≤ Isize.max

def SigningResult (profile : Str) (payload : Slice Std.U8)
    (result : core.result.Result (alloc.vec.Vec Std.U8) error.CodecError) : Prop :=
  match result with
  | .Ok _ => SigningAdmissible profile payload
  | .Err reason => reason = .LimitExceeded ∧ ¬ SigningAdmissible profile payload

theorem signing_total (kind : hash.ObjectType) (profile : Str) (version : Std.U16)
    (payload : Slice Std.U8) :
    hash.signing_preimage kind profile version payload ⦃ result => SigningResult profile payload result ⦄ := by
  unfold hash.signing_preimage
  simp only [core.str.Str.len, bind_tc_ok,
    U16.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from]
  step as ⟨profileLength, profileMeaning⟩
  cases profileLength with
  | Err conversionError =>
    simp only at profileMeaning
    have refuses : ¬ SigningAdmissible profile payload := by
      intro admitted
      have tooLong : U16.max < profile.val.length := by
        simpa only [Slice.len_val, Slice.length, UScalar.max_UScalarTy_U16_eq] using profileMeaning
      exact Nat.not_le_of_lt tooLong admitted.1
    simp [core.result.Result.map_err, BuiltinFnOnce, error.limit_error,
      core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, spec_ok, SigningResult, refuses]
  | Ok profileLength =>
    simp only [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
      U64.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from]
    step as ⟨converted, convertedMeaning⟩
    cases converted with
    | Err conversionError =>
      simp only at convertedMeaning
      have refuses : ¬ SigningAdmissible profile payload := by
        intro admitted
        have tooLong : U64.max < payload.val.length := by
          simpa only [Slice.len_val, Slice.length, UScalar.max_UScalarTy_U64_eq] using convertedMeaning
        exact Nat.not_le_of_lt tooLong admitted.2.1
      simp [core.result.Result.map_err, BuiltinFnOnce, error.limit_error,
        core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame.from, spec_ok, SigningResult, refuses]
    | Ok length =>
      simp only [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      step as ⟨four, fourEq⟩
      step as ⟨six, sixEq⟩
      step as ⟨eight, eightEq⟩
      step as ⟨sixteen, sixteenEq⟩
      step as ⟨base, baseMeaning⟩
      cases base with
      | none =>
        simp [core.option.Option.ok_or, core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
          core.convert.FromSame.from, spec_ok, SigningResult, SigningAdmissible]
        simp [hash.SIGNING_PREFIX, Slice.len_val, Slice.length] at baseMeaning
        scalar_tac
      | some base =>
        simp only [core.option.Option.ok_or, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
        step as ⟨profileCapacity, profileCapacityMeaning⟩
        cases profileCapacity with
        | none =>
          simp [core.option.Option.ok_or, core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame.from, spec_ok, SigningResult, SigningAdmissible]
          simp [hash.SIGNING_PREFIX, Slice.len_val, Slice.length] at baseMeaning profileCapacityMeaning
          scalar_tac
        | some profileCapacity =>
          simp only [core.option.Option.ok_or, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
          step as ⟨capacity, capacityMeaning⟩
          cases capacity with
          | none =>
            simp [core.option.Option.ok_or, core.result.Result.Insts.CoreOpsTry.branch,
              core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
              core.convert.FromSame.from, spec_ok, SigningResult, SigningAdmissible]
            simp [hash.SIGNING_PREFIX, Slice.len_val, Slice.length] at baseMeaning profileCapacityMeaning capacityMeaning
            scalar_tac
          | some capacity =>
            simp only [core.option.Option.ok_or, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
            step as ⟨buffer, bufferMeaning⟩
            cases buffer with
            | Err reason =>
              simp [core.result.Result.Insts.CoreOpsTry.branch,
                core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                core.convert.FromSame.from, spec_ok, SigningResult, SigningAdmissible]
              simp [hash.SIGNING_PREFIX, Slice.len_val, Slice.length, BufferAllocation.Fits] at baseMeaning profileCapacityMeaning capacityMeaning bufferMeaning
              scalar_tac
            | Ok buffer =>
              simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
              simp only at bufferMeaning
              have overall : 21 + profile.val.length + payload.val.length ≤ Usize.max := by
                simp [hash.SIGNING_PREFIX, Slice.len_val, Slice.length] at baseMeaning profileCapacityMeaning capacityMeaning
                scalar_tac
              step as ⟨out1, out1Meaning⟩
              simp only [lift, bind_tc_ok, object_tag]
              have out1Length : out1.val.length = 5 := by simp [out1Meaning, bufferMeaning.1, hash.SIGNING_PREFIX]
              step as ⟨out2, out2Meaning⟩
              have out2Length : out2.val.length = 7 := by simp [out2Meaning, out1Length]
              step as ⟨out3, out3Meaning⟩
              have out3Length : out3.val.length = 9 := by simp [out3Meaning, out2Length]
              step as ⟨out4, out4Meaning⟩
              · scalar_tac
              · have out4Length : out4.val.length = 11 := by simp [out4Meaning, out3Length]
                simp only [core.str.Str.as_bytes, bind_tc_ok]
                step as ⟨out5, out5Meaning⟩
                have out5Length : out5.val.length = 11 + profile.val.length := by simp [out5Meaning, out4Length]
                step as ⟨out6, out6Meaning⟩
                · scalar_tac
                · have out6Length : out6.val.length = 13 + profile.val.length := by simp [out6Meaning, out5Length]; omega
                  step as ⟨out7, out7Meaning⟩
                  · scalar_tac
                  · have out7Length : out7.val.length = 21 + profile.val.length := by simp [out7Meaning, out6Length]; omega
                    step as ⟨out8, out8Meaning⟩
                    simp only [spec_ok, SigningResult, SigningAdmissible]
                    simp [hash.SIGNING_PREFIX, Slice.len_val, Slice.length, BufferAllocation.Fits] at baseMeaning profileCapacityMeaning capacityMeaning bufferMeaning profileMeaning convertedMeaning
                    refine ⟨?_, ?_, overall, ?_⟩
                    · scalar_tac
                    · scalar_tac
                    · omega


theorem signing_accepts_iff (kind : hash.ObjectType) (profile : Str) (version : Std.U16)
    (payload : Slice Std.U8) :
    (∃ output, hash.signing_preimage kind profile version payload = ok (.Ok output)) ↔
      SigningAdmissible profile payload := by
  obtain ⟨result, evaluated, classified⟩ := spec_imp_exists (signing_total kind profile version payload)
  cases result with
  | Ok output =>
    constructor
    · intro _; exact classified
    · intro _; exact ⟨output, evaluated⟩
  | Err reason =>
    constructor
    · rintro ⟨output, accepted⟩
      have impossible := evaluated.symm.trans accepted
      cases impossible
    · intro admitted
      exact False.elim (classified.2 admitted)

theorem signing_refuses_iff (kind : hash.ObjectType) (profile : Str) (version : Std.U16)
    (payload : Slice Std.U8) :
    hash.signing_preimage kind profile version payload = ok (.Err error.CodecError.LimitExceeded) ↔
      ¬ SigningAdmissible profile payload := by
  obtain ⟨result, evaluated, classified⟩ := spec_imp_exists (signing_total kind profile version payload)
  cases result with
  | Ok output =>
    constructor
    · intro refused
      have impossible := evaluated.symm.trans refused
      cases impossible
    · intro outside; exact False.elim (outside classified)
  | Err reason =>
    constructor
    · intro _; exact classified.2
    · intro _
      have exactReason : reason = .LimitExceeded := classified.1
      simpa only [exactReason] using evaluated



end Auths.Crypto.FramingTotality
