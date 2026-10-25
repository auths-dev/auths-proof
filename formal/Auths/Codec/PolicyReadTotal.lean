import Auths.Codec.PolicyAccepted

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Codec.PolicyReadTotal
open Auths.Codec.Refinement Auths.Crypto

set_option maxHeartbeats 3000000
set_option maxRecDepth 4096

/- Typed logical termination is established from actual primitive/source calls
and then upgraded with accepted-value closure. No successful parser, expected
intermediate value, trusted termination flag or caller-supplied hash result is
an input. Abstract work/allocation and physical runtime remain separate. -/

@[step] theorem commitment_terminates (self : cbor.Decoder) :
    bounded_policy.commitment self ⦃ _ => True ⦄ := by
  unfold bounded_policy.commitment
  simp only [auths_model.bounded_policy.MAX_POLICY_IDENTIFIER_BYTES,
    auths_model.bounded_policy.MAX_POLICY_CANONICALIZATION_BYTES, bind_tc_ok]
  obtain ⟨⟨result0, state0⟩, run0, meaning0⟩ := spec_imp_exists (ProtocolFields.map_exact self 5#u64)
  rw [run0]
  cases result0 with
  | Err error =>
    simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
        error.CodecError.Insts.CoreConvertFromModelError.from,
        core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
  | Ok value0 =>
    simp only [core.result.Result.map_err, BuiltinFnOnce,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    obtain ⟨⟨result1, state1⟩, run1, meaning1⟩ := spec_imp_exists (ProtocolFields.key_exact state0 0#u8)
    rw [run1]
    cases result1 with
    | Err error =>
      simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
          error.CodecError.Insts.CoreConvertFromModelError.from,
          core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
          core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
    | Ok value1 =>
      simp only [core.result.Result.map_err, BuiltinFnOnce,
        core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      obtain ⟨⟨result2, state2⟩, run2, meaning2⟩ := spec_imp_exists (ProtocolFields.text_exact state1)
      rw [run2]
      cases result2 with
      | Err error =>
        simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
            error.CodecError.Insts.CoreConvertFromModelError.from,
            core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
      | Ok value2 =>
        simp only [core.result.Result.map_err, BuiltinFnOnce,
          core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
        have utf8Type := ProtocolStrings.text_valid state1 state2 value2 run2
        obtain ⟨result3, run3, meaning3⟩ := spec_imp_exists (PolicyAccepted.identifier_total value2 128#usize utf8Type)
        rw [run3]
        cases result3 with
        | Err error =>
          simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
              error.CodecError.Insts.CoreConvertFromModelError.from,
              core.result.Result.Insts.CoreOpsTry.branch,
              core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
              core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
        | Ok value3 =>
          simp only [core.result.Result.map_err, BuiltinFnOnce,
            core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
          obtain ⟨⟨result4, state4⟩, run4, meaning4⟩ := spec_imp_exists (ProtocolFields.key_exact state2 1#u8)
          rw [run4]
          cases result4 with
          | Err error =>
            simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                error.CodecError.Insts.CoreConvertFromModelError.from,
                core.result.Result.Insts.CoreOpsTry.branch,
                core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
          | Ok value4 =>
            simp only [core.result.Result.map_err, BuiltinFnOnce,
              core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
            obtain ⟨⟨result5, state5⟩, run5, meaning5⟩ := spec_imp_exists (ProtocolCursor.u16_exact state4)
            rw [run5]
            cases result5 with
            | Err error =>
              simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                  error.CodecError.Insts.CoreConvertFromModelError.from,
                  core.result.Result.Insts.CoreOpsTry.branch,
                  core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                  core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
            | Ok value5 =>
              simp only [core.result.Result.map_err, BuiltinFnOnce,
                core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
              obtain ⟨⟨result6, state6⟩, run6, meaning6⟩ := spec_imp_exists (ProtocolFields.key_exact state5 2#u8)
              rw [run6]
              cases result6 with
              | Err error =>
                simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                    error.CodecError.Insts.CoreConvertFromModelError.from,
                    core.result.Result.Insts.CoreOpsTry.branch,
                    core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                    core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
              | Ok value6 =>
                simp only [core.result.Result.map_err, BuiltinFnOnce,
                  core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                obtain ⟨⟨result7, state7⟩, run7, meaning7⟩ := spec_imp_exists (ProtocolFields.text_exact state6)
                rw [run7]
                cases result7 with
                | Err error =>
                  simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                      error.CodecError.Insts.CoreConvertFromModelError.from,
                      core.result.Result.Insts.CoreOpsTry.branch,
                      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                      core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
                | Ok value7 =>
                  simp only [core.result.Result.map_err, BuiltinFnOnce,
                    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                  have utf8Canonicalization := ProtocolStrings.text_valid state6 state7 value7 run7
                  obtain ⟨result8, run8, meaning8⟩ := spec_imp_exists (PolicyAccepted.identifier_total value7 64#usize utf8Canonicalization)
                  rw [run8]
                  cases result8 with
                  | Err error =>
                    simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                        error.CodecError.Insts.CoreConvertFromModelError.from,
                        core.result.Result.Insts.CoreOpsTry.branch,
                        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                        core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
                  | Ok value8 =>
                    simp only [core.result.Result.map_err, BuiltinFnOnce,
                      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                    obtain ⟨⟨result9, state9⟩, run9, meaning9⟩ := spec_imp_exists (ProtocolFields.key_exact state7 3#u8)
                    rw [run9]
                    cases result9 with
                    | Err error =>
                      simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                          error.CodecError.Insts.CoreConvertFromModelError.from,
                          core.result.Result.Insts.CoreOpsTry.branch,
                          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                          core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
                    | Ok value9 =>
                      simp only [core.result.Result.map_err, BuiltinFnOnce,
                        core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                      obtain ⟨⟨result10, state10⟩, run10, meaning10⟩ := spec_imp_exists (ProtocolFields.digest_bytes_exact state9)
                      rw [run10]
                      cases result10 with
                      | Err error =>
                        simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                            error.CodecError.Insts.CoreConvertFromModelError.from,
                            core.result.Result.Insts.CoreOpsTry.branch,
                            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                            core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
                      | Ok value10 =>
                        simp only [core.result.Result.map_err, BuiltinFnOnce,
                          core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                        simp only [auths_model.Digest.new, bind_tc_ok]
                        obtain ⟨⟨result11, state11⟩, run11, meaning11⟩ := spec_imp_exists (ProtocolFields.key_exact state10 4#u8)
                        rw [run11]
                        cases result11 with
                        | Err error =>
                          simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                              error.CodecError.Insts.CoreConvertFromModelError.from,
                              core.result.Result.Insts.CoreOpsTry.branch,
                              core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                              core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
                        | Ok value11 =>
                          simp only [core.result.Result.map_err, BuiltinFnOnce,
                            core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                          obtain ⟨⟨result12, state12⟩, run12, meaning12⟩ := spec_imp_exists (ProtocolFields.text_exact state11)
                          rw [run12]
                          cases result12 with
                          | Err error =>
                            simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                                error.CodecError.Insts.CoreConvertFromModelError.from,
                                core.result.Result.Insts.CoreOpsTry.branch,
                                core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                                core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
                          | Ok value12 =>
                            simp only [core.result.Result.map_err, BuiltinFnOnce,
                              core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                            have utf8Evaluator := ProtocolStrings.text_valid state11 state12 value12 run12
                            obtain ⟨result13, run13, meaning13⟩ := spec_imp_exists (PolicyAccepted.identifier_total value12 128#usize utf8Evaluator)
                            rw [run13]
                            cases result13 with
                            | Err error =>
                              simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                                  error.CodecError.Insts.CoreConvertFromModelError.from,
                                  core.result.Result.Insts.CoreOpsTry.branch,
                                  core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                                  core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
                            | Ok value13 =>
                              simp only [core.result.Result.map_err, BuiltinFnOnce,
                                core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                              let prototype : auths_model.bounded_policy.PolicyCommitment := ⟨value3, value5, value8, value10, value13⟩
                              have carriers : BoundedPolicyWriters.Fields prototype := by
                                have typeBound := meaning3.1.2
                                have canonicalizationBound := meaning8.1.2
                                have evaluatorBound := meaning13.1.2
                                constructor <;> scalar_tac
                              rw [PolicyConstructors.commitment_exact prototype carriers]
                              by_cases dimensions : PolicyValidity.CommitmentDimensions prototype <;>
                                simp [dimensions, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                                    error.CodecError.Insts.CoreConvertFromModelError.from,
                                    core.result.Result.Insts.CoreOpsTry.branch,
                                    core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                                    core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]

@[step] theorem commitment_total (self : cbor.Decoder) :
    bounded_policy.commitment self ⦃ actual =>
      match actual.1 with | .Err _ => True | .Ok value => PolicyValidity.Commitment value ⦄ := by
  obtain ⟨⟨verdict, next⟩, run, terminal⟩ := spec_imp_exists (commitment_terminates self)
  rw [run, spec_ok]
  cases verdict with
  | Err reason => trivial
  | Ok value => exact PolicyAccepted.commitment_valid self next value run

@[step] theorem parent_terminates (self : cbor.Decoder) :
    bounded_policy.parent_digest self ⦃ _ => True ⦄ := by
  unfold bounded_policy.parent_digest
  obtain ⟨probe, probeRun, probeMeaning⟩ := spec_imp_exists (ProtocolFields.is_null_exact self)
  rw [probeRun]
  cases probe with
  | Err error => simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
      error.CodecError.Insts.CoreConvertFromModelError.from,
      core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
  | Ok isNull =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    cases isNull with
    | false =>
      obtain ⟨⟨digest, next⟩, digestRun, digestMeaning⟩ := spec_imp_exists (ProtocolFields.digest_bytes_exact self)
      simp only [Bool.false_eq_true, ↓reduceIte, digestRun, bind_tc_ok]
      cases digest <;> simp [auths_model.Digest.new, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
      error.CodecError.Insts.CoreConvertFromModelError.from,
      core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
    | true =>
      obtain ⟨⟨verdict, next⟩, nullRun, nullMeaning⟩ := spec_imp_exists (ProtocolFields.null_exact self)
      simp only [↓reduceIte, nullRun, bind_tc_ok]
      cases verdict <;> simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
      error.CodecError.Insts.CoreConvertFromModelError.from,
      core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]

@[step] theorem body_constructor_total (value : auths_model.bounded_policy.BoundedPolicyCommitment)
    (commitment : PolicyValidity.Commitment value.commitment) :
    auths_model.bounded_policy.BoundedPolicyCommitment.new value.commitment value.policy value.parent ⦃ result =>
      match result with | .Err _ => True | .Ok body => PolicyValidity.Body body ⦄ := by
  rw [PolicyConstructors.body_exact value]
  by_cases empty : value.policy.val = []
  · simp [empty, spec_ok]
  · by_cases bounded : value.policy.val.length ≤ 4096
    · simp only [if_neg empty, if_pos bounded, spec_ok]
      exact ⟨commitment, empty, bounded⟩
    · simp [empty, bounded, spec_ok]

theorem body_error_exact (reason : auths_model.ModelError) :
    bounded_policy.body_error reason = ok
      (match reason with | .CollectionLimitExceeded => .LimitExceeded | other => .Model other) := by
  cases reason <;> rfl

/-- The public byte guard rejects before parsing, allocation or hashing. The
source equation does not need a SHA contract because the guard returns first. -/
theorem decoder_oversize [primitive : Sha256Primitives] (input : Slice Std.U8)
    (oversize : 65536 < input.val.length) :
    bounded_policy.decode_bounded_policy_commitment input = ok (.Err .LimitExceeded) := by
  unfold bounded_policy.decode_bounded_policy_commitment
  rw [PolicyInverse.extension_limit]
  simp only [bind_tc_ok]
  have overflow : 65536#usize < input.len := by
    simp only [Slice.len]
    scalar_tac
  simp [overflow]

@[step] theorem decoder_terminates [primitive : Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : FramedHash.Contract sha256) (input : Slice Std.U8) :
    bounded_policy.decode_bounded_policy_commitment input ⦃ _ => True ⦄ := by
  unfold bounded_policy.decode_bounded_policy_commitment
  rw [PolicyInverse.extension_limit]
  simp only [bind_tc_ok]
  by_cases overflow : 65536#usize < input.len
  · simp [overflow, spec_ok]
  · simp only [overflow, ↓reduceIte]
    obtain ⟨decoder, decoderRun, initial⟩ := spec_imp_exists (ProtocolCursor.new_exact input)
    rw [decoderRun, bind_tc_ok]
    simp only [auths_model.bounded_policy.MAX_BOUNDED_POLICY_BYTES, bind_tc_ok]
    obtain ⟨⟨result0, state0⟩, run0, meaning0⟩ := spec_imp_exists (ProtocolFields.map_exact decoder 3#u64)
    rw [run0]
    cases result0 with
    | Err error =>
      simp [body_error_exact, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
          error.CodecError.Insts.CoreConvertFromModelError.from,
          core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
          core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
    | Ok value0 =>
      simp only [core.result.Result.map_err, BuiltinFnOnce,
        core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      obtain ⟨⟨result1, state1⟩, run1, meaning1⟩ := spec_imp_exists (ProtocolFields.key_exact state0 0#u8)
      rw [run1]
      cases result1 with
      | Err error =>
        simp [body_error_exact, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
            error.CodecError.Insts.CoreConvertFromModelError.from,
            core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
      | Ok value1 =>
        simp only [core.result.Result.map_err, BuiltinFnOnce,
          core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
        obtain ⟨⟨result2, state2⟩, run2, meaning2⟩ := spec_imp_exists (commitment_total state1)
        rw [run2]
        cases result2 with
        | Err error =>
          simp [body_error_exact, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
              error.CodecError.Insts.CoreConvertFromModelError.from,
              core.result.Result.Insts.CoreOpsTry.branch,
              core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
              core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
        | Ok value2 =>
          simp only [core.result.Result.map_err, BuiltinFnOnce,
            core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
          obtain ⟨⟨result3, state3⟩, run3, meaning3⟩ := spec_imp_exists (ProtocolFields.key_exact state2 1#u8)
          rw [run3]
          cases result3 with
          | Err error =>
            simp [body_error_exact, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                error.CodecError.Insts.CoreConvertFromModelError.from,
                core.result.Result.Insts.CoreOpsTry.branch,
                core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
          | Ok value3 =>
            simp only [core.result.Result.map_err, BuiltinFnOnce,
              core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
            obtain ⟨⟨result4, state4⟩, run4, meaning4⟩ := spec_imp_exists (ProtocolFields.bounded_bytes_exact state3 4096#usize false)
            rw [run4]
            cases result4 with
            | Err error =>
              simp [body_error_exact, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                  error.CodecError.Insts.CoreConvertFromModelError.from,
                  core.result.Result.Insts.CoreOpsTry.branch,
                  core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                  core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
            | Ok value4 =>
              simp only [core.result.Result.map_err, BuiltinFnOnce,
                core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
              obtain ⟨⟨result5, state5⟩, run5, meaning5⟩ := spec_imp_exists (ProtocolFields.key_exact state4 2#u8)
              rw [run5]
              cases result5 with
              | Err error =>
                simp [body_error_exact, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                    error.CodecError.Insts.CoreConvertFromModelError.from,
                    core.result.Result.Insts.CoreOpsTry.branch,
                    core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                    core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
              | Ok value5 =>
                simp only [core.result.Result.map_err, BuiltinFnOnce,
                  core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                obtain ⟨⟨result6, state6⟩, run6, meaning6⟩ := spec_imp_exists (parent_terminates state5)
                rw [run6]
                cases result6 with
                | Err error =>
                  simp [body_error_exact, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                      error.CodecError.Insts.CoreConvertFromModelError.from,
                      core.result.Result.Insts.CoreOpsTry.branch,
                      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                      core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
                | Ok value6 =>
                  simp only [core.result.Result.map_err, BuiltinFnOnce,
                    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                  obtain ⟨result7, run7, meaning7⟩ := spec_imp_exists (ProtocolCursor.ensure_complete_exact state6 input)
                  rw [run7]
                  cases result7 with
                  | Err error =>
                    simp [body_error_exact, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                        error.CodecError.Insts.CoreConvertFromModelError.from,
                        core.result.Result.Insts.CoreOpsTry.branch,
                        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                        core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
                  | Ok value7 =>
                    simp only [core.result.Result.map_err, BuiltinFnOnce,
                      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                    let prototype : auths_model.bounded_policy.BoundedPolicyCommitment := ⟨value2, value4, value6⟩
                    obtain ⟨result8, run8, meaning8⟩ := spec_imp_exists (body_constructor_total prototype meaning2)
                    rw [run8]
                    cases result8 with
                    | Err error =>
                      simp [body_error_exact, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                          error.CodecError.Insts.CoreConvertFromModelError.from,
                          core.result.Result.Insts.CoreOpsTry.branch,
                          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                          core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
                    | Ok value8 =>
                      simp only [core.result.Result.map_err, BuiltinFnOnce,
                        core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                      obtain ⟨encoded, encoderRun, encoderMeaning⟩ := SigningObjectWriters.encoder_success
                        (PolicyConstructors.body_encoder_valid value8 meaning8)
                      rw [encoderRun]
                      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                      obtain ⟨result9, run9, meaning9⟩ := spec_imp_exists (ProtocolCanonical.accept_exact input encoded value8)
                      rw [run9]
                      cases result9 with
                      | Err error =>
                        simp [body_error_exact, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                            error.CodecError.Insts.CoreConvertFromModelError.from,
                            core.result.Result.Insts.CoreOpsTry.branch,
                            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                            core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
                      | Ok value9 =>
                        simp only [core.result.Result.map_err, BuiltinFnOnce,
                          core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                        have sameBody := (ProtocolCanonical.accepted_preserves input encoded value8 value9 run9).2
                        have gateValid : PolicyValidity.Body value9 := by simpa only [← sameBody] using meaning8
                        apply spec_mono (PolicyCanonical.checked_total sha256 contract value9 gateValid)
                        intro result classification
                        trivial

@[step] theorem decoder_total [primitive : Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : FramedHash.Contract sha256) (input : Slice Std.U8) :
    bounded_policy.decode_bounded_policy_commitment input ⦃ result =>
      match result with
      | .Err _ => True
      | .Ok carrier => ∃ value encoded, canonical_value.Canonical.as_value carrier = ok value ∧
          PolicyValidity.Body value ∧ PolicyValidity.Opening sha256 value ∧
          bounded_policy.encode_bounded_policy_commitment carrier = ok (.Ok encoded) ∧
          encoded.val = input.val ∧ byteList input.val = BoundedPolicyObjects.body value ⦄ := by
  obtain ⟨result, run, terminal⟩ := spec_imp_exists (decoder_terminates sha256 contract input)
  rw [run, spec_ok]
  cases result with
  | Err reason => trivial
  | Ok carrier => exact PolicyAccepted.decoder_closed sha256 contract input carrier run

end Auths.Codec.PolicyReadTotal
