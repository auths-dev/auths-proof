import Auths.Codec.PolicyReadTotal
import Auths.Codec.ProtocolReaderBounds

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Codec.PolicyCursor
open Auths.Codec.Refinement Auths.Crypto

set_option maxHeartbeats 3000000
set_option maxRecDepth 4096

/- Actual intermediate decoder frames, including the error that stops parsing.
The whole source reader is unfolded; no final successful parse or expected
intermediate decoder is supplied as a premise. -/
@[step] theorem commitment_frame (self : cbor.Decoder)
    (within : self.position.val ≤ self.input.val.length) :
    bounded_policy.commitment self ⦃ actual => ProtocolReaderBounds.Frame self actual.2 ⦄ := by
  unfold bounded_policy.commitment
  simp only [auths_model.bounded_policy.MAX_POLICY_IDENTIFIER_BYTES,
    auths_model.bounded_policy.MAX_POLICY_CANONICALIZATION_BYTES, bind_tc_ok]
  obtain ⟨⟨result0, state0⟩, run0, meaning0⟩ := spec_imp_exists (ProtocolReaderBounds.source_map self 5#u64 within)
  have frame0 : ProtocolReaderBounds.Frame self state0 := meaning0
  rw [run0]
  cases result0 with
  | Err error =>
    simp [frame0, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
        error.CodecError.Insts.CoreConvertFromModelError.from,
        core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
  | Ok value0 =>
    simp only [core.result.Result.map_err, BuiltinFnOnce,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    obtain ⟨⟨result1, state1⟩, run1, meaning1⟩ := spec_imp_exists (ProtocolReaderBounds.source_key state0 0#u8 (ProtocolReaderBounds.frame_within self state0 frame0))
    have frame1 : ProtocolReaderBounds.Frame self state1 := ProtocolReaderBounds.frame_trans self state0 state1 frame0 meaning1
    rw [run1]
    cases result1 with
    | Err error =>
      simp [frame1, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
          error.CodecError.Insts.CoreConvertFromModelError.from,
          core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
          core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
    | Ok value1 =>
      simp only [core.result.Result.map_err, BuiltinFnOnce,
        core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      obtain ⟨⟨result2, state2⟩, run2, meaning2⟩ := spec_imp_exists (ProtocolReaderBounds.source_text state1 (ProtocolReaderBounds.frame_within self state1 frame1))
      have frame2 : ProtocolReaderBounds.Frame self state2 := ProtocolReaderBounds.frame_trans self state1 state2 frame1 meaning2
      rw [run2]
      cases result2 with
      | Err error =>
        simp [frame2, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
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
          simp [frame2, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
              error.CodecError.Insts.CoreConvertFromModelError.from,
              core.result.Result.Insts.CoreOpsTry.branch,
              core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
              core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
        | Ok value3 =>
          simp only [core.result.Result.map_err, BuiltinFnOnce,
            core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
          obtain ⟨⟨result4, state4⟩, run4, meaning4⟩ := spec_imp_exists (ProtocolReaderBounds.source_key state2 1#u8 (ProtocolReaderBounds.frame_within self state2 frame2))
          have frame4 : ProtocolReaderBounds.Frame self state4 := ProtocolReaderBounds.frame_trans self state2 state4 frame2 meaning4
          rw [run4]
          cases result4 with
          | Err error =>
            simp [frame4, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                error.CodecError.Insts.CoreConvertFromModelError.from,
                core.result.Result.Insts.CoreOpsTry.branch,
                core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
          | Ok value4 =>
            simp only [core.result.Result.map_err, BuiltinFnOnce,
              core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
            obtain ⟨⟨result5, state5⟩, run5, meaning5⟩ := spec_imp_exists (ProtocolReaderBounds.source_u16 state4 (ProtocolReaderBounds.frame_within self state4 frame4))
            have frame5 : ProtocolReaderBounds.Frame self state5 := ProtocolReaderBounds.frame_trans self state4 state5 frame4 meaning5.1
            rw [run5]
            cases result5 with
            | Err error =>
              simp [frame5, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                  error.CodecError.Insts.CoreConvertFromModelError.from,
                  core.result.Result.Insts.CoreOpsTry.branch,
                  core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                  core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
            | Ok value5 =>
              simp only [core.result.Result.map_err, BuiltinFnOnce,
                core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
              obtain ⟨⟨result6, state6⟩, run6, meaning6⟩ := spec_imp_exists (ProtocolReaderBounds.source_key state5 2#u8 (ProtocolReaderBounds.frame_within self state5 frame5))
              have frame6 : ProtocolReaderBounds.Frame self state6 := ProtocolReaderBounds.frame_trans self state5 state6 frame5 meaning6
              rw [run6]
              cases result6 with
              | Err error =>
                simp [frame6, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                    error.CodecError.Insts.CoreConvertFromModelError.from,
                    core.result.Result.Insts.CoreOpsTry.branch,
                    core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                    core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
              | Ok value6 =>
                simp only [core.result.Result.map_err, BuiltinFnOnce,
                  core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                obtain ⟨⟨result7, state7⟩, run7, meaning7⟩ := spec_imp_exists (ProtocolReaderBounds.source_text state6 (ProtocolReaderBounds.frame_within self state6 frame6))
                have frame7 : ProtocolReaderBounds.Frame self state7 := ProtocolReaderBounds.frame_trans self state6 state7 frame6 meaning7
                rw [run7]
                cases result7 with
                | Err error =>
                  simp [frame7, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
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
                    simp [frame7, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                        error.CodecError.Insts.CoreConvertFromModelError.from,
                        core.result.Result.Insts.CoreOpsTry.branch,
                        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                        core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
                  | Ok value8 =>
                    simp only [core.result.Result.map_err, BuiltinFnOnce,
                      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                    obtain ⟨⟨result9, state9⟩, run9, meaning9⟩ := spec_imp_exists (ProtocolReaderBounds.source_key state7 3#u8 (ProtocolReaderBounds.frame_within self state7 frame7))
                    have frame9 : ProtocolReaderBounds.Frame self state9 := ProtocolReaderBounds.frame_trans self state7 state9 frame7 meaning9
                    rw [run9]
                    cases result9 with
                    | Err error =>
                      simp [frame9, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                          error.CodecError.Insts.CoreConvertFromModelError.from,
                          core.result.Result.Insts.CoreOpsTry.branch,
                          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                          core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
                    | Ok value9 =>
                      simp only [core.result.Result.map_err, BuiltinFnOnce,
                        core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                      obtain ⟨⟨result10, state10⟩, run10, meaning10⟩ := spec_imp_exists (ProtocolReaderBounds.source_digest state9 (ProtocolReaderBounds.frame_within self state9 frame9))
                      have frame10 : ProtocolReaderBounds.Frame self state10 := ProtocolReaderBounds.frame_trans self state9 state10 frame9 meaning10
                      rw [run10]
                      cases result10 with
                      | Err error =>
                        simp [frame10, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                            error.CodecError.Insts.CoreConvertFromModelError.from,
                            core.result.Result.Insts.CoreOpsTry.branch,
                            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                            core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
                      | Ok value10 =>
                        simp only [core.result.Result.map_err, BuiltinFnOnce,
                          core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                        simp only [auths_model.Digest.new, bind_tc_ok]
                        obtain ⟨⟨result11, state11⟩, run11, meaning11⟩ := spec_imp_exists (ProtocolReaderBounds.source_key state10 4#u8 (ProtocolReaderBounds.frame_within self state10 frame10))
                        have frame11 : ProtocolReaderBounds.Frame self state11 := ProtocolReaderBounds.frame_trans self state10 state11 frame10 meaning11
                        rw [run11]
                        cases result11 with
                        | Err error =>
                          simp [frame11, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                              error.CodecError.Insts.CoreConvertFromModelError.from,
                              core.result.Result.Insts.CoreOpsTry.branch,
                              core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                              core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
                        | Ok value11 =>
                          simp only [core.result.Result.map_err, BuiltinFnOnce,
                            core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                          obtain ⟨⟨result12, state12⟩, run12, meaning12⟩ := spec_imp_exists (ProtocolReaderBounds.source_text state1 (ProtocolReaderBounds.frame_within self state1 frame1)1)
                          have frame12 : ProtocolReaderBounds.Frame self state12 := ProtocolReaderBounds.frame_trans self state11 state12 frame11 meaning12
                          rw [run12]
                          cases result12 with
                          | Err error =>
                            simp [frame12, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
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
                              simp [frame12, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
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
                                simp [frame12, dimensions, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                                    error.CodecError.Insts.CoreConvertFromModelError.from,
                                    core.result.Result.Insts.CoreOpsTry.branch,
                                    core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                                    core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]

@[step] theorem commitment_bounded (self : cbor.Decoder)
    (within : self.position.val ≤ self.input.val.length) :
    bounded_policy.commitment self ⦃ actual => ProtocolReaderBounds.Frame self actual.2 ∧
      match actual.1 with | .Err _ => True | .Ok value => PolicyValidity.Commitment value ⦄ := by
  obtain ⟨⟨result, next⟩, run, frame⟩ := spec_imp_exists (commitment_frame self within)
  rw [run, spec_ok]
  refine ⟨frame, ?_⟩
  cases result with
  | Err reason => trivial
  | Ok value => exact PolicyAccepted.commitment_valid self next value run

@[step] theorem parent_frame (self : cbor.Decoder)
    (within : self.position.val ≤ self.input.val.length) :
    bounded_policy.parent_digest self ⦃ actual => ProtocolReaderBounds.Frame self actual.2 ⦄ := by
  unfold bounded_policy.parent_digest
  obtain ⟨probe, probeRun, probeMeaning⟩ := spec_imp_exists (ProtocolFields.is_null_exact self)
  rw [probeRun]
  cases probe with
  | Err reason =>
    have unchanged := ProtocolReaderBounds.frame_refl self within
    simp [unchanged, core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
      core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
  | Ok isNull =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    cases isNull with
    | false =>
      obtain ⟨⟨digest, next⟩, digestRun, frame⟩ :=
        spec_imp_exists (ProtocolReaderBounds.source_digest self within)
      simp only [Bool.false_eq_true, ↓reduceIte, digestRun, bind_tc_ok]
      cases digest <;> simp [frame, auths_model.Digest.new, core.result.Result.map_err,
        BuiltinFnOnce, decode.decode_error, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
    | true =>
      obtain ⟨⟨verdict, next⟩, nullRun, frame⟩ :=
        spec_imp_exists (ProtocolReaderBounds.source_null self within)
      simp only [↓reduceIte, nullRun, bind_tc_ok]
      cases verdict <;> simp [frame, core.result.Result.map_err, BuiltinFnOnce,
        decode.decode_error, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]

end Auths.Codec.PolicyCursor

