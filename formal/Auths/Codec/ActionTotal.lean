import Auths.Codec.DecoderContracts
import Auths.Codec.AttachmentDecode
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.ActionTotal
open ProtocolEncode DecodedFields ActionDecodedFields DecoderContracts

/-- Every represented input and limit record returns a typed codec result.
No successful-parse, expected-result, honest-input or caller field-validity
premise is assumed. Primitive-library/compiler contracts remain explicit in
the repository's existing translation qualification boundary. -/
@[step] theorem decode_total (input : Slice Std.U8) (limits : auths_codec.auths_model.VerifierLimits) :
    decode.decode_canonical_action input limits ⦃ _ => True ⦄ := by
  unfold decode.decode_canonical_action canonical.accept canonical.accept_with_error
  step with Limits.validate_exact as ⟨limitResult, limitMeaning⟩
  cases limitResult with
  | Err error =>
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      error.CodecError.Insts.CoreConvertFromModelError.from]
  | Ok _ =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
      auths_model.VerifierLimits.get]
    split
    · simp
    · step with Cursor.new_exact as ⟨decoder, inputSame, startsAtZero⟩
      step with Fields.map_exact decoder 6#u64 as ⟨map, decoder0, mapMeaning, mapInput⟩
      cases map with
      | Err error =>
        simp [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual, core.convert.FromSame.from, error.CodecError.Insts.CoreConvertFromModelError.from]
      | Ok _ =>
        simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
        step with Fields.key_exact decoder0 0#u8 as ⟨key0, decoder1, key0Meaning, key0Input⟩
        cases key0 with
        | Err error =>
          simp [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual, core.convert.FromSame.from, error.CodecError.Insts.CoreConvertFromModelError.from]
        | Ok _ =>
          simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
          step with DecodedFields.profile_success_valid decoder1 as ⟨profileResult, decoder2, profileChecked⟩
          cases profileResult with
          | Err error =>
            simp [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual, core.convert.FromSame.from, error.CodecError.Insts.CoreConvertFromModelError.from]
          | Ok profile =>
            simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
            have profileValid := profileChecked profile rfl
            step with Fields.key_exact decoder2 1#u8 as ⟨key1, decoder3, key1Meaning, key1Input⟩
            cases key1 with
            | Err error =>
              simp [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual, core.convert.FromSame.from, error.CodecError.Insts.CoreConvertFromModelError.from]
            | Ok _ =>
              simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
              step with DecoderContracts.text_checked decoder3 as ⟨textResult, decoder4, textChecked⟩
              cases textResult with
              | Err error =>
                simp [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual, core.convert.FromSame.from, error.CodecError.Insts.CoreConvertFromModelError.from]
              | Ok text =>
                simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                have textUtf8 := textChecked text rfl
                step with DecoderContracts.media_checked text textUtf8 as ⟨mediaResult, mediaChecked⟩
                simp only [core.result.Result.map_err, bind_tc_ok]
                cases mediaResult with
                | Err error =>
                  simp [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual, core.convert.FromSame.from, error.CodecError.Insts.CoreConvertFromModelError.from]
                | Ok media =>
                  simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                  have mediaValid := mediaChecked media rfl
                  step with Fields.key_exact decoder4 2#u8 as ⟨key2, decoder5, key2Meaning, key2Input⟩
                  cases key2 with
                  | Err error =>
                    simp [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual, core.convert.FromSame.from, error.CodecError.Insts.CoreConvertFromModelError.from]
                  | Ok _ =>
                    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                    simp only [auths_model.VerifierLimits.get, bind_tc_ok]
                    step with Fields.bounded_bytes_exact decoder5 limits.canonical_body_bytes true as ⟨bodyResult, decoder6, bodyMeaning, bodyInput⟩
                    cases bodyResult with
                    | Err error =>
                      simp [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual, core.convert.FromSame.from, error.CodecError.Insts.CoreConvertFromModelError.from]
                    | Ok body =>
                      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                      step with Fields.key_exact decoder6 3#u8 as ⟨key3, decoder7, key3Meaning, key3Input⟩
                      cases key3 with
                      | Err error =>
                        simp [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual, core.convert.FromSame.from, error.CodecError.Insts.CoreConvertFromModelError.from]
                      | Ok _ =>
                        simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                        step with DecodedFields.permission_success_valid decoder7 as ⟨permissionResult, decoder8, permissionChecked⟩
                        cases permissionResult with
                        | Err error =>
                          simp [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual, core.convert.FromSame.from, error.CodecError.Insts.CoreConvertFromModelError.from]
                        | Ok permission =>
                          simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                          have permissionValid := permissionChecked permission rfl
                          step with Fields.key_exact decoder8 4#u8 as ⟨key4, decoder9, key4Meaning, key4Input⟩
                          cases key4 with
                          | Err error =>
                            simp [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual, core.convert.FromSame.from, error.CodecError.Insts.CoreConvertFromModelError.from]
                          | Ok _ =>
                            simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                            step with DecoderContracts.optional_budget_checked decoder9 as ⟨budgetResult, decoder10, budgetChecked⟩
                            cases budgetResult with
                            | Err error =>
                              simp [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual, core.convert.FromSame.from, error.CodecError.Insts.CoreConvertFromModelError.from]
                            | Ok budget =>
                              simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                              have budgetValid := budgetChecked budget rfl
                              step with Fields.key_exact decoder10 5#u8 as ⟨key5, decoder11, key5Meaning, key5Input⟩
                              cases key5 with
                              | Err error =>
                                simp [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual, core.convert.FromSame.from, error.CodecError.Insts.CoreConvertFromModelError.from]
                              | Ok _ =>
                                simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                                simp only [auths_model.VerifierLimits.get, bind_tc_ok]
                                step with Fields.array_exact decoder11 limits.attachments as ⟨countResult, decoder12, countMeaning, countInput⟩
                                cases countResult with
                                | Err error =>
                                  simp [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual, core.convert.FromSame.from, error.CodecError.Insts.CoreConvertFromModelError.from]
                                | Ok count =>
                                  simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                                  simp only [cbor.Decoder.impl.position, bind_tc_ok]
                                  step with AttachmentDecode.batch_exact input limits decoder12.position count as ⟨attachmentsResult, attachmentsMeaning⟩
                                  cases attachmentsResult with
                                  | Err error =>
                                    simp [core.result.Result.Insts.CoreOpsTry.branch,
                                      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                                      core.convert.FromSame.from]
                                  | Ok attachments =>
                                    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                                    step with Cursor.at_exact input attachments.position as ⟨finalDecoder, finalDecoderMeaning⟩
                                    cases finalDecoder with
                                    | Err error => simp
                                    | Ok finalDecoder =>
                                      step with DecoderContracts.action_new_checked profile media body permission budget
                                        profileValid mediaValid permissionValid budgetValid as ⟨newResult, newChecked⟩
                                      cases newResult with
                                      | Err error =>
                                        simp [core.result.Result.Insts.CoreOpsTry.branch,
                                          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                                          error.CodecError.Insts.CoreConvertFromModelError.from]
                                      | Ok action =>
                                        have valid := newChecked action rfl
                                        simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                                        step with DecoderContracts.attachments_checked action attachments.attachments valid.1 valid.2
                                          as ⟨normalizedResult, normalizedChecked⟩
                                        cases normalizedResult with
                                        | Err error =>
                                          simp [core.result.Result.Insts.CoreOpsTry.branch,
                                            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                                            error.CodecError.Insts.CoreConvertFromModelError.from]
                                        | Ok normalized =>
                                          have normalizedValid := normalizedChecked normalized rfl
                                          simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                                          step with Cursor.ensure_complete_exact finalDecoder input as ⟨completion, completionMeaning⟩
                                          cases completion with
                                          | Err error =>
                                            simp [core.result.Result.Insts.CoreOpsTry.branch,
                                              core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                                              core.convert.FromSame.from]
                                          | Ok _ =>
                                            have strings := fields_earn_strings normalized normalizedValid.1
                                            have envelope := ActionResources.valid_allocation_envelope normalized
                                              normalizedValid.1 normalizedValid.2.1 normalizedValid.2.2
                                            have room : ActionEncode.actionCost normalized ≤ Usize.max := by
                                              have portable : 16818401 ≤ Usize.max := by scalar_tac
                                              omega
                                            simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                                            step with ActionEncode.action_exact normalized strings room as ⟨encodedResult, encodedMeaning⟩
                                            cases encodedResult with
                                            | Err error => simp [ActionEncode.resultView] at encodedMeaning
                                            | Ok encoded =>
                                              simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
                                                alloc.vec.Vec.as_slice]
                                              step with Action.bytes_ne_exact as ⟨different, compareMeaning⟩
                                              split <;> simp

end Auths.Codec.ActionTotal
