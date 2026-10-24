import Auths.Codec.DecodedActionDeployment
import Auths.Codec.ActionInverseExamples
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.ActionAssurance
open Refinement

/-- Public acceptance is exactly the independently stated valid carrier,
deployment fit and canonical complete byte encoding. This is an acceptance
relation, not a definition in terms of the implementation's verdict. -/
theorem accepted_iff (input : Slice Std.U8) (limits : auths_codec.auths_model.VerifierLimits)
    (action : auths_codec.auths_model.CanonicalAction) :
    decode.decode_canonical_action input limits = ok (.Ok action) ↔
      ActionCarrier.Valid action ∧ ActionCarrier.Fits limits action ∧
        byteList input.val = ActionEncode.actionEncoding action := by
  constructor
  · intro accepted
    exact ⟨DecodedActionCarrier.decoded_valid input limits action accepted,
      DecodedActionDeployment.decoded_fits input limits action accepted,
      ActionResources.decoded_wire_exact input limits action accepted⟩
  · rintro ⟨valid, fits, wire⟩
    obtain ⟨actual, evaluates, meaning⟩ := spec_imp_exists (ActionInverse.decode_encoding input limits action valid fits wire)
    simpa only [meaning] using evaluates

/-- Every valid value that fits a deployment has a real source encoding and
a real public-decoder round trip, including every constructor and final
canonical re-encoding comparison. -/
theorem useful_value_roundtrip (action : auths_codec.auths_model.CanonicalAction)
    (limits : auths_codec.auths_model.VerifierLimits)
    (valid : ActionCarrier.Valid action) (fits : ActionCarrier.Fits limits action) :
    ∃ bytes, encode.encode_canonical_action action = ok (.Ok bytes) ∧
      decode.decode_canonical_action (alloc.vec.Vec.deref bytes) limits = ok (.Ok action) := by
  obtain ⟨encoded, evaluates, roundtrip⟩ := spec_imp_exists (ActionInverse.encode_decode action limits valid fits)
  obtain ⟨bytes, same, parsed⟩ := roundtrip
  obtain ⟨decoded, decodes, sameAction⟩ := spec_imp_exists parsed
  exact ⟨bytes, by simpa only [same] using evaluates, by simpa only [sameAction] using decodes⟩

/-- Complete independent encodings are injective on the declared deployment's
valid carriers. The proof uses real parser determinism and byte equality;
it does not assume hash injectivity or the desired value equality. -/
theorem encoding_injective (left right : auths_codec.auths_model.CanonicalAction)
    (limits : auths_codec.auths_model.VerifierLimits)
    (leftValid : ActionCarrier.Valid left) (rightValid : ActionCarrier.Valid right)
    (leftFits : ActionCarrier.Fits limits left) (rightFits : ActionCarrier.Fits limits right)
    (sameEncoding : ActionEncode.actionEncoding left = ActionEncode.actionEncoding right) : left = right := by
  obtain ⟨bytes, encodes, leftDecode⟩ := useful_value_roundtrip left limits leftValid leftFits
  have encoded := ActionEncode.action_exact left (ActionCarrier.strings_bounded left leftValid)
    (ActionCarrier.buffer_room left leftValid)
  rw [encodes] at encoded
  simp only [spec_ok, ActionEncode.resultView, core.result.Result.Ok.injEq] at encoded
  have rightWire : byteList (alloc.vec.Vec.deref bytes).val = ActionEncode.actionEncoding right := by
    simpa only [alloc.vec.Vec.deref, sameEncoding] using encoded
  obtain ⟨decoded, rightDecode, sameRight⟩ := spec_imp_exists
    (ActionInverse.decode_encoding (alloc.vec.Vec.deref bytes) limits right rightValid rightFits rightWire)
  rw [leftDecode] at rightDecode
  have sameResult : decoded = .Ok left := Result.ok.inj rightDecode.symm
  simpa only [sameResult, core.result.Result.Ok.injEq] using sameRight

/-- Malformed, noncanonical, invalid-carrier or over-deployment input cannot
produce an accepted value, regardless of a caller's asserted intended action. -/
theorem rejects_outside_language (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits) (action : auths_codec.auths_model.CanonicalAction)
    (outside : ¬ (ActionCarrier.Valid action ∧ ActionCarrier.Fits limits action ∧
      byteList input.val = ActionEncode.actionEncoding action)) :
    decode.decode_canonical_action input limits ≠ ok (.Ok action) := by
  exact fun accepted => outside ((accepted_iff input limits action).mp accepted)

end Auths.Codec.ActionAssurance
