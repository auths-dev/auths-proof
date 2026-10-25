import Auths.Codec.ActionDecodedFields
import Auths.Codec.ActionEncode
import Auths.Codec.ActionValidity
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.ActionWire
open Refinement ActionEncode

/-- The existing source canonicality check and the independently specified
complete encoder agree on actual accepted action bytes. These explicit
carrier/allocation premises are discharged separately by decoded validity. -/
theorem accepted_bytes_equal_model (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits)
    (action : auths_codec.auths_model.CanonicalAction)
    (accepted : decode.decode_canonical_action input limits = ok (.Ok action))
    (stringsBounded : StringsBounded action) (space : actionCost action ≤ Usize.max) :
    byteList input.val = actionEncoding action := by
  obtain ⟨bytes, encoded, sameInput⟩ := Action.decode_encode_exact input limits action accepted
  have encoding := action_exact action stringsBounded space
  rw [encoded] at encoding
  simp only [spec_ok, resultView, core.result.Result.Ok.injEq] at encoding
  simpa only [sameInput] using encoding

theorem accepted_action_has_definite_map (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits)
    (action : auths_codec.auths_model.CanonicalAction)
    (accepted : decode.decode_canonical_action input limits = ok (.Ok action))
    (stringsBounded : StringsBounded action) (space : actionCost action ≤ Usize.max) :
    (byteList input.val)[0]? = some 166 := by
  rw [accepted_bytes_equal_model input limits action accepted stringsBounded space]
  simp [actionEncoding]

/-- Equal independently encoded bytes, rather than equal hashes, imply exact
accepted wire identity. No collision-freedom premise is used. -/
theorem accepted_equal_encodings_equal_bytes (left right : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits)
    (leftAction rightAction : auths_codec.auths_model.CanonicalAction)
    (leftAccepted : decode.decode_canonical_action left limits = ok (.Ok leftAction))
    (rightAccepted : decode.decode_canonical_action right limits = ok (.Ok rightAction))
    (leftStrings : StringsBounded leftAction) (rightStrings : StringsBounded rightAction)
    (leftSpace : actionCost leftAction ≤ Usize.max) (rightSpace : actionCost rightAction ≤ Usize.max)
    (sameEncoding : actionEncoding leftAction = actionEncoding rightAction) :
    byteList left.val = byteList right.val := by
  rw [accepted_bytes_equal_model left limits leftAction leftAccepted leftStrings leftSpace,
    accepted_bytes_equal_model right limits rightAction rightAccepted rightStrings rightSpace]
  exact sameEncoding

/-- Constructor-derived native-string validity closes the string premise in
the source decoder-to-independent-wire theorem. The allocation envelope is
still explicit until the attachment resource theorem discharges it. -/
theorem decoded_bytes_equal_model (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits)
    (action : auths_codec.auths_model.CanonicalAction)
    (accepted : decode.decode_canonical_action input limits = ok (.Ok action))
    (space : actionCost action ≤ Usize.max) :
    byteList input.val = actionEncoding action :=
  accepted_bytes_equal_model input limits action accepted
    (ActionDecodedFields.decoded_strings_bounded input limits action accepted) space

end Auths.Codec.ActionWire
