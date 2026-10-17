import Auths.Codec.Evaluation

open Aeneas Aeneas.Std Result
open auths_codec
set_option cbv.warning false
set_option maxHeartbeats 2000000
set_option maxRecDepth 4096

namespace Auths.Codec.Examples

/-- Small positive carrier exercising every required canonical-action field.
The singleton body is opaque profile data; this is codec acceptance, not an
authorization claim for a registered application profile. -/
def minimalLimits : auths_codec.auths_model.VerifierLimits := {
  bundle_bytes := 1#usize
  action_bytes := 128#usize
  context_bytes := 1#usize
  grants := 1#usize
  actions := 1#usize
  plan_leaves := 1#usize
  plan_depth := 1#usize
  plan_branching := 1#usize
  evidence := 1#usize
  evidence_bytes := 1#usize
  bindings := 1#usize
  principal_status := 1#usize
  grant_status := 1#usize
  attachments := 1#usize
  attachment_bytes := 1#usize
  signatures := 1#usize
  signature_bytes := 1#usize
  permissions := 1#usize
  audiences := 1#usize
  extensions := 1#usize
  extension_bytes := 1#usize
  body_digests := 1#usize
  binding_evidence := 1#usize
  canonical_body_bytes := 1#usize
  registry_entries := 1#usize
  trust_anchors := 1#usize
  work_units := 1#u64
  approvals := 1#usize
  approver_anchors := 1#usize
  approval_requirements := 1#usize
}
def minimalInput : Slice Std.U8 := ⟨[
  166#u8, 0#u8, 162#u8, 0#u8, 97#u8, 116#u8, 1#u8, 1#u8,
  1#u8, 97#u8, 109#u8, 2#u8, 65#u8, 1#u8, 3#u8, 162#u8,
  0#u8, 97#u8, 114#u8, 1#u8, 97#u8, 114#u8, 4#u8, 246#u8, 5#u8, 128#u8
], by scalar_tac⟩
def minimalAction : auths_codec.auths_model.CanonicalAction := {
  profile := { id := "t", version := 1#u16 }
  media_type := "m"
  body := ⟨[1#u8], by scalar_tac⟩
  permission := { capability := "r", resource := "r" }
  requested_budget := none
  detached_attachments := alloc.vec.Vec.new _
}


@[cbv_eval] theorem minimal_limits_valid :
    auths_model.VerifierLimits.validate minimalLimits = ok (.Ok ()) := by
  cbv

@[cbv_eval] theorem minimal_encoding_exact :
    encode.encode_canonical_action minimalAction =
      ok (.Ok (⟨minimalInput.val, by scalar_tac⟩ : alloc.vec.Vec Std.U8)) := by
  cbv

/-- The whole shipping decoder accepts a nonempty, bounded action. -/
theorem minimal_action_accepted :
    decode.decode_canonical_action minimalInput minimalLimits = ok (.Ok minimalAction) := by
  cbv

def duplicateKeyInput : Slice Std.U8 := ⟨[
  166#u8, 0#u8, 162#u8, 0#u8, 97#u8, 116#u8, 0#u8, 1#u8,
  1#u8, 97#u8, 109#u8, 2#u8, 65#u8, 1#u8, 3#u8, 162#u8,
  0#u8, 97#u8, 114#u8, 1#u8, 97#u8, 114#u8, 4#u8, 246#u8,
  5#u8, 128#u8
], by scalar_tac⟩

theorem duplicate_key_refused :
    decode.decode_canonical_action duplicateKeyInput minimalLimits = ok (.Err error.CodecError.NonCanonical) := by
  cbv

def nonminimalIntegerInput : Slice Std.U8 := ⟨[
  166#u8, 0#u8, 162#u8, 0#u8, 97#u8, 116#u8, 1#u8, 24#u8,
  1#u8, 1#u8, 97#u8, 109#u8, 2#u8, 65#u8, 1#u8, 3#u8,
  162#u8, 0#u8, 97#u8, 114#u8, 1#u8, 97#u8, 114#u8, 4#u8,
  246#u8, 5#u8, 128#u8
], by scalar_tac⟩

theorem nonminimal_integer_refused :
    decode.decode_canonical_action nonminimalIntegerInput minimalLimits = ok (.Err error.CodecError.NonCanonical) := by
  cbv

def invalidUtf8Input : Slice Std.U8 := ⟨[
  166#u8, 0#u8, 162#u8, 0#u8, 97#u8, 255#u8, 1#u8, 1#u8,
  1#u8, 97#u8, 109#u8, 2#u8, 65#u8, 1#u8, 3#u8, 162#u8,
  0#u8, 97#u8, 114#u8, 1#u8, 97#u8, 114#u8, 4#u8, 246#u8,
  5#u8, 128#u8
], by scalar_tac⟩

theorem invalid_utf8_refused :
    decode.decode_canonical_action invalidUtf8Input minimalLimits = ok (.Err error.CodecError.Malformed) := by
  cbv

def truncatedInput : Slice Std.U8 := ⟨[
  166#u8, 0#u8, 162#u8, 0#u8, 97#u8, 116#u8, 1#u8, 1#u8,
  1#u8, 97#u8, 109#u8, 2#u8, 65#u8, 1#u8, 3#u8, 162#u8,
  0#u8, 97#u8, 114#u8, 1#u8, 97#u8, 114#u8, 4#u8, 246#u8,
  5#u8
], by scalar_tac⟩

theorem truncated_refused :
    decode.decode_canonical_action truncatedInput minimalLimits = ok (.Err error.CodecError.Malformed) := by
  cbv

def trailingByteInput : Slice Std.U8 := ⟨[
  166#u8, 0#u8, 162#u8, 0#u8, 97#u8, 116#u8, 1#u8, 1#u8,
  1#u8, 97#u8, 109#u8, 2#u8, 65#u8, 1#u8, 3#u8, 162#u8,
  0#u8, 97#u8, 114#u8, 1#u8, 97#u8, 114#u8, 4#u8, 246#u8,
  5#u8, 128#u8, 0#u8
], by scalar_tac⟩

theorem trailing_byte_refused :
    decode.decode_canonical_action trailingByteInput minimalLimits = ok (.Err error.CodecError.Malformed) := by
  cbv

theorem action_byte_limit_refused :
    decode.decode_canonical_action minimalInput { minimalLimits with action_bytes := 25#usize } =
      ok (.Err error.CodecError.LimitExceeded) := by
  cbv

/-- The accepted input is exactly at the configured action-byte boundary. -/
theorem action_byte_limit_exact :
    decode.decode_canonical_action minimalInput { minimalLimits with action_bytes := 26#usize } =
      ok (.Ok minimalAction) := by
  cbv

end Auths.Codec.Examples
