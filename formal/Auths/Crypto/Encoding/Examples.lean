import Auths.Crypto.Encoding.Ed25519
import Auths.Crypto.Encoding.P256
import Lean.Elab.Tactic.Cbv
open Aeneas Aeneas.Std Result
set_option cbv.warning false
set_option maxRecDepth 4096
set_option maxHeartbeats 2000000

namespace Auths.Crypto.Encoding.Examples

-- These are public encoding witnesses. Curve membership and signatures are separate.
def rfcPublicKey : Encoded.Input := ⟨[215#u8, 90#u8, 152#u8, 1#u8, 130#u8, 177#u8, 10#u8, 183#u8, 213#u8, 75#u8, 254#u8, 211#u8, 201#u8, 100#u8, 7#u8, 58#u8, 14#u8, 225#u8, 114#u8, 243#u8, 218#u8, 166#u8, 35#u8, 37#u8, 175#u8, 2#u8, 26#u8, 104#u8, 247#u8, 7#u8, 81#u8, 26#u8], by scalar_tac⟩

def noncanonicalField : Encoded.Input := ⟨[240#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 255#u8, 127#u8], by scalar_tac⟩

def negativeZero : Encoded.Input := ⟨[1#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 128#u8], by scalar_tac⟩

def canonicalIdentity : Encoded.Input := ⟨[1#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8], by scalar_tac⟩

theorem rfc_key_encoding_accepted : auths_signature_core.ed25519_point_encoding_is_canonical rfcPublicKey = ok true := by
  rw [Ed25519.guard_refines]
  cbv

theorem field_alias_refused : auths_signature_core.ed25519_point_encoding_is_canonical noncanonicalField = ok false := by
  rw [Ed25519.guard_refines]
  cbv

theorem negative_zero_refused : auths_signature_core.ed25519_point_encoding_is_canonical negativeZero = ok false := by
  rw [Ed25519.guard_refines]
  cbv

theorem canonical_identity_encoding_accepted : auths_signature_core.ed25519_point_encoding_is_canonical canonicalIdentity = ok true := by
  rw [Ed25519.guard_refines]
  cbv

theorem compressed_form_accepted : auths_signature_core.p256_key_encoding_is_canonical
    (⟨[2#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8], by scalar_tac⟩ : Slice Std.U8) = ok true := by
  rw [P256.guard_refines]
  cbv

theorem uncompressed_tag_refused : auths_signature_core.p256_key_encoding_is_canonical
    (⟨[4#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8], by scalar_tac⟩ : Slice Std.U8) = ok false := by
  rw [P256.guard_refines]
  cbv

theorem short_compressed_refused : auths_signature_core.p256_key_encoding_is_canonical
    (⟨[2#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8], by scalar_tac⟩ : Slice Std.U8) = ok false := by
  rw [P256.guard_refines]
  cbv

end Auths.Crypto.Encoding.Examples
