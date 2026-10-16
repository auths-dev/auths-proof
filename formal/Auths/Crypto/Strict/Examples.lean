import Auths.Crypto.Strict.SourceAcceptance
import Auths.Crypto.Encoding.Examples
import Lean.Elab.Tactic.Cbv
open Aeneas Aeneas.Std Result
set_option cbv.warning false
set_option maxRecDepth 4096
set_option maxHeartbeats 2000000
-- Encoding/guard witnesses alone do not establish signature authenticity.
namespace Auths.Crypto.Strict.Examples

def zero : LowScan.Input := ⟨List.replicate 64 0#u8, by scalar_tac⟩
def half : LowScan.Input := ⟨List.replicate 32 0#u8 ++ auths_signature_core.P256_HALF_ORDER.val, by
  have size := LowScan.half_length
  scalar_tac⟩
def aboveHalf : LowScan.Input := ⟨List.replicate 32 0#u8 ++ auths_signature_core.P256_HALF_ORDER.val.set 31 169#u8, by
  have size := LowScan.half_length
  scalar_tac⟩
def maximum : LowScan.Input := ⟨List.replicate 32 0#u8 ++ List.replicate 32 255#u8, by scalar_tac⟩
def publicR : RContract.Input := ⟨Encoding.Examples.rfcPublicKey.val ++ List.replicate 32 0#u8, by
  have size := Encoding.Encoded.input_length Encoding.Examples.rfcPublicKey
  scalar_tac⟩

theorem zero_s_form_allowed : auths_signature_core.p256_signature_is_low_s zero = ok true := by
  rw [LowContract.guard_refines]
  cbv

theorem half_s_form_allowed : auths_signature_core.p256_signature_is_low_s half = ok true := by
  rw [LowContract.guard_refines]
  unfold half
  simp only [List.drop_append, List.length_replicate, List.drop_replicate, Nat.sub_self, List.nil_append,
    LowContract.half_order_exact]
  cbv

theorem above_half_s_refused : auths_signature_core.p256_signature_is_low_s aboveHalf = ok false := by
  rw [LowContract.guard_refines]
  unfold aboveHalf auths_signature_core.P256_HALF_ORDER
  cbv

theorem maximum_s_refused : auths_signature_core.p256_signature_is_low_s maximum = ok false := by
  rw [LowContract.guard_refines]
  cbv

theorem identity_coordinate_is_weak :
    auths_signature_core.ed25519_has_small_order_coordinate Encoding.Examples.canonicalIdentity = ok true := by
  rw [WeakContract.guard_refines]
  cbv

theorem published_key_coordinate_is_not_weak :
    auths_signature_core.ed25519_has_small_order_coordinate Encoding.Examples.rfcPublicKey = ok false := by
  rw [WeakContract.guard_refines]
  cbv

theorem weak_r_form_refused : auths_signature_core.ed25519_signature_r_is_allowed zero = ok false := by
  rw [RContract.guard_refines]
  cbv

theorem public_r_form_allowed : auths_signature_core.ed25519_signature_r_is_allowed publicR = ok true := by
  rw [RContract.guard_refines]
  cbv

end Auths.Crypto.Strict.Examples
