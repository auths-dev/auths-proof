import Auths.Crypto.P256Native
import Lean.Elab.Tactic.Cbv
open Aeneas Aeneas.Std Result
set_option cbv.warning false
set_option maxRecDepth 4096
set_option maxHeartbeats 2000000
namespace Auths.Crypto.P256Examples

def key : Slice Std.U8 := ⟨2#u8 :: List.replicate 32 0#u8, by scalar_tac⟩
def changedKey : Slice Std.U8 := ⟨3#u8 :: List.replicate 32 0#u8, by scalar_tac⟩
def signature : Slice Std.U8 := ⟨List.replicate 63 0#u8 ++ [1#u8], by scalar_tac⟩
def changedSignature : Slice Std.U8 := ⟨1#u8 :: List.replicate 62 0#u8 ++ [1#u8], by scalar_tac⟩
def message : Slice Std.U8 := ⟨[42#u8], by scalar_tac⟩
def changedMessage : Slice Std.U8 := ⟨[43#u8], by scalar_tac⟩
def empty : Slice Std.U8 := ⟨[], by scalar_tac⟩

-- Explicit forwarding mock only: these form witnesses are not P-256 signatures
-- and do not establish curve membership, primitive correctness or authenticity.
def equation (point text scalar : List Std.U8) : Bool :=
  point == key.val && text == message.val && scalar == signature.val

@[reducible] def forwardingPrimitive : P256Primitives where
  Key := List Std.U8
  Signature := List Std.U8
  Error := Unit
  decode := fun bytes => ok (.Ok bytes.val)
  parse := fun bytes => ok (.Ok bytes.val)
  verify := fun point text scalar =>
    ok (if equation point text.val scalar then .Ok () else .Err ())

theorem forwarding_contract : P256Native.Contract (P := forwardingPrimitive)
    (fun bytes => some bytes) (fun bytes => some bytes) equation := by
  refine P256Native.Contract.mk (P := forwardingPrimitive) ?_ ?_ ?_
  · intro bytes; rfl
  · intro bytes; rfl
  · intro point text scalar
    change (do
      let result ← ok (if equation point text.val scalar then .Ok () else .Err ())
      ok (P256Native.resultIsOk result)) = ok (equation point text.val scalar)
    split <;> simp_all [P256Native.resultIsOk]

theorem public_call_forwards_exact_bytes :
    AuthsNativeP256.verify_p256_sha256 (primitive := forwardingPrimitive)
      key message signature = ok (.Ok ()) := by
  rw [P256Native.public_verify_refines (P := forwardingPrimitive)
    (fun bytes => some bytes) (fun bytes => some bytes) equation forwarding_contract]
  cbv

theorem changed_message_is_refused :
    AuthsNativeP256.verify_p256_sha256 (primitive := forwardingPrimitive)
      key changedMessage signature = ok (.Err .VerificationFailed) := by
  rw [P256Native.public_verify_refines (P := forwardingPrimitive)
    (fun bytes => some bytes) (fun bytes => some bytes) equation forwarding_contract]
  cbv

theorem changed_key_is_refused :
    AuthsNativeP256.verify_p256_sha256 (primitive := forwardingPrimitive)
      changedKey message signature = ok (.Err .VerificationFailed) := by
  rw [P256Native.public_verify_refines (P := forwardingPrimitive)
    (fun bytes => some bytes) (fun bytes => some bytes) equation forwarding_contract]
  cbv

theorem changed_signature_is_refused :
    AuthsNativeP256.verify_p256_sha256 (primitive := forwardingPrimitive)
      key message changedSignature = ok (.Err .VerificationFailed) := by
  rw [P256Native.public_verify_refines (P := forwardingPrimitive)
    (fun bytes => some bytes) (fun bytes => some bytes) equation forwarding_contract]
  cbv

theorem malformed_key_refused_without_primitive_contract [P : P256Primitives]
    (message signature : Slice Std.U8) :
    AuthsNativeP256.verify_p256_sha256 (primitive := P) empty message signature =
      ok (.Err .InvalidKey) := by
  unfold AuthsNativeP256.verify_p256_sha256 AuthsNativeP256.verify_p256_sha256_with
    AuthsNativeP256.decode_p256_key_with
  rw [P256Encoding.guard_refines]
  cbv

end Auths.Crypto.P256Examples
