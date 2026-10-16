import Auths.Crypto.NativeContract
import Lean.Elab.Tactic.Cbv

open Aeneas Aeneas.Std Result
set_option cbv.warning false
set_option maxRecDepth 4096
set_option maxHeartbeats 2000000

namespace Auths.Crypto.NativeExamples

def key : Slice Std.U8 := ⟨Encoding.Examples.rfcPublicKey.val, by
  have := Encoding.Encoded.input_length Encoding.Examples.rfcPublicKey
  scalar_tac⟩
def signature : Slice Std.U8 := ⟨Strict.Examples.publicR.val, by
  have := LowScan.input_length Strict.Examples.publicR
  scalar_tac⟩
def message : Slice Std.U8 := ⟨[42#u8], by scalar_tac⟩
def changedMessage : Slice Std.U8 := ⟨[43#u8], by scalar_tac⟩
def empty : Slice Std.U8 := ⟨[], by scalar_tac⟩

-- An explicit call-binding witness, deliberately not a cryptographic instance.
-- It accepts only the stated message and exact signature bytes. No global
-- instance is installed, and these examples make no authenticity claim.
def equation (_key : Unit) (message bytes : List Std.U8) : Bool :=
  message == [42#u8] && bytes == signature.val

@[reducible] def forwardingPrimitive : Ed25519Primitives where
  Key := Unit
  Signature := List Std.U8
  Error := Unit
  decode := fun _ => ok (.Ok ())
  signatureFromBytes := fun bytes => ok bytes.val
  verifyStrict := fun key message bytes =>
    ok (if equation key message.val bytes then .Ok () else .Err ())

theorem forwarding_contract :
    Native.Ed25519Contract (P := forwardingPrimitive) (fun _ => some ()) id equation := by
  refine Native.Ed25519Contract.mk (P := forwardingPrimitive) ?_ ?_ ?_
  · intro bytes
    exact ⟨.Ok (), rfl, rfl⟩
  · intro bytes
    rfl
  · intro key message bytes
    refine ⟨if equation key message.val bytes.val then .Ok () else .Err (), rfl, ?_⟩
    split <;> simp_all [Native.authenticated]

theorem public_call_forwards_exact_bytes :
    auths_signature_core.verify_ed25519 (primitives := forwardingPrimitive)
      key message signature = ok (.Ok ()) := by
  rw [Native.public_verify_refines (P := forwardingPrimitive) (fun _ => some ()) id equation forwarding_contract]
  cbv

theorem changed_message_is_refused :
    auths_signature_core.verify_ed25519 (primitives := forwardingPrimitive)
      key changedMessage signature = ok (.Err .VerificationFailed) := by
  rw [Native.public_verify_refines (P := forwardingPrimitive) (fun _ => some ()) id equation forwarding_contract]
  cbv

theorem malformed_key_refused_without_primitive_contract [P : Ed25519Primitives]
    (message signature : Slice Std.U8) :
    auths_signature_core.verify_ed25519 (primitives := P) empty message signature =
      ok (.Err .InvalidKey) := by
  cbv

end Auths.Crypto.NativeExamples
