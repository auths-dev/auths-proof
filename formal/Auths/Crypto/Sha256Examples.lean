import Auths.Crypto.Sha256Native
import Lean.Elab.Tactic.Cbv
open Aeneas Aeneas.Std Result
set_option cbv.warning false
namespace Auths.Crypto.Sha256Examples

-- A byte-forwarding mock, not a SHA-256 implementation or security claim.
def echo (bytes : List Std.U8) : Array Std.U8 32#usize :=
  Array.repeat 32#usize (bytes.headD 0#u8)

@[reducible] def forwardingPrimitive : Sha256Primitives where
  Output := Array Std.U8 32#usize
  digest := fun bytes => ok (echo bytes.val)
  intoBytes := fun bytes => ok bytes

theorem forwarding_contract : Sha256Native.Contract (P := forwardingPrimitive) echo := by
  refine Sha256Native.Contract.mk (P := forwardingPrimitive) ?_
  intro bytes
  exact ⟨echo bytes.val, rfl, rfl⟩

theorem exact_input_reaches_selected_digest :
    AuthsNativeSha256.hash.raw_sha256 (primitive := forwardingPrimitive)
      (⟨[42#u8], by scalar_tac⟩ : Slice Std.U8) = ok (Array.repeat 32#usize 42#u8) := by
  rw [Sha256Native.raw_hash_refines (P := forwardingPrimitive) echo forwarding_contract]
  rfl

theorem changed_input_reaches_selected_digest :
    AuthsNativeSha256.hash.raw_sha256 (primitive := forwardingPrimitive)
      (⟨[43#u8], by scalar_tac⟩ : Slice Std.U8) = ok (Array.repeat 32#usize 43#u8) := by
  rw [Sha256Native.raw_hash_refines (P := forwardingPrimitive) echo forwarding_contract]
  rfl

end Auths.Crypto.Sha256Examples
