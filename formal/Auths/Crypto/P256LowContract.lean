import Auths.Crypto.P256LowScan
import Auths.Crypto.Strict.LowContract
open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace Auths.Crypto.P256LowContract

abbrev order := Auths.Crypto.LowContract.order

theorem half_order_exact : ByteLex.value AuthsNativeP256.P256_HALF_ORDER.val = order / 2 := by
  unfold ByteLex.value AuthsNativeP256.P256_HALF_ORDER order
  decide

theorem guard_refines (input : P256LowScan.Input) :
    AuthsNativeP256.p256_signature_is_low_s input =
      ok (decide (ByteLex.value (input.val.drop 32) ≤ order / 2)) := by
  obtain ⟨result, executes, meaning⟩ := spec_imp_exists
    (P256LowScan.loop_refines input 32 0#usize (by scalar_tac))
  have exactSource : AuthsNativeP256.p256_signature_is_low_s input =
      ok (ByteLex.le (input.val.drop 32) AuthsNativeP256.P256_HALF_ORDER.val) := by
    simpa only [AuthsNativeP256.p256_signature_is_low_s, meaning,
      UScalar.ofNatCore_val_eq, Nat.add_zero, List.drop_zero] using executes
  rw [exactSource]
  congr 1
  apply Bool.eq_iff_iff.mpr
  have sizes : (input.val.drop 32).length = AuthsNativeP256.P256_HALF_ORDER.val.length := by
    simp only [List.length_drop, P256LowScan.input_length, P256LowScan.half_length]
  simpa only [half_order_exact, decide_eq_true_eq] using
    ByteLex.le_numeric (input.val.drop 32) AuthsNativeP256.P256_HALF_ORDER.val sizes

theorem r_bytes_irrelevant (left right : P256LowScan.Input)
    (sameScalar : left.val.drop 32 = right.val.drop 32) :
    AuthsNativeP256.p256_signature_is_low_s left = AuthsNativeP256.p256_signature_is_low_s right := by
  rw [guard_refines, guard_refines, sameScalar]

end Auths.Crypto.P256LowContract
