import qualification.aeneas.generated.p256.Funs
import Auths.Crypto.Encoding.P256
open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace Auths.Crypto.P256Encoding
abbrev Encoding := Auths.Crypto.Encoding.P256.Encoding

theorem guard_refines (input : Slice Std.U8) :
    AuthsNativeP256.p256_key_encoding_is_canonical input =
      ok (decide (Encoding (input.val.map UScalar.val))) := by
  suffices h : AuthsNativeP256.p256_key_encoding_is_canonical input
      ⦃ result => result = decide (Encoding (input.val.map UScalar.val)) ⦄ by
    obtain ⟨result, executes, rfl⟩ := spec_imp_exists h
    exact executes
  unfold AuthsNativeP256.p256_key_encoding_is_canonical
  simp only [AuthsNativeP256.P256_KEY_LEN, AuthsNativeP256.core.qualified_p256_fun_decls_20, bind_tc_ok]
  by_cases sized : input.val.length = 33
  · have sizeEq : Slice.len input = 33#usize := by scalar_tac
    simp only [sizeEq, bne_self_eq_false, Bool.false_eq_true, ite_false]
    step as ⟨first, firstEq⟩
    have two : (first = 2#u8) ↔ first.val = 2 := by scalar_tac
    have three : (first = 3#u8) ↔ first.val = 3 := by scalar_tac
    have headEq : (input.val.map UScalar.val).head? = some first.val := by
      cases values : input.val with
      | nil => simp [values] at sized
      | cons head tail =>
        have firstIsHead : first = head := by simpa only [values, List.getElem_cons_zero] using firstEq
        simp [firstIsHead]
    simp only [Encoding, Auths.Crypto.Encoding.P256.Encoding, List.length_map, sized, headEq, Option.some.injEq, true_and]
    split <;> simp_all
  · have sizeNe : Slice.len input ≠ 33#usize := by scalar_tac
    simp [sizeNe, spec_ok, Encoding, Auths.Crypto.Encoding.P256.Encoding, sized]

end Auths.Crypto.P256Encoding
