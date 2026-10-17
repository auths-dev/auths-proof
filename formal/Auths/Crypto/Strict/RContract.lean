import qualification.aeneas.generated.signature.Funs
import Auths.Crypto.Strict.WeakContract
import Auths.Crypto.Encoding.Ed25519
open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace Auths.Crypto.RContract

abbrev Input := Array Std.U8 64#usize

def rBytes (input : Input) : Encoding.Encoded.Input := ⟨input.val.take 32, by
  have size := input.property
  scalar_tac⟩

def Allowed (input : Input) : Prop := Encoding.Encoded.Encoding (rBytes input) ∧
    ¬ WeakContract.WeakCoordinate (Encoding.Encoded.ordinate (rBytes input))

instance (input : Input) : Decidable (Allowed input) := inferInstanceAs
  (Decidable (Encoding.Encoded.Encoding (rBytes input) ∧
    ¬ WeakContract.WeakCoordinate (Encoding.Encoded.ordinate (rBytes input))))

theorem guard_refines (input : Input) :
    auths_signature_core.ed25519_signature_r_is_allowed input = ok (decide (Allowed input)) := by
  suffices run : auths_signature_core.ed25519_signature_r_is_allowed input
      ⦃ result => result = decide (Allowed input) ⦄ by
    obtain ⟨result, executes, rfl⟩ := spec_imp_exists run
    exact executes
  unfold auths_signature_core.ed25519_signature_r_is_allowed
  have inputSize : input.val.length = 64 := by have size := input.property; scalar_tac
  step as ⟨prefixBytes, prefixEq⟩
  unfold core.array.TryFromSharedArraySlice.try_from
  have sized : prefixBytes.len = 32#usize := by scalar_tac
  simp only [sized, _root_.dite_true, bind_tc_ok]
  rw [Encoding.Ed25519.guard_refines]
  simp only [bind_tc_ok]
  rw [WeakContract.guard_refines]
  have same : (⟨prefixBytes.val, by scalar_tac⟩ : Encoding.Encoded.Input) = rBytes input := by
    apply Subtype.ext
    simpa [rBytes, List.slice, Array.to_slice] using prefixEq
  simp only [same]
  by_cases canonical : Encoding.Encoded.Encoding (rBytes input)
  · simp [canonical, Allowed, spec_ok]
  · simp [canonical, Allowed, spec_ok]

end Auths.Crypto.RContract
