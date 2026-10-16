import qualification.aeneas.generated.signature.Funs
import Auths.Crypto.Encoding.Encoded
open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace Auths.Crypto.CoordinateScan
open Auths.Crypto.Encoding.Encoded

theorem loop_refines (input expected : Input) (remaining : Nat) (index : Std.Usize)
    (count : index.val + remaining = 31) :
    auths_signature_core.ed25519_same_coordinate_loop input expected index
      ⦃ result => result = decide ((input.val.drop index.val).take remaining =
        (expected.val.drop index.val).take remaining) ⦄ := by
  induction remaining generalizing index with
  | zero =>
    have atEnd : index = 31#usize := by scalar_tac
    subst index
    rw [auths_signature_core.ed25519_same_coordinate_loop.eq_def]
    simp [spec_ok]
  | succ remaining ih =>
    rw [auths_signature_core.ed25519_same_coordinate_loop.eq_def]
    have advances : index < 31#usize := by scalar_tac
    simp only [advances, ↓reduceIte]
    have inputSize := input_length input
    have expectedSize := input_length expected
    step as ⟨byte, byteEq⟩
    step as ⟨bound, boundEq⟩
    have leftParts : (input.val.drop index.val).take (remaining + 1) =
        byte :: (input.val.drop (index.val + 1)).take remaining := by
      rw [List.drop_eq_getElem_cons (by omega)]
      simp only [List.take_succ_cons, byteEq]
    have rightParts : (expected.val.drop index.val).take (remaining + 1) =
        bound :: (expected.val.drop (index.val + 1)).take remaining := by
      rw [List.drop_eq_getElem_cons (by omega)]
      simp only [List.take_succ_cons, boundEq]
    by_cases same : byte = bound
    · simp only [same, bne_self_eq_false, Bool.false_eq_true, ite_false]
      step as ⟨next, nextEq⟩
      have countNext : next.val + remaining = 31 := by omega
      apply spec_mono (ih next countNext)
      intro result exactResult
      simpa only [leftParts, rightParts, same, List.cons.injEq, true_and, nextEq] using exactResult
    · simp [same, spec_ok, leftParts, rightParts]

end Auths.Crypto.CoordinateScan
