import qualification.aeneas.generated.signature.Funs
import Auths.Crypto.Strict.ByteLex
open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace Auths.Crypto.LowScan

abbrev Input := Array Std.U8 64#usize

theorem input_length (input : Input) : input.val.length = 64 := by
  have bounded := input.property
  scalar_tac

theorem half_length : auths_signature_core.P256_HALF_ORDER.val.length = 32 := by
  have bounded := auths_signature_core.P256_HALF_ORDER.property
  scalar_tac

theorem loop_refines (input : Input) (remaining : Nat) (index : Std.Usize)
    (count : index.val + remaining = 32) :
    auths_signature_core.p256_signature_is_low_s_loop input index
      ⦃ result => result = ByteLex.le (input.val.drop (32 + index.val))
        (auths_signature_core.P256_HALF_ORDER.val.drop index.val) ⦄ := by
  induction remaining generalizing index with
  | zero =>
    have atEnd : index = 32#usize := by scalar_tac
    subst index
    rw [auths_signature_core.p256_signature_is_low_s_loop.eq_def]
    have emptyInput : input.val.drop 64 = [] := List.drop_eq_nil_iff.mpr (by rw [input_length])
    have emptyHalf : auths_signature_core.P256_HALF_ORDER.val.drop 32 = [] :=
      List.drop_eq_nil_iff.mpr (by rw [half_length])
    simp [spec_ok, emptyInput, emptyHalf, ByteLex.le]
  | succ remaining ih =>
    rw [auths_signature_core.p256_signature_is_low_s_loop.eq_def]
    have advances : index < 32#usize := by scalar_tac
    simp only [advances, ↓reduceIte]
    have inputSize := input_length input
    have halfSize := half_length
    step as ⟨offset, offsetEq⟩
    step as ⟨byte, byteEq⟩
    step as ⟨bound, boundEq⟩
    have leftParts : input.val.drop (32 + index.val) =
        byte :: input.val.drop (32 + index.val + 1) := by
      rw [List.drop_eq_getElem_cons (by omega)]
      simp only [byteEq, offsetEq]
    have rightParts : auths_signature_core.P256_HALF_ORDER.val.drop index.val =
        bound :: auths_signature_core.P256_HALF_ORDER.val.drop (index.val + 1) := by
      rw [List.drop_eq_getElem_cons (by omega)]
      simp only [boundEq]
    by_cases less : byte < bound
    · have natural : byte.val < bound.val := by scalar_tac
      simp [less, spec_ok, leftParts, rightParts, ByteLex.le, natural]
    · by_cases greater : bound < byte
      · have naturalLess : ¬ byte.val < bound.val := by scalar_tac
        have naturalGreater : bound.val < byte.val := by scalar_tac
        simp [less, greater, spec_ok, leftParts, rightParts, ByteLex.le, naturalLess, naturalGreater]
      · have naturalLess : ¬ byte.val < bound.val := by scalar_tac
        have naturalGreater : ¬ bound.val < byte.val := by scalar_tac
        simp only [less, greater, ↓reduceIte]
        step as ⟨next, nextEq⟩
        have countNext : next.val + remaining = 32 := by omega
        apply spec_mono (ih next countNext)
        intro result exactResult
        simpa only [leftParts, rightParts, ByteLex.le, naturalLess, naturalGreater, ↓reduceIte,
          nextEq, Nat.add_assoc] using exactResult

end Auths.Crypto.LowScan
