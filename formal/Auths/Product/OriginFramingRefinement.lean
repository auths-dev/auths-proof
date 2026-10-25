import Auths.Product.PathCompilerLeaves

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.Refinement.ByteIdentity

namespace Auths.Product.PathCompiler.Refinement

/-- Exact source origin/host agreement, without a parsed-host or normalization
result as a premise. Hostname policy and parser meaning remain separate. -/
@[step] theorem origin_matches_exact (origin host : Slice Std.U8) :
    path_compiler.origin_matches_host origin host ⦃ actual =>
      actual = decide (OriginMatches (sliceBytes origin) (sliceBytes host)) ⦄ := by
  unfold path_compiler.origin_matches_host
  by_cases empty : host.val = []
  · simp [empty, core.slice.Slice.is_empty, OriginMatches, sliceBytes, byteList]
  · have nonempty : 0 < host.val.length := List.length_pos.mpr empty
    by_cases long : 253 < host.val.length
    · have nativeLong : host.len > 253#usize := by scalar_tac
      simp [nativeLong, OriginMatches, sliceBytes, byteList, Nat.not_le.mpr long]
    · have hostBound : host.val.length ≤ 253 := by omega
      have nativeBound : ¬host.len > 253#usize := by scalar_tac
      simp only [core.slice.Slice.is_empty, empty, List.isEmpty_eq_false, nativeBound, Bool.false_or]
      step as ⟨length, lengthValue⟩
      by_cases sameLength : origin.val.length = 8 + host.val.length
      · have nativeSame : origin.len = length := by scalar_tac
        simp only [nativeSame, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
        step with copy_bytes_spec as ⟨prefix, prefixValue⟩
        have appendFits : prefix.val.length + host.val.length < 4294967295 := by
          simp [prefixValue]
          omega
        step with append_bytes_spec as ⟨expected, expectedValue⟩
        step with field_name_equal_exact as ⟨actual, meaning⟩
        have frame : byteList expected.val = httpsPrefix ++ sliceBytes host := by
          simp [expectedValue, prefixValue, byteList, sliceBytes, httpsPrefix]
        have identity : origin.val = expected.val ↔ sliceBytes origin = httpsPrefix ++ sliceBytes host := by
          rw [← frame]
          exact byteList_inj _ _ |>.symm
        simpa [OriginMatches, nonempty, hostBound, sliceBytes, byteList, identity, alloc.vec.Vec.deref] using meaning
      · have nativeDifferent : origin.len ≠ length := by scalar_tac
        have invalid : ¬OriginMatches (sliceBytes origin) (sliceBytes host) := by
          intro matched
          have size := congrArg List.length matched.2.2
          simp [sliceBytes, byteList, httpsPrefix] at size
          exact sameLength size
        simp [nativeDifferent, invalid]

theorem source_matched_origin_bounded (origin host : Slice Std.U8) :
    path_compiler.origin_matches_host origin host ⦃ actual => actual = true → origin.val.length ≤ 261 ⦄ := by
  apply spec_mono (origin_matches_exact origin host)
  intro actual meaning accepted
  have matched : OriginMatches (sliceBytes origin) (sliceBytes host) := by
    apply of_decide_eq_true
    simpa [accepted] using meaning.symm
  simpa [sliceBytes, byteList] using origin_matches_bound _ _ matched

end Auths.Product.PathCompiler.Refinement
