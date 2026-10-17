import qualification.aeneas.generated.codec.Funs
import Mathlib.Tactic.CasesM

open Aeneas Aeneas.Std Result
open auths_codec
namespace Auths.Crypto.BufferAllocation

/-- The signed pointer-size restriction imposed by Rust Vec, independently
of the preceding unsigned length arithmetic. Physical memory is external. -/
abbrev Fits (capacity : Std.Usize) : Prop := (capacity.val : Int) ≤ Isize.max

theorem signed_bounds_iff (capacity : Std.Usize) :
    IScalar.inBounds .Isize capacity.val ↔ Fits capacity := by
  have lower : -((2 : Int) ^ (IScalarTy.Isize.numBits - 1)) ≤ 0 := by
    have : 0 ≤ (2 : Int) ^ (IScalarTy.Isize.numBits - 1) := by positivity
    omega
  simp only [IScalar.inBounds, Fits, Isize.max, Isize.numBits]
  omega

theorem buffer_refines (capacity : Std.Usize) :
    hash.preimage_buffer capacity =
      ok (if Fits capacity then .Ok (alloc.vec.Vec.new Std.U8) else .Err .LimitExceeded) := by
  unfold hash.preimage_buffer Isize.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from
  have conversion := IScalar.tryMkOpt_eq .Isize capacity.val
  cases converted : IScalar.tryMkOpt .Isize capacity.val with
  | none =>
    simp only [converted] at conversion
    have refused : ¬ Fits capacity := fun fits => conversion ((signed_bounds_iff capacity).mpr fits)
    simp [converted, refused, core.result.Result.map_err, error.limit_error, BuiltinFnOnce,
      core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from]
  | some signed =>
    simp only [converted] at conversion
    have fits : Fits capacity := (signed_bounds_iff capacity).mp conversion.2
    simp [converted, fits, core.result.Result.map_err, error.limit_error, BuiltinFnOnce,
      core.result.Result.Insts.CoreOpsTry.branch, alloc.vec.Vec.with_capacity]

theorem accepted_empty (capacity : Std.Usize) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.preimage_buffer capacity = ok (.Ok output)) : output.val = [] := by
  rw [buffer_refines] at accepted
  split at accepted
  · have same : alloc.vec.Vec.new Std.U8 = output := by simpa using accepted
    subst output
    rfl
  · simp at accepted

theorem accepted_capacity_fits (capacity : Std.Usize) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.preimage_buffer capacity = ok (.Ok output)) : Fits capacity := by
  rw [buffer_refines] at accepted
  split at accepted
  · assumption
  · simp at accepted

theorem fits_conservative (capacity : Std.Usize) (small : capacity.val ≤ 2147483647) :
    Fits capacity := by
  have lower := IScalar.cMax_le_rMax .Isize
  rw [IScalar.rMax_eq_max, IScalar.max_ISize_eq] at lower
  norm_num [IScalar.cMax, IScalar.rMax, I32.rMax] at lower
  omega

-- Kernel witnesses can reduce a small literal without expanding the opaque
-- platform-width definition. The large branch retains the exact native limit.
theorem buffer_conservative_model (capacity : Std.Usize) :
    hash.preimage_buffer capacity = ok (
      if capacity.val ≤ 2147483647 then .Ok (alloc.vec.Vec.new Std.U8)
      else if Fits capacity then .Ok (alloc.vec.Vec.new Std.U8) else .Err .LimitExceeded) := by
  rw [buffer_refines]
  by_cases small : capacity.val ≤ 2147483647
  · simp [small, fits_conservative capacity small]
  · simp [small]

end Auths.Crypto.BufferAllocation
