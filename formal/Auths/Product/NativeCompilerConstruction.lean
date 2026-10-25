import Auths.Product.NativeCompilerSchemaAtoms
import Auths.Product.PathCompiler

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

abbrev NativeSegment := AuthsNativeRecipe.auths_gateway_kernel.construct.SegmentPlan

def nativeConstructError : NativeConstructError → RequestConstruction.ConstructError
  | .ArgumentMismatch => .argumentMismatch
  | .UnsafeSegment => .unsafeSegment
  | .PathTooLong => .pathTooLong
  | .HeaderValue => .headerValue
  | .BodySize => .bodySize

def nativeConstructResult {T V : Type} (view : T → V) :
    core.result.Result T NativeConstructError → Except RequestConstruction.ConstructError V
  | .Ok value => .ok (view value)
  | .Err error => .error (nativeConstructError error)

def nativeSegment : NativeSegment → RequestConstruction.Segment
  | .Fixed value => .fixed (bytes value)
  | .Field index => .field index.val

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open RequestConstruction
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

@[step] theorem native_path_literal_exact (byte : Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.is_path_literal byte ⦃ actual =>
      actual = pathLiteral byte.val ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.is_path_literal
  step with native_schema_alphanumeric_exact byte as ⟨alpha, meaning⟩
  repeat' split
  all_goals simp_all [pathLiteral, alphanumeric, OperationIdentity.Alphanumeric,
    UScalar.eq_equiv, Bool.eq_iff_iff]

/-- Complete ordinary segment-value check. The stronger fixed-path grammar
is established separately; a successful value check alone does not earn it. -/
@[step] theorem native_segment_value_exact (text : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.segment_value_valid text ⦃ actual =>
      actual = segmentValueValid (schemaSliceBytes text) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.segment_value_valid
    AuthsNativeRecipe.auths_gateway_kernel.construct.MAX_SEGMENT_VALUE_BYTES
  cases original : text.val with
  | nil => simp [core.slice.Slice.is_empty, original, schemaSliceBytes, segmentValueValid]
  | cons first rest =>
      have nonempty : text.val.isEmpty = false := by simp only [original, List.isEmpty_cons]
      simp only [core.slice.Slice.is_empty, nonempty, bind_tc_ok, Bool.false_eq_true, ↓reduceIte]
      by_cases large : 4096 < text.val.length
      · have nativeLarge : text.len > 4096#usize := by scalar_tac
        simp [nativeLarge, schemaSliceBytes, segmentValueValid, maxSegmentValueBytes,
          Nat.not_le.mpr large]
      · have bounded : text.val.length ≤ 4096 := by omega
        have nativeBound : ¬text.len > 4096#usize := by scalar_tac
        simp only [nativeBound, ↓reduceIte]
        cases rest with
        | nil =>
            have length : text.len = 1#usize := by scalar_tac
            simp only [length, ↓reduceIte]
            step with Slice.index_usize_spec text 0#usize (by simp only [original, List.length_cons]; omega)
              as ⟨byte, byteAt⟩
            have same : byte = first := by simpa only [original] using byteAt
            simp [same, schemaSliceBytes, original, segmentValueValid, maxSegmentValueBytes,
              UScalar.eq_equiv]
        | cons second tail =>
            cases tail with
            | nil =>
                have length : text.len = 2#usize := by scalar_tac
                simp only [length, ↓reduceIte]
                step with Slice.index_usize_spec text 0#usize
                  (by simp only [original, List.length_cons]; omega) as ⟨byte, byteAt⟩
                have same : byte = first := by simpa only [original] using byteAt
                by_cases dot : byte = 46#u8
                · simp only [dot, ↓reduceIte]
                  step with Slice.index_usize_spec text 1#usize
                    (by simp only [original, List.length_cons]; omega) as ⟨next, nextAt⟩
                  have nextSame : next = second := by simpa only [original] using nextAt
                  simp [same, nextSame, dot, schemaSliceBytes, original, segmentValueValid,
                    maxSegmentValueBytes, UScalar.eq_equiv]
                · simp [dot, same, schemaSliceBytes, original, segmentValueValid,
                    maxSegmentValueBytes, UScalar.eq_equiv]
            | cons third tail =>
                have notOne : text.len ≠ 1#usize := by scalar_tac
                have notTwo : text.len ≠ 2#usize := by scalar_tac
                simp [notOne, notTwo, schemaSliceBytes, original, segmentValueValid,
                  maxSegmentValueBytes, bounded]

@[step] theorem native_segment_clone_exact (segment : NativeSegment) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.SegmentPlan.Insts.CoreCloneClone.clone segment
      ⦃ actual => actual = segment ⦄ := by
  cases segment with
  | Fixed value =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.construct.SegmentPlan.Insts.CoreCloneClone.clone
      step with native_vector_clone_exact core.clone.CloneU8 value (by intro byte _; rfl)
        as ⟨copied, same⟩
      simpa only [same]
  | Field index =>
      simp [AuthsNativeRecipe.auths_gateway_kernel.construct.SegmentPlan.Insts.CoreCloneClone.clone,
        core.clone.impls.CloneUsize.clone]

end Auths.Product.NativeCompiler.Refinement
